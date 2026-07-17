/*
 *  Copyright (C) 2026 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA 02110-1301, USA.
 */

//! PKCS#7 detached signing helpers shared by ClamAV-compatible tools.

use std::path::{Path, PathBuf};

use openssl::{
    pkcs7::{Pkcs7, Pkcs7Flags},
    pkey::{PKey, Private},
    stack::{self, Stack},
    x509::{
        store::{X509Store, X509StoreBuilder},
        X509,
    },
};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("can't sign: {0}")]
    SignFailed(String),

    #[error("signature verification failed: {0}")]
    InvalidDigitalSignature(String),

    #[error("no trusted signer found")]
    NoTrustedSigner,

    #[error("file is not signed")]
    NotSigned,

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("cert store: {0}")]
    CertificateStore(String),

    #[error("OpenSSL error: {0}")]
    OpenSsl(#[from] openssl::error::ErrorStack),
}

pub struct Signer {
    cert: X509,
    certs: Stack<X509>,
    key: PKey<Private>,
}

impl Signer {
    pub fn new<P>(key_path: &Path, cert_paths: &[P]) -> Result<Self, Error>
    where
        P: AsRef<Path>,
    {
        let mut signing_cert = None;
        let mut cert_stack = Stack::new()?;

        for cert_path in cert_paths {
            let cert_bytes = std::fs::read(cert_path)?;
            let certs = X509::stack_from_pem(&cert_bytes)?;
            for cert in certs {
                if signing_cert.is_none() {
                    signing_cert = Some(cert.clone());
                } else {
                    cert_stack.push(cert.clone())?;
                }
            }
        }

        let Some(cert) = signing_cert else {
            return Err(Error::SignFailed(
                "no signing certificate found in the provided certificate files".to_owned(),
            ));
        };

        let key_bytes = std::fs::read(key_path)?;
        let key = PKey::private_key_from_pem(&key_bytes)?;

        Ok(Self {
            cert,
            certs: cert_stack,
            key,
        })
    }

    pub fn sign_pkcs7(&self, data: &[u8]) -> Result<Pkcs7, Error> {
        let flags = Pkcs7Flags::DETACHED | Pkcs7Flags::BINARY;
        Pkcs7::sign(&self.cert, &self.key, &self.certs, data, flags).map_err(Error::OpenSsl)
    }

    pub fn sign_pkcs7_der(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
        Ok(self.sign_pkcs7(data)?.to_der()?)
    }
}

pub fn sign_pkcs7_der<P>(data: &[u8], key_path: &Path, cert_paths: &[P]) -> Result<Vec<u8>, Error>
where
    P: AsRef<Path>,
{
    Signer::new(key_path, cert_paths)?.sign_pkcs7_der(data)
}

pub struct Verifier {
    store: X509Store,
    certs_directory: PathBuf,
}

impl Verifier {
    pub fn new(certs_directory: &Path) -> Result<Self, Error> {
        let mut store_builder = X509StoreBuilder::new()?;

        for file in std::fs::read_dir(certs_directory)? {
            let Ok(file) = file else {
                log::debug!("error reading certificate directory entry; skipping");
                continue;
            };
            let path = file.path();
            if !path.is_file() {
                continue;
            }
            let ext = path.extension().and_then(|ext| ext.to_str());
            if !matches!(ext, Some("pem" | "crt")) {
                continue;
            }

            let Ok(cert_bytes) = std::fs::read(&path) else {
                log::debug!(
                    "error reading certificate file {path}; skipping",
                    path = path.display()
                );
                continue;
            };
            let Ok(certs) = X509::stack_from_pem(&cert_bytes) else {
                log::debug!(
                    "error parsing certificate file {path}; skipping",
                    path = path.display()
                );
                continue;
            };
            for cert in certs {
                store_builder.add_cert(cert.clone())?;
            }
        }

        Ok(Self {
            store: store_builder.build(),
            certs_directory: certs_directory.to_path_buf(),
        })
    }

    #[must_use]
    pub fn certs_directory(&self) -> &Path {
        &self.certs_directory
    }

    pub fn verify_pkcs7_der(&self, data: &[u8], pkcs7_der: &[u8]) -> Result<String, Error> {
        let pkcs7 = Pkcs7::from_der(pkcs7_der)?;
        self.verify_pkcs7(data, &pkcs7)
    }

    pub fn verify_pkcs7(&self, data: &[u8], pkcs7: &Pkcs7) -> Result<String, Error> {
        if pkcs7.signed().is_none() {
            return Err(Error::NotSigned);
        }

        let certs = stack::Stack::new()?;
        let flags = Pkcs7Flags::DETACHED | Pkcs7Flags::BINARY | Pkcs7Flags::NOCRL;
        let mut output = Vec::new();
        let result = pkcs7.verify(&certs, &self.store, Some(data), Some(&mut output), flags);
        let signers = pkcs7.signers(&certs, flags)?;
        let signer_names = signers
            .iter()
            .map(|cert| cert_common_name(cert).unwrap_or_default())
            .collect::<Vec<_>>();

        match result {
            Ok(()) => Ok(signer_names.join(", ")),
            Err(error) if openssl_error_looks_untrusted(&error) => {
                log::debug!(
                    "signature could not be verified by cert store {certs_directory}: {error}",
                    certs_directory = self.certs_directory.display()
                );
                Err(Error::NoTrustedSigner)
            }
            Err(error) => Err(Error::InvalidDigitalSignature(error.to_string())),
        }
    }
}

fn cert_common_name(cert: &openssl::x509::X509Ref) -> Option<String> {
    cert.subject_name()
        .entries()
        .find(|entry| entry.object().nid() == openssl::nid::Nid::COMMONNAME)
        .map(|entry| String::from_utf8_lossy(entry.data().as_slice()).into_owned())
}

fn openssl_error_looks_untrusted(error: &openssl::error::ErrorStack) -> bool {
    let text = error.to_string().to_ascii_lowercase();
    text.contains("certificate verify error")
        || text.contains("unable to get local issuer certificate")
        || text.contains("self-signed certificate")
        || text.contains("unable to verify")
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::{
        asn1::Asn1Time,
        bn::{BigNum, MsbOption},
        hash::MessageDigest,
        rsa::Rsa,
        x509::X509NameBuilder,
    };
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock after epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "clam_sigutil_codesign_{name}_{nonce}_{}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("create temp dir");
        path
    }

    fn write_self_signed_cert(dir: &Path, common_name: &str) -> (PathBuf, PathBuf) {
        let rsa = Rsa::generate(2048).expect("generate RSA key");
        let key = PKey::from_rsa(rsa).expect("convert RSA key");

        let mut name = X509NameBuilder::new().expect("name builder");
        name.append_entry_by_text("CN", common_name)
            .expect("set common name");
        let name = name.build();

        let mut serial = BigNum::new().expect("serial bignum");
        serial
            .rand(64, MsbOption::MAYBE_ZERO, false)
            .expect("random serial");
        let serial = serial.to_asn1_integer().expect("serial integer");

        let mut cert = X509::builder().expect("cert builder");
        cert.set_version(2).expect("set cert version");
        cert.set_serial_number(&serial).expect("set serial");
        cert.set_subject_name(&name).expect("set subject");
        cert.set_issuer_name(&name).expect("set issuer");
        cert.set_pubkey(&key).expect("set pubkey");
        cert.set_not_before(Asn1Time::days_from_now(0).expect("not before").as_ref())
            .expect("set not before");
        cert.set_not_after(Asn1Time::days_from_now(1).expect("not after").as_ref())
            .expect("set not after");
        cert.sign(&key, MessageDigest::sha256())
            .expect("sign certificate");
        let cert = cert.build();

        let key_path = dir.join(format!("{common_name}.key"));
        let cert_path = dir.join(format!("{common_name}.crt"));
        fs::write(&key_path, key.private_key_to_pem_pkcs8().expect("key pem")).expect("write key");
        fs::write(&cert_path, cert.to_pem().expect("cert pem")).expect("write cert");
        (key_path, cert_path)
    }

    #[test]
    fn pkcs7_sign_verify_roundtrip_with_trusted_signer() {
        let root = temp_dir("roundtrip");
        let (key_path, cert_path) = write_self_signed_cert(&root, "trusted");
        let der = sign_pkcs7_der(b"signed-data", &key_path, std::slice::from_ref(&cert_path))
            .expect("sign data");
        let verifier = Verifier::new(&root).expect("trusted cert store");

        let signer = verifier
            .verify_pkcs7_der(b"signed-data", &der)
            .expect("verify signature");

        assert_eq!(signer, "trusted");
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn pkcs7_verify_skips_untrusted_signer() {
        let signer_root = temp_dir("untrusted_signer");
        let trust_root = temp_dir("untrusted_store");
        let (key_path, cert_path) = write_self_signed_cert(&signer_root, "signer");
        let (_other_key_path, _other_cert_path) = write_self_signed_cert(&trust_root, "other");
        let der = sign_pkcs7_der(b"signed-data", &key_path, std::slice::from_ref(&cert_path))
            .expect("sign data");
        let verifier = Verifier::new(&trust_root).expect("trusted cert store");

        let error = verifier
            .verify_pkcs7_der(b"signed-data", &der)
            .expect_err("untrusted signer should not verify");

        assert!(matches!(error, Error::NoTrustedSigner));
        let _ = fs::remove_dir_all(signer_root);
        let _ = fs::remove_dir_all(trust_root);
    }

    #[test]
    fn pkcs7_verify_hard_fails_trusted_invalid_signature() {
        let root = temp_dir("invalid_signature");
        let (key_path, cert_path) = write_self_signed_cert(&root, "trusted");
        let der = sign_pkcs7_der(b"signed-data", &key_path, std::slice::from_ref(&cert_path))
            .expect("sign data");
        let verifier = Verifier::new(&root).expect("trusted cert store");

        let error = verifier
            .verify_pkcs7_der(b"tampered-data", &der)
            .expect_err("tampered data should not verify");

        assert!(matches!(error, Error::InvalidDigitalSignature(_)));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn verifier_tolerates_unparseable_cert_files() {
        let root = temp_dir("unparseable_cert");
        let (_key_path, _cert_path) = write_self_signed_cert(&root, "trusted");
        fs::write(root.join("not-a-cert.crt"), b"not a cert").expect("write bad cert");

        Verifier::new(&root).expect("bad cert file should be skipped");

        let _ = fs::remove_dir_all(root);
    }
}
