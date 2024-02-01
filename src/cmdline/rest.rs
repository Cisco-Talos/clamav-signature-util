use crate::Opt;
use anyhow::Result;
use axum::{extract::Query, routing::post, Extension, Json, Router};
use clam_sigutil::SigType;
use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, sync::Arc};
use tower::ServiceBuilder;

pub(crate) async fn run_server(opt: Opt, addr: SocketAddr) -> Result<()> {
    let opt = Arc::new(opt);
    let app = Router::new()
        .route("/check-sig", post(post_handler))
        .layer(ServiceBuilder::new().layer(Extension(opt)));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    eprintln!("listening on {listener:?}");

    Ok(axum::serve(listener, app).await?)
}

/// Expected query string for `/check-sig`
#[derive(Debug, Deserialize)]
struct CheckSigQuery {
    sig_type: String,
    // TODO: add an optional FLevel restriction to allow validation to fail
}

/// A response similar to that used by earlier versions of ClamAV, as
/// incorporated into sigmanager.
///
/// This is implemented as an enum to allow for default values beyond the
/// required one (result).
#[derive(Debug, Serialize)]
#[serde(tag = "result")]
enum SigMgrV1Response {
    Pass(SigMgrV1PassResp),
    Fail(SigMgrV1FailResp),
}

/// A pass response.  Both `stdout` and `stderr` will generally be empty
#[derive(Debug, Serialize, Default)]
struct SigMgrV1PassResp {
    stderr: String,
    stdout: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    comp_flevel: Option<String>,
}

/// A failure response.  `stdout` will be left empty
#[derive(Debug, Serialize, Default)]
struct SigMgrV1FailResp {
    stderr: String,
    stdout: String,
}

// Simple conversion to the parent enum
impl From<SigMgrV1PassResp> for SigMgrV1Response {
    fn from(value: SigMgrV1PassResp) -> Self {
        SigMgrV1Response::Pass(value)
    }
}

// Simple conversion to the parent enum
impl From<SigMgrV1FailResp> for SigMgrV1Response {
    fn from(value: SigMgrV1FailResp) -> Self {
        SigMgrV1Response::Fail(value)
    }
}

async fn post_handler(
    Extension(opt): Extension<Arc<Opt>>,
    Query(params): Query<CheckSigQuery>,
    body: String,
) -> Json<SigMgrV1Response> {
    let Some(sig_type) = SigType::from_file_extension(&params.sig_type) else {
        return Json(
            SigMgrV1FailResp {
                stderr: "Unrecognized signature type/file extension".into(),
                stdout: String::default(),
            }
            .into(),
        );
    };

    match clam_sigutil::signature::parse_from_cvd_with_meta(sig_type, &(body.into())) {
        Ok((sig, sigmeta)) => {
            if opt.validate {
                // NOTE: FLevel validation is effectively skipped since the
                // provided SigMeta is the same as was returned by the sig
                // parser.
                if let Err(err) = sig.validate(&sigmeta) {
                    return Json(
                        SigMgrV1FailResp {
                            stderr: err.to_string(),
                            ..Default::default()
                        }
                        .into(),
                    );
                }
            }
            Json(
                SigMgrV1PassResp {
                    comp_flevel: sigmeta.f_level.map(|r| format!("{r:?}")),
                    ..Default::default()
                }
                .into(),
            )
        }
        Err(err) => Json(
            SigMgrV1FailResp {
                stderr: err.to_string(),
                ..Default::default()
            }
            .into(),
        ),
    }
}
