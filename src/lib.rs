/*
 *  Copyright (C) 2024 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
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

//! # ClamAV Signature Utilities
//!
//! An API for ingesting and validating ClamAV signatures

#![deny(clippy::mod_module_files)]

/// Functionality associated with engine features
pub mod feature;

/// File type classification
pub mod filetype;

/// Regular expressions
pub mod regexp;

/// SigBytes (Vec<u8>) wrapper
pub mod sigbytes;

/// Engine signature parsing and examination
pub mod signature;

pub mod util;

pub use feature::Feature;
pub use signature::sigtype::SigType;
pub use signature::Signature;

#[cfg(test)]
pub(crate) mod test_data {
    include!(concat!(env!("OUT_DIR"), "/logical-exprs.rs"));
}
