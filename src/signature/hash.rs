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

use crate::util::ParseNumberError;

/// Errors common to hash-based signatures
#[derive(Debug, thiserror::Error, PartialEq)]
pub enum ParseError {
    #[error("missing FileSize field")]
    MissingFileSize,

    #[error("invalid value for field: {0}")]
    InvalidValueFor(String),

    #[error("missing field: {0}")]
    MissingField(String),

    #[error("parsing size: {0}")]
    ParseSize(ParseNumberError<usize>),

    #[error("Parsing min_flevel: {0}")]
    ParseMinFlevel(ParseNumberError<u32>),

    #[error("Parsing max_flevel: {0}")]
    ParseMaxFlevel(ParseNumberError<u32>),

    #[error("Parsing hash signature: {0}")]
    ParseHash(#[from] crate::util::ParseHashError),
}

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum ValidationError {}
