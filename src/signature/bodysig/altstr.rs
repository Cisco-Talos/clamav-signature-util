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

use super::pattern::MatchBytes;

#[derive(Debug, PartialEq)]
pub enum AlternativeStrings {
    FixedWidth {
        negated: bool,
        width: usize,
        data: MatchBytes,
    },
    Generic {
        ranges: Vec<std::ops::Range<usize>>,
        data: MatchBytes,
    },
}

impl AlternativeStrings {
    #[must_use]
    pub fn fixed_width(&self) -> Option<(bool, usize, &MatchBytes)> {
        match self {
            Self::FixedWidth {
                negated,
                width,
                data,
            } => Some((*negated, *width, data)),
            Self::Generic { .. } => None,
        }
    }

    #[must_use]
    pub fn generic(&self) -> Option<(&[std::ops::Range<usize>], &MatchBytes)> {
        match self {
            Self::Generic { ranges, data } => Some((ranges.as_slice(), data)),
            Self::FixedWidth { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exposes_fixed_width_parts() {
        let strings = AlternativeStrings::FixedWidth {
            negated: true,
            width: 2,
            data: b"abcd".as_slice().into(),
        };

        let (negated, width, data) = strings.fixed_width().expect("fixed width accessor");
        assert!(negated);
        assert_eq!(width, 2);
        assert_eq!(data.to_string(), "61626364");
        assert!(strings.generic().is_none());
    }

    #[test]
    fn exposes_generic_parts() {
        let strings = AlternativeStrings::Generic {
            ranges: vec![0..2, 2..5],
            data: b"abcde".as_slice().into(),
        };

        let (ranges, data) = strings.generic().expect("generic accessor");
        assert_eq!(ranges, &[0..2, 2..5]);
        assert_eq!(data.to_string(), "6162636465");
        assert!(strings.fixed_width().is_none());
    }
}
