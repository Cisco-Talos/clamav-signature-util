use super::{
    super::{pattern::ByteAnchorSide, *},
    BodySigParseError, Context,
};
use crate::{
    signature::bodysig::{
        altstr::AlternativeStrings, pattern::MatchByte, pattern_modifier::PatternModifier,
    },
    util::{Position, Range},
};
use enumflags2::BitFlag;
use hex_literal::hex;

#[test]
fn empty_signature() {
    assert_eq!(
        Err(BodySigParseError::Empty),
        BodySig::try_from(b"".as_slice())
    )
}

#[test]
fn string() {
    assert_eq!(
        Ok(BodySig {
            patterns: vec![Pattern::String(
                vec![
                    MatchByte::Full(0xaa),
                    MatchByte::Full(0x55),
                    MatchByte::Full(0xaa),
                    MatchByte::Full(0x55),
                ]
                .into(),
                PatternModifier::empty()
            ),],
        }),
        b"aa55aa55".as_slice().try_into()
    )
}

#[test]
fn string_with_wildcards() {
    assert_eq!(
        Ok(BodySig {
            patterns: vec![Pattern::String(
                vec![
                    MatchByte::Full(0xaa),
                    MatchByte::Full(0xbb),
                    MatchByte::Any,
                    MatchByte::Full(0xcc),
                    MatchByte::Full(0xdd),
                    MatchByte::LowNyble(0x05),
                    MatchByte::Full(0xee),
                    MatchByte::Full(0xff),
                    MatchByte::HighNyble(0x50),
                    MatchByte::Full(0x00),
                    MatchByte::Full(0x11),
                ]
                .into(),
                PatternModifier::empty()
            )],
        }),
        b"aabb??ccdd?5eeff5?0011".as_slice().try_into()
    )
}

#[test]
fn string_with_ifinibyte_wildcard() {
    assert_eq!(
        Ok(BodySig {
            patterns: vec![
                Pattern::String(hex!("0011").into(), PatternModifier::empty()),
                Pattern::Wildcard,
                Pattern::String(hex!("2233").into(), PatternModifier::empty())
            ],
        }),
        b"0011*2233".as_slice().try_into()
    )
}

#[test]
fn string_with_fixed_range_wildcard() {
    assert_eq!(
        Ok(BodySig {
            patterns: vec![Pattern::String(
                vec![
                    MatchByte::Full(0xaa),
                    MatchByte::Full(0xbb),
                    MatchByte::WildcardMany { size: 63 },
                    MatchByte::Full(0xcc),
                    MatchByte::Full(0xdd),
                ]
                .into(),
                PatternModifier::empty()
            ),],
        }),
        b"aabb{63}ccdd".as_slice().try_into()
    )
}

#[test]
fn string_with_large_fixed_range_wildcard() {
    assert_eq!(
        Ok(BodySig {
            patterns: vec![
                Pattern::String(hex!("aabb").into(), PatternModifier::empty()),
                Pattern::ByteRange(Range::Exact(630)),
                Pattern::String(hex!("ccdd").into(), PatternModifier::empty()),
            ],
        }),
        b"aabb{630}ccdd".as_slice().try_into()
    );
}

#[test]
fn string_with_open_start_range_wildcard() {
    assert_eq!(
        Ok(BodySig {
            patterns: vec![
                Pattern::String(hex!("aabb").into(), PatternModifier::empty()),
                Pattern::ByteRange((..=630).into()),
                Pattern::String(hex!("ccdd").into(), PatternModifier::empty()),
            ],
        }),
        b"aabb{-630}ccdd".as_slice().try_into()
    )
}

#[test]
fn string_with_open_end_range_wildcard() {
    assert_eq!(
        Ok(BodySig {
            patterns: vec![
                Pattern::String(hex!("aabb").into(), PatternModifier::empty()),
                Pattern::ByteRange((630..).into()),
                Pattern::String(hex!("ccdd").into(), PatternModifier::empty()),
            ],
        }),
        b"aabb{630-}ccdd".as_slice().try_into()
    )
}

#[test]
fn anchored_byte_standalone_left() {
    assert_eq!(
        Ok(BodySig {
            patterns: vec![Pattern::AnchoredByte {
                anchor_side: ByteAnchorSide::Left,
                byte: 0xaa.into(),
                range: 1..=2,
                string: hex!("bbcc").into(),
            }],
        }),
        b"aa[1-2]bbcc".as_slice().try_into()
    )
}

#[test]
fn anchored_byte_standalone_right() {
    assert_eq!(
        Ok(BodySig {
            patterns: vec![Pattern::AnchoredByte {
                anchor_side: ByteAnchorSide::Right,
                byte: 0xcc.into(),
                range: 1..=2,
                string: hex!("aabb").into(),
            }],
        }),
        b"aabb[1-2]cc".as_slice().try_into()
    )
}

#[test]
fn anchored_byte_left_with_trailing() {
    assert_eq!(
        Ok(BodySig {
            patterns: vec![
                Pattern::AnchoredByte {
                    anchor_side: ByteAnchorSide::Left,
                    byte: MatchByte::Full(0xaa),
                    range: 1..=2,
                    string: hex!("bbcc").into(),
                },
                Pattern::Wildcard,
                Pattern::String(hex!("0123").into(), PatternModifier::empty()),
            ],
        }),
        b"aa[1-2]bbcc*0123".as_slice().try_into()
    );
}

#[test]
fn anchored_byte_left_with_leading() {
    assert_eq!(
        Ok(BodySig {
            patterns: vec![
                Pattern::String(hex!("0123").into(), PatternModifier::empty()),
                Pattern::Wildcard,
                Pattern::AnchoredByte {
                    anchor_side: ByteAnchorSide::Left,
                    byte: MatchByte::Full(0xaa),
                    range: 1..=2,
                    string: hex!("bbcc").into(),
                },
            ],
        }),
        b"0123*aa[1-2]bbcc".as_slice().try_into()
    );
}

#[test]
fn anchored_byte_right_with_trailing() {
    assert_eq!(
        Ok(BodySig {
            patterns: vec![
                Pattern::AnchoredByte {
                    anchor_side: ByteAnchorSide::Right,
                    byte: MatchByte::Full(0xcc),
                    range: 1..=2,
                    string: hex!("aabb").into(),
                },
                Pattern::Wildcard,
                Pattern::String(hex!("0123").into(), PatternModifier::empty()),
            ],
        }),
        b"aabb[1-2]cc*0123".as_slice().try_into()
    );
}

#[test]
fn anchored_byte_right_with_leading() {
    assert_eq!(
        Ok(BodySig {
            patterns: vec![
                Pattern::String(hex!("0123").into(), PatternModifier::empty()),
                Pattern::Wildcard,
                Pattern::AnchoredByte {
                    anchor_side: ByteAnchorSide::Right,
                    byte: MatchByte::Full(0xcc),
                    range: 1..=2,
                    string: hex!("aabb").into(),
                },
            ],
        }),
        b"0123*aabb[1-2]cc".as_slice().try_into()
    );
}

#[test]
fn anchored_byte_left_string_too_small() {
    assert_eq!(
        Err(BodySigParseError::AnchoredByteStringTooSmall {
            start_pos: 5.into(),
        }),
        BodySig::try_from(b"abcd*00[2-4]01*e0f0".as_slice())
    )
}

#[test]
fn anchored_byte_string_too_small() {
    assert_eq!(
        Err(BodySigParseError::AnchoredByteStringTooSmall {
            start_pos: 5.into(),
        }),
        BodySig::try_from(b"abcd*00[2-4]01*e0f0".as_slice())
    )
}

#[test]
fn anchored_byte_missing_single_byte() {
    assert_eq!(
        Err(BodySigParseError::AnchoredByteMissingSingleByte {
            start_pos: 5.into(),
        }),
        BodySig::try_from(b"abcd*0001[2-4]0203*e0f0".as_slice())
    )
}

#[test]
fn anchored_byte_expecting_single_byte() {
    // This test differs in that something other than a nyble character was found
    // after the bracket expression (i.e., some other kind of pattern was starting)
    assert_eq!(
        Err(BodySigParseError::AnchoredByteExpectingSingleByte {
            start_pos: 5.into(),
            pos: 14.into(),
        }),
        BodySig::try_from(b"abcd*0001[2-4]x".as_slice())
    );
    assert_eq!(
        Err(BodySigParseError::AnchoredByteExpectingSingleByte {
            start_pos: 5.into(),
            pos: Position::End,
        }),
        BodySig::try_from(b"abcd*0001[2-4]".as_slice())
    );
}

#[test]
fn anchored_byte_invalid_lower_bound() {
    assert_eq!(
        Err(BodySigParseError::AnchoredByteInvalidLowerBound {
            bracket_pos: 9.into(),
            found: 33
        }),
        BodySig::try_from(b"abcd*0001[33-4]aa".as_slice())
    );
}

#[test]
fn anchored_byte_invalid_upper_bound() {
    assert_eq!(
        Err(BodySigParseError::AnchoredByteInvalidUpperBound {
            bracket_pos: 9.into(),
            found: 1,
            lower: 2,
        }),
        BodySig::try_from(b"abcd*0001[2-1]aa".as_slice())
    );
    assert_eq!(
        Err(BodySigParseError::AnchoredByteInvalidUpperBound {
            bracket_pos: 9.into(),
            found: 40,
            lower: 2,
        }),
        BodySig::try_from(b"abcd*0001[2-40]aa".as_slice())
    );
    assert_eq!(
        Err(BodySigParseError::AnchoredByteInvalidUpperBound {
            bracket_pos: 9.into(),
            found: 0,
            lower: 3,
        }),
        BodySig::try_from(b"abcd*0001[3-0]aa".as_slice())
    );
}

#[test]
fn unexpected_pipe() {
    assert_eq!(
        Err(BodySigParseError::UnexpectedPipeChar { pos: 4.into() }),
        BodySig::try_from(b"abcd|".as_slice())
    );
}

#[test]
fn astrs_single_byte() {
    assert_eq!(
        Ok(BodySig {
            patterns: vec![
                Pattern::AlternativeStrings(AlternativeStrings::FixedWidth {
                    negated: false,
                    width: 1,
                    data: hex!("aabbcc").into(),
                }),
                Pattern::String(hex!("ffff").into(), PatternModifier::empty())
            ],
        }),
        b"(aa|bb|cc)ffff".as_slice().try_into()
    );
}

#[test]
fn astrs_multi_byte() {
    assert_eq!(
        Ok(BodySig {
            patterns: vec![
                Pattern::AlternativeStrings(AlternativeStrings::FixedWidth {
                    negated: false,
                    width: 2,
                    data: hex!("aa01bb02cc03").into(),
                }),
                Pattern::String(hex!("ffff").into(), PatternModifier::empty())
            ],
        }),
        b"(aa01|bb02|cc03)ffff".as_slice().try_into()
    );
}

#[test]
fn astrs_generic_wildcard() {
    assert_eq!(
        Ok(BodySig {
            patterns: vec![
                Pattern::String(hex!("aaaa").into(), PatternModifier::empty()),
                Pattern::AlternativeStrings(AlternativeStrings::Generic {
                    ranges: vec![0..1, 1..2, 2..3],
                    data: vec![
                        MatchByte::HighNyble(0x00),
                        MatchByte::Full(0x02),
                        MatchByte::Full(0x03),
                    ]
                    .into()
                }),
                Pattern::String(hex!("bbbb").into(), PatternModifier::empty()),
            ],
        }),
        b"aaaa(0?|02|03)bbbb".as_slice().try_into()
    );
}

#[test]
fn astrs_generic_variable() {
    assert_eq!(
        Ok(BodySig {
            patterns: vec![
                Pattern::String(hex!("aaaa").into(), PatternModifier::empty()),
                Pattern::AlternativeStrings(AlternativeStrings::Generic {
                    ranges: vec![0..2, 2..3],
                    data: hex!("010203").into(),
                }),
                Pattern::String(hex!("bbbb").into(), PatternModifier::empty()),
            ],
        }),
        b"aaaa(0102|03)bbbb".as_slice().try_into()
    );
}

#[test]
fn empty_parens() {
    assert_eq!(
        Err(BodySigParseError::EmptyParens { pos: 0.into() }),
        BodySig::try_from(b"()".as_slice()),
    )
}

#[test]
fn empty_alternative_string() {
    assert_eq!(
        Ok(BodySig {
            patterns: vec![Pattern::AlternativeStrings(AlternativeStrings::Generic {
                ranges: vec![0..0, 0..1, 1..2],
                data: hex!("1234").into()
            })]
        }),
        BodySig::try_from(b"(|12|34)".as_slice()),
    )
}

#[test]
fn single_alternative_string() {
    assert_eq!(
        Ok(BodySig {
            patterns: vec![
                Pattern::String(hex!("aaaa").into(), PatternModifier::empty()),
                Pattern::AlternativeStrings(AlternativeStrings::FixedWidth {
                    negated: true,
                    width: 1,
                    data: hex!("12").into()
                }),
                Pattern::String(hex!("bbbb").into(), PatternModifier::empty()),
            ],
        }),
        BodySig::try_from(b"aaaa!(12)bbbb".as_slice()),
    )
}

#[test]
fn unmatched_right_paren() {
    assert_eq!(
        Err(BodySigParseError::UnmatchedClosingParen { pos: 4.into() }),
        BodySig::try_from(b"0123)".as_slice()),
    )
}

#[test]
fn curly_range_start_unexpected() {
    assert_eq!(
        Err(BodySigParseError::UnexpectedChar {
            context: Context::CurlyBraceRange,
            pos: 3.into(),
            found: b'x'.into()
        }),
        BodySig::try_from(b"{12x-45}".as_slice())
    )
}

#[test]
fn curly_range_end_unexpected() {
    assert_eq!(
        Err(BodySigParseError::UnexpectedChar {
            context: Context::CurlyBraceRange,
            pos: 4.into(),
            found: b'x'.into()
        }),
        BodySig::try_from(b"{12-x45}".as_slice())
    )
}

#[test]
fn bracket_range_start_unexpected() {
    assert_eq!(
        Err(BodySigParseError::BracketRangeUnexpectedChar {
            pos: 3.into(),
            found: b'x'.into()
        }),
        BodySig::try_from(b"[12x-45]".as_slice())
    )
}

#[test]
fn bracket_no_left_bytes() {
    assert_eq!(
        Err(BodySigParseError::AnchoredByteNoLeftBytes { pos: 4.into() }),
        BodySig::try_from(b"[1-2]abcd".as_slice())
    )
}

#[test]
fn bracket_upper_unexpected_char() {
    assert_eq!(
        Err(BodySigParseError::BracketRangeUnexpectedChar {
            pos: 6.into(),
            found: b'x'.into()
        }),
        BodySig::try_from(b"01[1-2x]abcd".as_slice())
    )
}

#[test]
fn bracket_lower_missing() {
    assert_eq!(
        Err(BodySigParseError::BracketRangeMissingLowerBound {
            start_pos: 2.into()
        }),
        BodySig::try_from(b"01[-1]abcd".as_slice())
    );
}

#[test]
fn brackets_only_one_bound() {
    assert_eq!(
        Ok(BodySig {
            patterns: vec![Pattern::AnchoredByte {
                anchor_side: ByteAnchorSide::Left,
                byte: MatchByte::Full(0x01),
                range: 5..=5,
                string: hex!("abcd").into()
            }]
        }),
        BodySig::try_from(b"01[5]abcd".as_slice())
    );
    assert_eq!(
        Err(BodySigParseError::AnchoredByteInvalidLowerBound {
            bracket_pos: 2.into(),
            found: 50,
        }),
        BodySig::try_from(b"01[50]abcd".as_slice())
    );
}

#[test]
fn brackets_empty() {
    assert_eq!(
        Err(BodySigParseError::BracketRangeEmpty {
            start_pos: 2.into()
        }),
        BodySig::try_from(b"01[]abcd".as_slice())
    );
}

#[test]
fn negate_unexpected_char() {
    assert_eq!(
        Err(BodySigParseError::NegateUnexpectedChar {
            pos: 1.into(),
            found: b'x'.into()
        }),
        BodySig::try_from(b"!x".as_slice())
    )
}

#[test]
fn cc_closing_paren_unexpected_char() {
    assert_eq!(
        Err(BodySigParseError::CharClassExpectCloseParen {
            pos: 2.into(),
            found: b'x'.into()
        }),
        BodySig::try_from(b"(Lx".as_slice())
    );
    // 'B' unfortunately returns a different error since it's unclear what's
    // expected in that context
    assert_eq!(
        Err(BodySigParseError::ExpectingLowNyble {
            pos: 2.into(),
            found: Some(b'x'.into())
        }),
        BodySig::try_from(b"(Bx".as_slice())
    );
}

#[test]
fn cc_nothing_adjacent() {
    assert_eq!(
        Err(BodySigParseError::CharClassNothingAdjacent { pos: Position::End }),
        BodySig::try_from(b"aaaa*(L)*".as_slice())
    )
}

#[test]
fn expecting_low_nyble_at_end() {
    assert_eq!(
        Err(BodySigParseError::ExpectingLowNyble {
            pos: Position::End,
            found: None
        }),
        BodySig::try_from(b"0".as_slice())
    )
}

#[test]
fn word_boundary() {
    let bs = BodySig::try_from(b"(B)0123!(W)45".as_slice()).unwrap();
    dbg!(bs);
}

#[test]
fn christmas_tree() {
    let bs = BodySig::try_from(
        b"0102{3}0405*0607{8-}090a{-12}0c0d*0e0f{120}*aabb[1-2]cc*(B)deadbeef!(W)".as_slice(),
    )
    .unwrap();
    dbg!(bs);
}

#[test]
fn low_nyble_bad() {
    assert_eq!(
        Err(BodySigParseError::ExpectingLowNyble {
            pos: 5.into(),
            found: Some(b'x'.into())
        }),
        BodySig::try_from(b"abcdex01".as_slice()),
    )
}

#[test]
fn low_nyble_incomplete() {
    assert_eq!(
        Err(BodySigParseError::ExpectingLowNyble {
            pos: Position::End,
            found: None
        }),
        BodySig::try_from(b"0".as_slice())
    )
}

#[test]
fn curly_brace_not_closed() {
    assert_eq!(
        Err(BodySigParseError::CurlyBraceNotClosed {
            start_pos: 4.into(),
        }),
        BodySig::try_from(b"0123{".as_slice())
    );
    assert_eq!(
        Err(BodySigParseError::CurlyBraceNotClosed {
            start_pos: 6.into(),
        }),
        BodySig::try_from(b"012345{5".as_slice())
    );
    assert_eq!(
        Err(BodySigParseError::CurlyBraceNotClosed {
            start_pos: 8.into(),
        }),
        BodySig::try_from(b"01234567{5-".as_slice())
    );
    assert_eq!(
        Err(BodySigParseError::CurlyBraceNotClosed {
            start_pos: 10.into(),
        }),
        BodySig::try_from(b"0123456789{5-6".as_slice())
    );
}

#[test]
fn bracket_not_closed() {
    assert_eq!(
        Err(BodySigParseError::BracketNotClosed {
            start_pos: 11.into(),
        }),
        BodySig::try_from(b"abcd{6}0123[".as_slice())
    );
    assert_eq!(
        Err(BodySigParseError::BracketNotClosed {
            start_pos: 13.into(),
        }),
        BodySig::try_from(b"abcd{6}012345[5".as_slice())
    );
    assert_eq!(
        Err(BodySigParseError::BracketNotClosed {
            start_pos: 15.into(),
        }),
        BodySig::try_from(b"abcd{6}01234567[5-".as_slice())
    );
    assert_eq!(
        Err(BodySigParseError::BracketNotClosed {
            start_pos: 17.into(),
        }),
        BodySig::try_from(b"abcd{6}0123456789[5-6".as_slice())
    );
}

#[test]
fn negation_targetless() {
    assert_eq!(
        Err(BodySigParseError::NegationTargetless),
        BodySig::try_from(b"abcd{6}0123!".as_slice())
    );
}

#[test]
fn char_class_unterminated() {
    assert_eq!(
        Err(BodySigParseError::CharClassUnterminated {
            start_pos: 11.into()
        }),
        BodySig::try_from(b"abcd{6}0123(L".as_slice())
    );
}

#[test]
fn hex_mixed_case() {
    assert_eq!(
        Ok(BodySig {
            patterns: vec![Pattern::String(
                hex!("0123456789abcdefabcdef").into(),
                PatternModifier::empty()
            ),],
        }),
        BodySig::try_from(b"0123456789abcdefABCDEF".as_slice())
    );
}

#[test]
fn error_ne() {
    let err1 = BodySigParseError::ExpectingLowNyble {
        pos: 0.into(),
        found: None,
    };
    let err2 = BodySigParseError::ExpectingLowNyble {
        pos: 1.into(),
        found: None,
    };

    // This test exists to exercise the 'not-equal' code path for Error/PartialEq
    assert!(err1.ne(&err2));
}

#[test]
fn error_display() {
    let err = BodySigParseError::UnexpectedChar {
        context: Context::Pattern,
        pos: Position::End,
        found: b'x'.into(),
    };
    let _ = format!("{}", &err);
    let _ = format!("{:?}", &err);
}

#[test]
fn invalid_pattern_char() {
    assert_eq!(
        Err(BodySigParseError::UnexpectedChar {
            context: Context::Pattern,
            pos: 4.into(),
            found: b'x'.into(),
        }),
        BodySig::try_from(b"0123xx".as_slice())
    )
}

#[test]
fn inverted_range() {
    assert_eq!(
        Err(BodySigParseError::RangeBoundsInverted {
            start_pos: 4.into(),
            start: 4,
            end: 3
        }),
        BodySig::try_from(b"0123{4-3}".as_slice())
    );
}

#[test]
fn empty_byte_range() {
    assert_eq!(
        Err(BodySigParseError::EmptyBraces {
            start_pos: 4.into(),
        }),
        BodySig::try_from(b"0123{}".as_slice())
    );
    // Another variation, except that only the hyphen was present
    assert_eq!(
        Err(BodySigParseError::NoBraceBounds {
            start_pos: 4.into(),
        }),
        BodySig::try_from(b"0123{-}".as_slice())
    );
}

#[test]
fn decimal_overflow() {
    // Overflow on addition
    assert_eq!(
        Err(BodySigParseError::DecimalOverflow { pos: 26.into() }),
        BodySig::try_from(b"0123{4-18446744073709551616}".as_slice())
    );
    // Overflow on place-shift
    assert_eq!(
        Err(BodySigParseError::DecimalOverflow { pos: 27.into() }),
        BodySig::try_from(b"0123{4-184467440737095516150}".as_slice())
    );
    // Within brackets
    assert_eq!(
        Err(BodySigParseError::DecimalOverflow { pos: 27.into() }),
        BodySig::try_from(b"0123[4-184467440737095516150]".as_slice())
    );
    // Test in left position
    assert_eq!(
        Err(BodySigParseError::DecimalOverflow { pos: 25.into() }),
        BodySig::try_from(b"0123{184467440737095516150-1}".as_slice())
    );
    // Within brackets
    assert_eq!(
        Err(BodySigParseError::DecimalOverflow { pos: 25.into() }),
        BodySig::try_from(b"0123[184467440737095516150-1]".as_slice())
    );
}

#[test]
fn leading_wildcard() {
    assert_eq!(
        Err(BodySigParseError::LeadingWildcard {
            pattern: Pattern::Wildcard
        }),
        BodySig::try_from(b"*012345".as_slice())
    );
    assert_eq!(
        Err(BodySigParseError::LeadingWildcard {
            pattern: Pattern::ByteRange((..=5).into())
        }),
        BodySig::try_from(b"{-5}012345".as_slice())
    );
    assert_eq!(
        Err(BodySigParseError::LeadingWildcard {
            pattern: Pattern::ByteRange(Range::Exact(500))
        }),
        BodySig::try_from(b"{500}012345".as_slice())
    );
}

#[test]
fn trailing_wildcard() {
    assert_eq!(
        Err(BodySigParseError::TrailingUnsizedPattern {
            pattern: Pattern::Wildcard
        }),
        BodySig::try_from(b"012345*".as_slice())
    );
    assert_eq!(
        Err(BodySigParseError::TrailingUnsizedPattern {
            pattern: Pattern::ByteRange((5..).into())
        }),
        BodySig::try_from(b"012345{5-}".as_slice())
    );
    assert_eq!(
        Err(BodySigParseError::TrailingUnsizedPattern {
            pattern: Pattern::ByteRange(Range::Exact(500))
        }),
        BodySig::try_from(b"012345{500}".as_slice())
    );
}

#[cfg(feature = "broken_min_static_bytes")]
#[test]
fn short_match_bytes() {
    assert_eq!(
        Err(BodySigParseError::MinStaticBytes {
            start_pos: 12.into()
        }),
        BodySig::try_from(b"(a?ee|?bff)*aa".as_slice()),
    );
}

#[test]
fn legal_two_byte_with_fixed_wildcard() {
    assert_eq!(
        Ok(BodySig {
            patterns: vec![Pattern::String(
                vec![
                    MatchByte::WildcardMany { size: 2 },
                    MatchByte::Full(0xaa),
                    MatchByte::Full(0xbb),
                ]
                .into(),
                PatternModifier::empty()
            ),],
        }),
        BodySig::try_from(b"{2}aabb".as_slice())
    );
}

#[cfg(feature = "broken_min_static_bytes")]
#[test]
fn no_static_bytes_within_string() {
    assert_eq!(
        Err(BodySigParseError::MinStaticBytes {
            start_pos: 5.into()
        }),
        BodySig::try_from(b"aabb*a?b???{2}".as_slice())
    );
}

#[cfg(feature = "broken_min_static_bytes")]
#[test]
fn no_static_bytes_within_string_leading_wildcard() {
    // This tests that the reported position is correct when the string includes
    // a brace wildcard
    assert_eq!(
        Err(BodySigParseError::MinStaticBytes {
            start_pos: 5.into()
        }),
        BodySig::try_from(b"aabb*{2}a?b???{2}".as_slice())
    );
}

#[test]
fn negated_generic_altstr() {
    // Generic due to differing sizes
    assert_eq!(
        Err(BodySigParseError::NegatedGenericAltStr {
            start_pos: 7.into()
        }),
        BodySig::try_from(b"012345!(aa|bbbb|cc)".as_slice())
    );
    // Generic due to nyble wildcard
    assert_eq!(
        Err(BodySigParseError::NegatedGenericAltStr {
            start_pos: 5.into()
        }),
        BodySig::try_from(b"00aa!(1a?5)abab".as_slice()),
    )
}

#[cfg(feature = "broken_min_static_bytes")]
#[test]
fn insufficient_static_bytes_ahead_of_gen_altstr() {
    assert_eq!(
        Err(BodySigParseError::MinStaticBytes {
            start_pos: 0.into()
        }),
        BodySig::try_from(b"00(a?)ffff".as_slice())
    );
}

#[cfg(feature = "broken_min_static_bytes")]
#[test]
fn insufficient_static_bytes_ahead_of_fixed_altstr() {
    assert_eq!(
        Err(BodySigParseError::MinStaticBytes {
            start_pos: 0.into()
        }),
        BodySig::try_from(b"00(ffaa)ffff".as_slice())
    );
}

#[cfg(feature = "broken_min_static_bytes")]
#[test]
fn insufficient_static_bytes_ahead_of_empty_altstr() {
    if let Err(e) = BodySig::try_from(b"00()aba?".as_slice()) {
        eprintln!("{e}")
    }
    assert_eq!(
        Err(BodySigParseError::MinStaticBytes {
            start_pos: 0.into()
        }),
        BodySig::try_from(b"00()aba?".as_slice())
    );
}

#[cfg(feature = "broken_min_static_bytes")]
#[test]
fn insufficient_static_bytes_ahead_of_large_range() {
    if let Err(e) = BodySig::try_from(b"00()aba?".as_slice()) {
        eprintln!("{e}")
    }
    assert_eq!(
        Err(BodySigParseError::MinStaticBytes {
            start_pos: 0.into()
        }),
        BodySig::try_from(b"00{500}aba?".as_slice())
    );
}

#[test]
fn legal_static_bytes_with_small_fixed_range() {
    assert_eq!(
        Ok(BodySig {
            patterns: vec![Pattern::String(
                vec![
                    MatchByte::Full(0x00),
                    MatchByte::WildcardMany { size: 2 },
                    MatchByte::Full(0xab),
                    MatchByte::Full(0xab),
                ]
                .into(),
                PatternModifier::empty()
            )]
        }),
        BodySig::try_from(b"00{2}abab".as_slice()),
    )
}
