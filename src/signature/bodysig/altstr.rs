use super::pattern::MatchBytes;

#[derive(Debug, PartialEq)]
pub enum AlternativeStrings {
    FixedWidth {
        negated: bool,
        width: usize,
        data: MatchBytes,
    },
    Generic {
        ranges: Vec<std::ops::RangeInclusive<usize>>,
        data: MatchBytes,
    },
}
