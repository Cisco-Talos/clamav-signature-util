pub mod expression;
pub mod targetdesc;

use super::{ParseError, Signature};
use std::str;
use targetdesc::TargetDesc;

#[derive(Debug)]
pub struct LogicalSig {
    name: String,
    #[allow(dead_code)]
    target_desc: TargetDesc,
    #[allow(dead_code)]
    expression: Box<dyn expression::Element>,
}

impl Signature for LogicalSig {
    fn name(&self) -> &str {
        &self.name
    }

    fn feature_levels(&self) -> (usize, Option<usize>) {
        (51, None)
    }
}

impl TryFrom<&[u8]> for LogicalSig {
    type Error = ParseError;

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        let mut fields = data.split(|b| *b == b';');

        let name = str::from_utf8(fields.next().ok_or(ParseError::MissingName)?)?.into();
        let target_desc = fields
            .next()
            .ok_or(ParseError::MissingTargetDesc)?
            .try_into()?;
        let expression = fields
            .next()
            .ok_or(ParseError::MissingExpression)?
            .try_into()?;

        Ok(Self {
            name,
            target_desc,
            expression,
        })
    }
}
