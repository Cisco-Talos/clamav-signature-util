use std::fmt::{self, Write};

pub mod error;
pub use error::Parse as LogExprParseError;

/// Size of modifier match requirement and unique match requirement
type ModifierValue = usize;

/// An expression represents one or more indexes or other expressions bound by a
/// common operator (either & or |), and an optional modifier that futher refines
/// whether the expression matches.
#[derive(Debug)]
pub struct Expr {
    depth: u8,

    operation: Option<Operation>,

    /// Grouped elements that comprise this expression
    elements: Vec<Box<dyn Element>>,

    /// Optional modifier
    modifier: Option<Modifier>,
}

/// Required functionality of an expression `Element`
pub trait Element: fmt::Display + fmt::Debug {
    /// Whether or not this element represents a required or alternative match to
    /// all prior matches within the same expression.
    fn operation(&self) -> Option<Operation>;

    /// Set the operation for this element
    fn set_operation(&mut self, op: Option<Operation>);

    /// Return the optional modifier for this element
    fn modifier(&self) -> Option<Modifier>;

    /// Set the modifier for this element
    fn set_modifier(&mut self, op: Option<Modifier>);
}

/// An element's relationship to the prior element within the same expression.
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum Operation {
    /// This element is required, and matching fails if this expression does not
    /// match, and no alternatives are encountered.
    And,
    /// This element provides an an alternative should prior matches fail
    Or,
}

#[derive(Debug)]
/// A reference (by index) to a sub-signature specified within this logical
/// signature.
pub struct SigIndex {
    operation: Option<Operation>,
    sig_index: u8,
    modifier: Option<Modifier>,
}

#[derive(Debug, Clone, Copy)]
/// An element modifier. When specified, `match_req` is compared against the
/// number of matches found in the element, and must conform to the relationship
/// specified by `mod_op`
///
/// If `match_uniq` is specified, at least this many *unique* sub-signatures
/// must match, independent of the total number of matches.
pub struct Modifier {
    /// Relationsihp between number of matches and `match_req`
    pub mod_op: ModOp,
    /// Required number of matches
    pub match_req: ModifierValue,
    /// Minimum number of unique matches
    pub match_uniq: Option<ModifierValue>,
}

#[derive(Debug, Clone, Copy)]
pub enum ModOp {
    LessThan,
    Equal,
    GreaterThan,
}

/*********************************************************************
 * Expr
 *********************************************************************/

impl fmt::Display for Expr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(op) = self.operation() {
            write!(f, "{op}")?;
        }
        if self.depth > 0 {
            f.write_char('(')?;
        }
        for element in &self.elements {
            write!(f, "{element}")?;
        }
        if self.depth > 0 {
            f.write_char(')')?;
        }
        if let Some(modifier) = &self.modifier {
            write!(f, "{}{}", modifier.mod_op, modifier.match_req)?;
            if let Some(match_uniq) = modifier.match_uniq {
                write!(f, ",{match_uniq}")?;
            }
        }
        Ok(())
    }
}

impl Element for Expr {
    fn operation(&self) -> Option<Operation> {
        self.operation
    }

    fn set_operation(&mut self, op: Option<Operation>) {
        self.operation = op;
    }

    fn modifier(&self) -> Option<Modifier> {
        self.modifier
    }

    fn set_modifier(&mut self, modifier: Option<Modifier>) {
        self.modifier = modifier;
    }
}

/*********************************************************************
 * Modifier
 *********************************************************************/

impl fmt::Display for Modifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}{}", self.mod_op, self.match_req)?;
        if let Some(match_uniq) = self.match_uniq {
            write!(f, ",{match_uniq}")?;
        }
        Ok(())
    }
}

/*********************************************************************
 * Operation
 *********************************************************************/

impl fmt::Display for Operation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_char(match self {
            Operation::And => '&',
            Operation::Or => '|',
        })
    }
}

impl TryFrom<u8> for Operation {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            b'&' => Ok(Operation::And),
            b'|' => Ok(Operation::Or),
            _ => Err(()),
        }
    }
}

/*********************************************************************
 * Modifier Operation
 *********************************************************************/

impl fmt::Display for ModOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_char(match self {
            ModOp::LessThan => '<',
            ModOp::GreaterThan => '>',
            ModOp::Equal => '=',
        })
    }
}

impl TryFrom<u8> for ModOp {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            b'<' => Ok(ModOp::LessThan),
            b'=' => Ok(ModOp::Equal),
            b'>' => Ok(ModOp::GreaterThan),
            _ => Err(()),
        }
    }
}

/*********************************************************************
 * SigIndex
 *********************************************************************/

impl fmt::Display for SigIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(op) = self.operation() {
            write!(f, "{op}")?;
        }
        write!(f, "{}", self.sig_index)?;
        if let Some(modifier) = &self.modifier {
            write!(f, "{}{}", modifier.mod_op, modifier.match_req)?;
            if let Some(match_uniq) = modifier.match_uniq {
                write!(f, ",{match_uniq}")?;
            }
        }
        Ok(())
    }
}

impl Element for SigIndex {
    fn operation(&self) -> Option<Operation> {
        self.operation
    }

    fn set_operation(&mut self, op: Option<Operation>) {
        self.operation = op;
    }

    fn modifier(&self) -> Option<Modifier> {
        self.modifier
    }

    fn set_modifier(&mut self, modifier: Option<Modifier>) {
        self.modifier = modifier;
    }
}

/*********************************************************************
 * Element
 *********************************************************************/

impl TryFrom<&[u8]> for Box<dyn Element> {
    type Error = error::Parse;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let mut bytes = value.iter().copied().enumerate();
        parse_element(&mut bytes, 0)
    }
}

#[allow(clippy::too_many_lines)]
fn parse_element<B>(byte_stream: &mut B, depth: u8) -> Result<Box<dyn Element>, error::Parse>
where
    B: Iterator<Item = (usize, u8)> + Clone,
{
    #[derive(Debug)]
    enum State {
        // Next item should be a signature index or an expression
        Initial,
        // Found modifier operator, reading required matches
        ModReq,
        // Found the comma in the modifier
        ModUniq,
        // Found something that indicated the end of a modifier
        ApplyModifier,
    }

    let mut state = State::Initial;
    let mut sig_id = None;
    let mut operation = None;
    let mut mod_op = None;
    let mut match_req: Option<ModifierValue> = None;
    let mut match_uniq: Option<ModifierValue> = None;
    let mut elements = vec![];
    let mut modifier = None;
    let mut modval_pos = None;

    'handle_stream: loop {
        let b = byte_stream.next();
        'handle_byte: loop {
            match state {
                State::Initial => match b {
                    Some((_, b'(')) => {
                        let mut element = parse_element(byte_stream, depth + 1)?;
                        // Apply the prior operation (if any)
                        element.set_operation(operation.take());
                        elements.push(element);
                    }
                    Some((_, b')')) => {
                        if depth > 0 {
                            break 'handle_stream;
                        }
                        // FIXME: panic?
                        panic!("unmatched closing paren found");
                    }
                    // next digit
                    Some((_, b)) if b.is_ascii_digit() => {
                        sig_id = Some((b - b'0') + sig_id.unwrap_or_default() * 10);
                    }
                    // everything else
                    Some((pos, op)) if b.is_some() => {
                        if sig_id.is_some() {
                            let expr = Box::new(SigIndex {
                                operation: operation.take(),
                                sig_index: sig_id.take().unwrap(),
                                modifier: modifier.take(),
                            });
                            elements.push(expr);
                        }
                        if let Ok(this_op) = Operation::try_from(op) {
                            // No double-character operators are supported
                            if operation.is_some() {
                                return Err(error::Parse::UnexpectedOperator(pos.into()));
                            }
                            operation = Some(this_op);
                        } else if let Ok(this_modop) = ModOp::try_from(op) {
                            mod_op = Some(this_modop);
                            state = State::ModReq;
                            modval_pos = None;
                        } else {
                            return Err(error::Parse::InvalidCharacter(pos.into(), op.into()));
                        }
                    }
                    None => break 'handle_stream,
                    _ => unreachable!(),
                },
                State::ModReq => match b {
                    Some((pos, b)) if b.is_ascii_digit() => {
                        let start_pos = if let Some(pos) = modval_pos {
                            pos
                        } else {
                            modval_pos = Some(pos);
                            pos
                        };
                        match_req = Some(
                            ((b - b'0') as ModifierValue)
                                .checked_add(
                                    match_req.unwrap_or_default().checked_mul(10).ok_or_else(
                                        || {
                                            error::Parse::ModifierMatchValueOverflow(
                                                (start_pos..=pos).into(),
                                            )
                                        },
                                    )?,
                                )
                                .ok_or_else(|| {
                                    error::Parse::ModifierMatchValueOverflow(
                                        (start_pos..=pos).into(),
                                    )
                                })?,
                        );
                    }
                    Some((_, b',')) => state = State::ModUniq,
                    _ => {
                        state = State::ApplyModifier;
                        continue 'handle_byte;
                    }
                },
                State::ModUniq => match b {
                    Some((pos, b)) if b.is_ascii_digit() => {
                        let start_pos = if let Some(pos) = modval_pos {
                            pos
                        } else {
                            modval_pos = Some(pos);
                            pos
                        };
                        match_uniq = Some(
                            ((b - b'0') as ModifierValue)
                                .checked_add(
                                    match_uniq.unwrap_or_default().checked_mul(10).ok_or_else(
                                        || {
                                            error::Parse::ModifierMatchValueOverflow(
                                                (start_pos..=pos).into(),
                                            )
                                        },
                                    )?,
                                )
                                .ok_or_else(|| {
                                    error::Parse::ModifierMatchValueOverflow(
                                        (start_pos..=pos).into(),
                                    )
                                })?,
                        );
                    }
                    pos_and_byte => {
                        if match_uniq.is_none() {
                            return Err(error::Parse::ModifierMatchUniqMissing(
                                pos_and_byte.into(),
                            ));
                        }
                        state = State::ApplyModifier;
                        continue 'handle_byte;
                    }
                },
                State::ApplyModifier => {
                    assert!(modifier.is_none(), "Already had a modifier!");
                    if match_req.is_none() {
                        return Err(error::Parse::ModifierMatchReqMissing(b.into()));
                    }
                    let this_modifier = Some(Modifier {
                        mod_op: mod_op.take().unwrap(),
                        match_req: match_req.take().unwrap(),
                        match_uniq: match_uniq.take(),
                    });
                    // Modifier applies to prior element if still within the stream, or to the outer expression if not
                    if b.is_some() {
                        if let Some(element) = elements.last_mut() {
                            // eprintln!("Applying modifier to last element ({:?}", &element);
                            element.set_modifier(this_modifier);
                            // eprintln!("Applied modifier to last element  ({:?}", &element);
                        } else {
                            panic!("Modifier with no prior expression");
                        }
                    } else {
                        // eprintln!("Apply modifier to this expression (saving for later)");
                        modifier = this_modifier;
                    }
                    state = State::Initial;
                    continue 'handle_byte;
                }
            }

            break;
        }
    }

    if let Some(sig_id) = sig_id {
        let expr = Box::new(SigIndex {
            operation: operation.take(),
            sig_index: sig_id,
            // modifier: modifier.take(),
            modifier: None,
        });
        // eprintln!("Push final expr = {:?}", expr);
        elements.push(expr);
    }

    Ok(Box::new(Expr {
        depth,
        operation,
        elements,
        modifier,
    }))
}

#[cfg(test)]
mod tests {
    #[test]
    fn large_set() {
        // This test mainly confirms that expressions don't crash, and outputs
        // the expressions for human inspection.
        let mut errs = vec![];
        for (i, &expr_bytes) in crate::test_data::TEST_LOGICAL_EXPRS
            .iter()
            .enumerate()
            .skip(6)
        {
            let expr_s = expr_bytes.to_owned();
            let before = std::str::from_utf8(&expr_s).unwrap();
            eprintln!("{i}. before = {before}");
            let element: Result<Box<dyn super::Element>, _> = expr_bytes.try_into();
            match element {
                Ok(element) => {
                    eprintln!("{i}.  after = {element}");
                    assert_eq!(before, element.to_string());
                }
                Err(e) => {
                    eprintln!("{}.  error = {}", i, &e);
                    errs.push((before.to_owned(), e));
                }
            }
        }
        if !errs.is_empty() {
            eprintln!("Encountered {} error(s):", errs.len());
            errs.iter().enumerate().for_each(|(pos, (expr, e))| {
                eprintln!("{}. {} - {}", pos + 1, expr, e);
            });
        }
    }
}
