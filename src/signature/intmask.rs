use crate::sigbytes::AppendSigBytes;
use num_traits::{bounds::Bounded, cast, sign::Unsigned, PrimInt};
use std::fmt::Write;

/// An integer with an associated mask, used for matching other integers
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct IntWithMask<T> {
    pub value: T,
    pub mask: T,
}

impl<T> IntWithMask<T>
where
    T: Unsigned + Bounded + PrimInt + std::fmt::UpperHex + std::fmt::LowerHex,
{
    fn format(&self, f: &mut std::fmt::Formatter, uppercase: bool) -> std::fmt::Result {
        // A nyble-wide mask that will float down the value
        let mut cur_mask = T::max_value() ^ T::max_value().shr(4);
        // The amount the currently-evaluated nyble needs to be shifted to
        // produce the right single-character hex value
        let mut cur_shift = std::mem::size_of::<T>() * 8;

        while !cur_mask.is_zero() {
            cur_shift -= 4;
            let low_nyble_mask: T = cast(0x0f).unwrap();
            if cur_mask & self.mask == cur_mask {
                f.write_char('?')?;
            } else if (cur_mask & self.mask).is_zero() {
                let nyble = self
                    .value
                    .bitand(cur_mask)
                    .shr(cur_shift)
                    .bitand(low_nyble_mask);
                if uppercase {
                    write!(f, "{:X}", nyble)?;
                } else {
                    write!(f, "{:x}", nyble)?;
                }
            } else {
                panic!(
                    "mask {:x} does not correspond directly to nyble(s)",
                    self.mask
                )
            }
            cur_mask = cur_mask >> 4;
        }

        Ok(())
    }
}

impl<T> AppendSigBytes for IntWithMask<T>
where
    T: Unsigned + PrimInt + std::fmt::Debug + std::fmt::LowerHex + std::fmt::UpperHex,
{
    fn append_sigbytes(
        &self,
        sb: &mut crate::sigbytes::SigBytes,
    ) -> Result<(), crate::signature::ToSigBytesError> {
        write!(sb, "{:x}", self)?;
        Ok(())
    }
}

impl<T> std::fmt::Display for IntWithMask<T>
where
    T: Unsigned + PrimInt + std::fmt::Debug + std::fmt::LowerHex + std::fmt::UpperHex,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:x}", self)?;
        Ok(())
    }
}

impl<T> std::fmt::LowerHex for IntWithMask<T>
where
    T: Unsigned + PrimInt + std::fmt::Debug + std::fmt::LowerHex + std::fmt::UpperHex,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.format(f, false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lower_hex() {
        let im = IntWithMask {
            value: 0x63u8,
            mask: 0x0f,
        };
        assert_eq!("6?", &format!("{:x}", im));

        let im = IntWithMask {
            value: 0x63u8,
            mask: 0xf0,
        };
        assert_eq!("?3", &format!("{:x}", im));

        // Tricky...
        let im = IntWithMask {
            value: 0x63u8,
            mask: 0xff,
        };
        assert_eq!("??", &format!("{:x}", im));
    }
}
