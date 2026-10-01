use derive_more::{Display, Error};

use std::fmt;
use std::rc::Rc;
use std::str::FromStr;

#[derive(Default, Clone, PartialEq, Eq)]
pub struct Buf {
    inner: Rc<Box<[u8]>>,
}

impl Buf {
    #[inline]
    pub fn from_slice<T: AsRef<[u8]>>(s: T) -> Self {
        Self {
            inner: Rc::new(s.as_ref().into()),
        }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn cow_buffer(self) -> Box<[u8]> {
        Rc::unwrap_or_clone(self.inner)
    }
}

impl AsRef<[u8]> for Buf {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.inner
    }
}

impl From<Vec<u8>> for Buf {
    #[inline]
    fn from(mut s: Vec<u8>) -> Self {
        s.shrink_to_fit();
        Self {
            inner: Rc::new(s.into()),
        }
    }
}

impl From<Box<[u8]>> for Buf {
    #[inline]
    fn from(s: Box<[u8]>) -> Self {
        Self { inner: Rc::new(s) }
    }
}

// Must take reference here because otherwise trait can be implemented for self
impl<T> From<&T> for Buf
where
    T: AsRef<[u8]> + ?Sized,
{
    #[inline]
    fn from(s: &T) -> Self {
        Self {
            inner: Rc::new(s.as_ref().into()),
        }
    }
}

impl fmt::Debug for Buf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", Literal(&self.inner))
    }
}

/// The bytes which may appear as themselves in a string literal: printable ASCII and space.
fn is_printable(b: u8) -> bool {
    (b' '..=b'~').contains(&b)
}

/// Displays bytes as a resynth string literal, quotes included, which reads back as the same
/// bytes. Printable ASCII is written as text and every other byte as hex inside `|...|`, with
/// bytes separated by spaces: `"|03|com|00|"`. `|` and `"` are written as hex because they have
/// special meaning in a literal.
#[derive(Debug, Clone, Copy)]
pub struct Literal<'a>(pub &'a [u8]);

impl Literal<'_> {
    fn is_text(b: u8) -> bool {
        is_printable(b) && b != b'|' && b != b'"'
    }
}

impl fmt::Display for Literal<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("\"")?;

        let mut in_hex = false;
        for &b in self.0 {
            if Self::is_text(b) {
                if in_hex {
                    f.write_str("|")?;
                    in_hex = false;
                }
                write!(f, "{}", b as char)?;
            } else {
                f.write_str(if in_hex { " " } else { "|" })?;
                in_hex = true;
                write!(f, "{b:02x}")?;
            }
        }

        if in_hex {
            f.write_str("|")?;
        }
        f.write_str("\"")
    }
}

/// Displays a character's UTF-8 encoding as it would be written in a string literal: `|c3 a9|`
struct HexForm(char);

impl fmt::Display for HexForm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut buf = [0; 4];
        let mut sep = "|";
        for b in self.0.encode_utf8(&mut buf).bytes() {
            write!(f, "{sep}{b:02x}")?;
            sep = " ";
        }
        f.write_str("|")
    }
}

/// Why the body of a string literal could not be decoded, and where
#[derive(Debug, Display, Error, Clone, Copy, PartialEq, Eq)]
#[display("{kind}")]
pub struct StringLiteralParseError {
    /// Byte offset of the offending character within the literal's body (the text between the
    /// quotes)
    pub offset: usize,
    pub kind: StringLiteralErrorKind,
}

/// What is wrong with the body of a string literal
#[derive(Debug, Display, Error, Clone, Copy, PartialEq, Eq)]
pub enum StringLiteralErrorKind {
    #[display("{_0:?} is not allowed in a string literal, write it as {}", HexForm(*_0))]
    #[error(ignore)]
    BadChar(char),

    #[display("invalid hex digit {_0:?} in string literal")]
    #[error(ignore)]
    BadHexDigit(char),

    #[display("odd number of hex digits in string literal")]
    OddHexDigits,

    #[display("unterminated hex sequence in string literal")]
    UnterminatedHex,
}

impl StringLiteralErrorKind {
    /// This error, at `offset` within the literal's body
    pub(crate) fn at(self, offset: usize) -> StringLiteralParseError {
        StringLiteralParseError { offset, kind: self }
    }
}

impl Buf {
    /// Decode the body of a string literal (the text between the quotes), appending the bytes to
    /// `out`. The body may contain only printable ASCII and space: any other byte must be written
    /// as hex. Text is copied as it is. Text between a pair of `|` is hex: each pair of hex digits
    /// becomes one byte, and spaces and the separators ``: . _ - ' ` `` are ignored. A hex
    /// sequence must be closed within the same literal.
    pub fn decode_literal_into(
        body: &str,
        out: &mut Vec<u8>,
    ) -> Result<(), StringLiteralParseError> {
        use StringLiteralErrorKind::*;

        let rewind = out.len();

        // Offset of the opening '|' while inside a hex sequence
        let mut hex_start: Option<usize> = None;
        // High nibble of a partially decoded byte
        let mut high: Option<u8> = None;

        for (offset, b) in body.bytes().enumerate() {
            if !is_printable(b) {
                // Every byte before this one was printable ASCII, so `offset` is on a char
                // boundary and this recovers the whole (maybe multi-byte) character.
                let chr = body
                    .get(offset..)
                    .and_then(|rest| rest.chars().next())
                    .unwrap_or(char::REPLACEMENT_CHARACTER);
                out.truncate(rewind);
                return Err(BadChar(chr).at(offset));
            }

            if hex_start.is_none() {
                if b == b'|' {
                    hex_start = Some(offset);
                } else {
                    out.push(b);
                }
                continue;
            }

            match b {
                b'|' => {
                    if high.is_some() {
                        out.truncate(rewind);
                        return Err(OddHexDigits.at(offset));
                    }
                    hex_start = None;
                }
                b' ' | b':' | b'.' | b'_' | b'-' | b'\'' | b'`' => {}
                b => {
                    let Some(nibble) = (b as char).to_digit(16) else {
                        out.truncate(rewind);
                        return Err(BadHexDigit(b as char).at(offset));
                    };
                    match high.take() {
                        Some(h) => out.push((h << 4) | nibble as u8),
                        None => high = Some(nibble as u8),
                    }
                }
            }
        }

        match hex_start {
            Some(offset) => {
                out.truncate(rewind);
                Err(UnterminatedHex.at(offset))
            }
            None => Ok(()),
        }
    }
}

impl FromStr for Buf {
    type Err = StringLiteralParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut v = Vec::new();
        Self::decode_literal_into(s, &mut v)?;
        Ok(Buf::from(v))
    }
}
