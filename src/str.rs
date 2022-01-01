use std::fmt;
use std::rc::Rc;
use std::str::FromStr;

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Buf {
    inner: Rc<Vec<u8>>,
}

impl Buf {
    #[inline]
    pub fn len(&self) -> usize {
        self.inner.len()
    }
}

impl AsRef<[u8]> for Buf {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.inner
    }
}

impl Default for Buf {
    #[inline]
    fn default() -> Self {
        Self {
            inner: Rc::new(vec!()),
        }
    }
}

impl From<Vec<u8>> for Buf {
    #[inline]
    fn from(mut s: Vec<u8>) -> Self {
        s.shrink_to_fit();
        Self {
            inner: Rc::new(s),
        }
    }
}

impl<T> From<&T> for Buf where T: AsRef<[u8]> + ?Sized {
    #[inline]
    fn from(s: &T) -> Self {
        Self {
            inner: Rc::new(s.as_ref().to_owned()),
        }
    }
}

impl fmt::Debug for Buf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        /* FIXME: allow printing of hex crap, data here does not have to be utf-8, and printing it
         * like this could panic.
         */
        let s = std::str::from_utf8(self.inner.as_ref()).unwrap();
        f.write_fmt(format_args!("Bytes<{:?}>", s))
    }
}

pub(crate) struct StringLiteralParseError {
}

fn hex_decode(chr: char) -> u8 {
    debug_assert!(chr.is_ascii_hexdigit());
    let c = chr as u8;
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => unreachable!()
    }
}

impl FromStr for Buf {
    type Err = StringLiteralParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let inner = &s[1..s.len() - 1];
        let mut hex = false;
        let mut v: Vec<u8> = Vec::new();
        let mut h: [u8; 2] = [0, 0];
        let mut ix: usize = 0;

        for chr in inner.chars() {
            if !hex {
                if chr == '|' {
                    hex = true;
                    ix = 0;
                    continue;
                }
                v.push(chr as u8);
            } else {
                if chr.is_whitespace() {
                    continue;
                }

                if chr == '|' {
                    if ix != 0 {
                        /* Odd number of hex digits */
                        return Err(Self::Err {});
                    }

                    hex = false;
                    continue;
                }

                if !chr.is_ascii_hexdigit() {
                    /* Non-hex in hex sequence */
                    return Err(Self::Err {});
                }

                h[ix] = hex_decode(chr);
                ix += 1;
                if ix == 2 {
                    v.push((h[0] << 4) | h[1]);
                    ix = 0;
                }
            }
        }

        Ok(Buf::from(v))
    }
}
