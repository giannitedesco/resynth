#[derive(Debug, Copy, Clone, PartialEq, Eq, Default)]
pub(crate) struct Loc {
    line: u32,
    col: u32,
}

#[allow(unused)]
impl Loc {
    pub const fn new(line: usize, col: usize) -> Self {
        Self {
            line: line as u32,
            col: col as u32,
        }
    }

    pub fn set_line(&mut self, lno: usize) {
        self.line = lno as u32;
    }

    pub fn set_col(&mut self, col: usize) {
        self.col = col as u32;
    }

    pub fn is_nil(&self) -> bool {
        *self == Self::nil()
    }

    pub const fn nil() -> Self {
        Self::new(0, 0)
    }

    pub const fn line(&self) -> usize {
        self.line as usize
    }

    pub const fn col(&self) -> usize {
        self.col as usize
    }
}
