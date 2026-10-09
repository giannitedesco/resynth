//! A recursive descent parser, using Pratt parsing for expressions.
//!
//! ```ebnf
//! program  = { stmt } EOF ;
//! stmt     = "import" IDENT ";"
//!          | "let" IDENT "=" expr ";"
//!          | expr ";" ;
//! expr     = postfix { "/" postfix } ;
//! postfix  = primary { "." IDENT | "(" [ args ] ")" } ;
//! primary  = literal
//!          | IPV4 [ ":" DEC ]
//!          | IDENT "::" IDENT { "::" IDENT }
//!          | IDENT ;
//! literal  = STRING | BOOL | HEX | DEC ;
//! args     = arg { "," arg } [ "," ] ;
//! arg      = [ IDENT ":" ] expr ;
//! ```

use std::collections::VecDeque;
use std::fmt;
use std::net::SocketAddrV4;

use derive_more::{Display, Error};

use crate::ast::{Arg, BinOp, Expr, ExprKind, Ident, Lit, ModulePath, Stmt};
use crate::lex::{Tok, Token};
use crate::loc::Loc;

/// Why the tokens could not be parsed, and where
#[derive(Debug, Display, Error, Clone, PartialEq, Eq)]
#[display("{loc}: {kind}")]
pub struct ParseError {
    pub loc: Loc,
    pub kind: ParseErrorKind,
}

/// What is wrong with the tokens
#[derive(Debug, Display, Error, Clone, PartialEq, Eq)]
pub enum ParseErrorKind {
    #[display("expected {}, found {found}", Expected(expected))]
    #[error(ignore)]
    UnexpectedToken {
        /// Every token or category that would have been valid, in the order the parser tries them
        expected: Box<[&'static str]>,
        found: Tok,
    },

    /// An integer literal greater than `u64::MAX`, or a port greater than `u16::MAX`
    #[display("integer literal out of range")]
    IntOutOfRange,
}

impl ParseErrorKind {
    /// This error, at `loc`
    pub(crate) fn at(self, loc: Loc) -> ParseError {
        ParseError { loc, kind: self }
    }
}

/// Displays the tokens a parser expected: `` `;` `` for one, and `` one of `(`, `.` or `;` `` for
/// several.
struct Expected<'a>(&'a [&'static str]);

impl fmt::Display for Expected<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            [] => f.write_str("nothing"),
            [one] => f.write_str(one),
            [first, middle @ .., last] => {
                write!(f, "one of {first}")?;
                for entry in middle {
                    write!(f, ", {entry}")?;
                }
                write!(f, " or {last}")
            }
        }
    }
}

type Result<T> = std::result::Result<T, ParseError>;

/// Parse a whole program. `toks` must end with a single [Tok::Eof], as [Lexer::lex] returns.
///
/// Stops at the first error.
///
/// [Lexer::lex]: crate::Lexer::lex
pub fn parse(toks: VecDeque<Token>) -> Result<Vec<Stmt>> {
    Parser {
        toks,
        expected: DedupeVec::default(),
    }
    .program()
}

/// A list built with duplicates, which drops them when it's finished
#[derive(Debug)]
struct DedupeVec<T>(Vec<T>);

impl<T> Default for DedupeVec<T> {
    fn default() -> Self {
        Self(Vec::new())
    }
}

impl<T: PartialEq> DedupeVec<T> {
    fn push(&mut self, item: T) {
        self.0.push(item);
    }

    fn clear(&mut self) {
        self.0.clear();
    }

    /// The items in the order they were first pushed, without duplicates
    fn into_vec(self) -> Vec<T> {
        let mut out = Vec::with_capacity(self.0.len());
        for item in self.0 {
            if !out.contains(&item) {
                out.push(item);
            }
        }
        out
    }
}

/// Invariant: the queue ends with [Tok::Eof], which is only taken when reporting an error. After
/// an error the parser is not used again.
///
/// # Expected tokens
///
/// When a parse error lists every token that would have been valid (see
/// [ParseErrorKind::UnexpectedToken]), the list comes from `expected`. Every test of the next
/// token that fails records what it was looking for, and taking a token clears the list. So at an
/// error, `expected` holds everything tried at that position, by every rule still on the stack, in
/// the order they were tried.
///
/// This only works if every test of the next token goes through a recording helper: [Parser::check],
/// [Parser::eat], [Parser::expect], [Parser::check_expr_start] or [Parser::take_matching]. A
/// bare [Parser::peek] in a decision silently drops its token from messages.
struct Parser {
    toks: VecDeque<Token>,
    expected: DedupeVec<&'static str>,
}

impl Parser {
    /// Binding power of the postfix operators, `.` and `(`, which bind tightest
    const POSTFIX_BP: u8 = 30;

    fn peek(&self) -> &Tok {
        self.toks
            .front()
            .expect("the token queue ends with Eof")
            .tok()
    }

    /// Take the next token, and clear the expected list. Only call this after a recording helper
    /// has matched a token other than [Tok::Eof], or when reporting an error.
    fn take(&mut self) -> Token {
        self.expected.clear();
        self.toks
            .pop_front()
            .expect("the token queue ends with Eof")
    }

    /// Whether the next token is `want`. If not, records `label` as expected.
    fn check(&mut self, want: &Tok, label: &'static str) -> bool {
        let found = self.peek() == want;
        if !found {
            self.expected.push(label);
        }
        found
    }

    /// Take the next token if it's `want`. If not, records `label` as expected.
    fn eat(&mut self, want: &Tok, label: &'static str) -> bool {
        let found = self.check(want, label);
        if found {
            self.take();
        }
        found
    }

    fn expect(&mut self, want: &Tok, label: &'static str) -> Result<()> {
        if self.eat(want, label) {
            Ok(())
        } else {
            Err(self.unexpected())
        }
    }

    /// Take the next token if `matches` accepts it. If not, records `label` as expected and fails.
    fn take_matching(&mut self, label: &'static str, matches: fn(&Tok) -> bool) -> Result<Token> {
        if matches(self.peek()) {
            Ok(self.take())
        } else {
            self.expected.push(label);
            Err(self.unexpected())
        }
    }

    /// Whether the next token can start an expression. If not, records `expression` as expected.
    fn check_expr_start(&mut self) -> bool {
        let found = matches!(
            self.peek(),
            Tok::Identifier(_)
                | Tok::BooleanLiteral(_)
                | Tok::IPv4Literal(_)
                | Tok::StringLiteral(_)
                | Tok::HexLiteral(_)
                | Tok::DecLiteral(_)
        );
        if !found {
            self.expected.push("expression");
        }
        found
    }

    /// Take the next token as the `found` of an error, with everything expected at its position
    fn unexpected(&mut self) -> ParseError {
        let expected = std::mem::take(&mut self.expected).into_vec().into();
        let (loc, found) = self.take().into_parts();
        ParseErrorKind::UnexpectedToken { expected, found }.at(loc)
    }

    fn ident(&mut self) -> Result<Ident> {
        let (loc, tok) = self
            .take_matching("identifier", |tok| matches!(tok, Tok::Identifier(_)))?
            .into_parts();
        let Tok::Identifier(name) = tok else {
            unreachable!("take_matching only takes an identifier");
        };
        Ok(Ident { loc, name })
    }

    /// Take an infix operator that binds at least as tightly as `min_bp`. Returns the operator
    /// and its right binding power.
    fn eat_infix(&mut self, min_bp: u8) -> Option<(BinOp, u8)> {
        // Left binding power 10, right 11: left associative
        if 10 >= min_bp && self.eat(&Tok::Slash, "`/`") {
            return Some((BinOp::Slash, 11));
        }
        None
    }

    fn program(mut self) -> Result<Vec<Stmt>> {
        let mut stmts = Vec::new();
        while !self.check(&Tok::Eof, "eof") {
            stmts.push(self.stmt()?);
        }
        Ok(stmts)
    }

    fn stmt(&mut self) -> Result<Stmt> {
        if self.eat(&Tok::ImportKeyword, "`import`") {
            let module = self.ident()?;
            self.expect(&Tok::SemiColon, "`;`")?;
            Ok(Stmt::Import(module))
        } else if self.eat(&Tok::LetKeyword, "`let`") {
            let target = self.ident()?;
            self.expect(&Tok::Equals, "`=`")?;
            let value = self.expr(0)?;
            self.expect(&Tok::SemiColon, "`;`")?;
            Ok(Stmt::Let { target, value })
        } else if self.check_expr_start() {
            let expr = self.expr(0)?;
            self.expect(&Tok::SemiColon, "`;`")?;
            Ok(Stmt::Expr(expr))
        } else {
            Err(self.unexpected())
        }
    }

    fn expr(&mut self, min_bp: u8) -> Result<Expr> {
        let mut lhs = self.primary()?;

        loop {
            let loc = lhs.loc;
            let kind = if Self::POSTFIX_BP >= min_bp && self.eat(&Tok::LParen, "`(`") {
                ExprKind::Call {
                    callee: Box::new(lhs),
                    args: self.args()?,
                }
            } else if Self::POSTFIX_BP >= min_bp && self.eat(&Tok::Dot, "`.`") {
                ExprKind::Member {
                    obj: Box::new(lhs),
                    name: self.ident()?,
                }
            } else if let Some((op, r_bp)) = self.eat_infix(min_bp) {
                ExprKind::Binary {
                    op,
                    lhs: Box::new(lhs),
                    rhs: Box::new(self.expr(r_bp)?),
                }
            } else {
                break;
            };
            lhs = Expr { loc, kind };
        }

        Ok(lhs)
    }

    fn primary(&mut self) -> Result<Expr> {
        if !self.check_expr_start() {
            return Err(self.unexpected());
        }
        let (loc, tok) = self.take().into_parts();

        let kind = match tok {
            Tok::BooleanLiteral(b) => ExprKind::Literal(Lit::Bool(b)),
            Tok::StringLiteral(buf) => ExprKind::Literal(Lit::Str(buf)),
            Tok::HexLiteral(i) | Tok::DecLiteral(i) => {
                let i = u64::try_from(i).map_err(|_| ParseErrorKind::IntOutOfRange.at(loc))?;
                ExprKind::Literal(Lit::Int(i))
            }
            Tok::IPv4Literal(addr) if self.eat(&Tok::Colon, "`:`") => {
                ExprKind::Literal(Lit::Sock4(SocketAddrV4::new(addr, self.port()?)))
            }
            Tok::IPv4Literal(addr) => ExprKind::Literal(Lit::Ip4(addr)),
            Tok::Identifier(name) if self.check(&Tok::DoubleColon, "`::`") => {
                ExprKind::ModulePath(Box::new(self.module_path(Ident { loc, name })?))
            }
            Tok::Identifier(name) => ExprKind::LocalRef(Ident { loc, name }),
            _ => unreachable!("check_expr_start only accepts the tokens above"),
        };

        Ok(Expr { loc, kind })
    }

    /// The port after `ip:`, which is decimal and must fit in a `u16`
    fn port(&mut self) -> Result<u16> {
        let (loc, tok) = self
            .take_matching("decimal port", |tok| matches!(tok, Tok::DecLiteral(_)))?
            .into_parts();
        let Tok::DecLiteral(port) = tok else {
            unreachable!("take_matching only takes a decimal literal");
        };
        u16::try_from(port).map_err(|_| ParseErrorKind::IntOutOfRange.at(loc))
    }

    /// The rest of a module path, after its first segment. The next token is `::`.
    fn module_path(&mut self, module: Ident) -> Result<ModulePath> {
        let mut segs = Vec::new();
        while self.eat(&Tok::DoubleColon, "`::`") {
            segs.push(self.ident()?);
        }

        let item = segs.pop().expect("a module path has at least two segments");
        Ok(ModulePath {
            module,
            inner: segs.into(),
            item,
        })
    }

    /// The arguments of a call, after the `(`, and the closing `)`
    fn args(&mut self) -> Result<Box<[Arg]>> {
        let mut args = Vec::new();

        loop {
            if self.check_expr_start() {
                args.push(self.arg()?);
            } else if self.eat(&Tok::RParen, "`)`") {
                break;
            } else {
                return Err(self.unexpected());
            }

            if self.eat(&Tok::Comma, "`,`") {
                continue;
            } else if self.eat(&Tok::RParen, "`)`") {
                break;
            } else {
                return Err(self.unexpected());
            }
        }

        Ok(args.into())
    }

    /// An argument. A positional argument that is a lone identifier becomes the name of a named
    /// argument if `:` follows it.
    fn arg(&mut self) -> Result<Arg> {
        let Expr { loc, kind } = self.expr(0)?;
        match kind {
            ExprKind::LocalRef(name) if self.eat(&Tok::Colon, "`:`") => Ok(Arg {
                name: Some(name),
                value: self.expr(0)?,
            }),
            kind => Ok(Arg {
                name: None,
                value: Expr { loc, kind },
            }),
        }
    }
}
