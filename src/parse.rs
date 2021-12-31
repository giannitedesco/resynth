use crate::lex::{TokType, Token};
use crate::err::Error;
use crate::err::Error::ParseError;
use crate::val::Val;
use crate::args::ArgExpr;

use std::net::{Ipv4Addr, SocketAddrV4};

#[derive(Debug)]
pub(crate) struct ObjectRef {
    pub modules: Box<[String]>,
    pub components: Box<[String]>,
}

#[derive(Debug)]
pub(crate) struct Call {
    pub obj: ObjectRef,
    pub args: Vec<ArgExpr>
}

#[derive(Debug)]
pub(crate) enum Expr {
    Nil,
    Literal(Val),
    ObjectRef(ObjectRef),
    Call(Call),
}

impl Default for Expr {
    fn default() -> Self {
        Expr::Nil
    }
}

#[derive(Debug)]
pub(crate) struct Import {
    pub module: String,
}

#[derive(Debug)]
pub(crate) struct Assign {
    pub target: String,
    pub rvalue: Expr,
}

#[derive(Debug)]
pub(crate) enum Stmt {
    //Nop,
    Import(Import),
    Assign(Assign),
    Expr(Expr),
}

#[derive(Debug, Copy, Clone)]
enum State {
    Initial,

    Import,
    ImportEnd,
    ReduceImport,

    Let,
    Assign,

    RefComponent,
    ReduceModule,
    RefModule,
    ReduceObject,
    ReduceRefCall,
    ReduceRefNaked,
    RefObject,
    RefObjEnd,

    ReduceCall,

    ReduceArg,
    ArgNext,

    ExprArg,
    ArgName,
    ArgVal,
    ExprStmt,
    ExprRvalue,

    IPv4,
    IPv4Colon,

    ReduceLiteralExpr,
    ReduceRefExpr,
    ReduceCallExpr,
    ReduceExpr,
    ReduceSockAddr,

    ExprStmtEnd,
    AssignStmtEnd,

    ReduceAssign,

    ReduceExprStmt,
    ReduceAssignStmt,

    ReduceStmt,

    Accept,
}

#[derive(Debug)]
struct PathBuilder {
    module: Vec<String>,
    object: Vec<String>,
}

impl PathBuilder {
    pub fn new() -> Self {
        Self {
            module: Vec::new(),
            object: Vec::new(),
        }
    }
}

#[derive(Debug)]
enum Node {
    State(State),

    //Port(u16),
    //Address(Ipv4Addr),
    //SockAddr(SocketAddrV4),
    Literal(Val),

    Module(String),
    AssignTo(String),
    Component(String),

    ArgName(Option<String>),
    ArgList(Vec<ArgExpr>),

    Path(PathBuilder),

    Object(ObjectRef),

    Expr(Expr),
    Assign(Assign),
    Call(Call),

    Stmt(Stmt),
}

impl From<Node> for State {
    fn from(node: Node) -> Self {
        match node {
            Node::State(s) => s,
            _ => unreachable!()
        }
    }
}

impl From<Node> for u16 {
    fn from(node: Node) -> Self {
        match node {
            Node::Literal(Val::U64(u)) => u as u16,
            _ => unreachable!()
        }
    }
}

impl From<Node> for Ipv4Addr {
    fn from(node: Node) -> Self {
        match node {
            Node::Literal(Val::Ip4(addr)) => addr,
            _ => unreachable!()
        }
    }
}

impl From<Node> for String {
    fn from(node: Node) -> Self {
        match node {
            Node::Module(s) => s,
            Node::AssignTo(s) => s,
            Node::Component(s) => s,
            _ => unreachable!()
        }
    }
}

impl From<Node> for Option<String> {
    fn from(node: Node) -> Self {
        match node {
            Node::ArgName(s) => s,
            _ => unreachable!()
        }
    }
}

impl From<Node> for Vec<ArgExpr> {
    fn from(node: Node) -> Self {
        match node {
            Node::ArgList(list) => list,
            _ => unreachable!()
        }
    }
}

impl From<Node> for Val {
    fn from(node: Node) -> Self {
        match node {
            Node::Literal(val) => val,
            _ => unreachable!()
        }
    }
}

impl From<Node> for Expr {
    fn from(node: Node) -> Self {
        match node {
            Node::Expr(expr) => expr,
            _ => unreachable!()
        }
    }
}

impl From<Node> for PathBuilder {
    fn from(node: Node) -> Self {
        match node {
            Node::Path(p) => p,
            _ => unreachable!()
        }
    }
}

impl From<Node> for ObjectRef {
    fn from(node: Node) -> Self {
        match node {
            Node::Object(obj) => obj,
            _ => unreachable!()
        }
    }
}

impl From<Node> for Call {
    fn from(node: Node) -> Self {
        match node {
            Node::Call(c) => c,
            _ => unreachable!()
        }
    }
}

impl From<Node> for Assign {
    fn from(node: Node) -> Self {
        match node {
            Node::Assign(a) => a,
            _ => unreachable!()
        }
    }
}

impl From<Node> for Stmt {
    fn from(node: Node) -> Self {
        match node {
            Node::Stmt(c) => c,
            _ => unreachable!()
        }
    }
}

pub(crate) struct Parser {
    state: State,
    stack: Vec<Node>,

    stmts: Vec<Stmt>,
}

enum Action {
    Discard(State),
    Shift(State, Node),
    Goto(State),
    Accept,
}

impl Parser {
    pub fn new() -> Parser {
        Parser {
            state: State::Initial,
            stack: Vec::new(),
            stmts: Vec::new(),
        }
    }

    fn push(&mut self, item: Node) {
        self.stack.push(item);
    }

    fn push_goto(&mut self, st: State) {
        self.stack.push(Node::State(st));
    }

    fn pop(&mut self) -> Node {
        self.stack.pop().unwrap()
    }

    fn reduce_module(&mut self) {
        let component: String = self.pop().into();
        let mut builder: PathBuilder = self.pop().into();

        //println!("{:?} -> module {:?}", builder, component);

        builder.module.push(component);
        self.push(Node::Path(builder));
    }

    fn reduce_object(&mut self) {
        let component: String = self.pop().into();
        let mut builder: PathBuilder = self.pop().into();

        //println!("{:?} -> object {:?}", builder, component);

        builder.object.push(component);
        self.push(Node::Path(builder));
    }

    fn reduce_ref(&mut self) {
        self.reduce_object();

        let builder: PathBuilder = self.pop().into();


        let obj = ObjectRef {
            modules: builder.module.into_boxed_slice(),
            components: builder.object.into_boxed_slice(),
        };

        //println!("push: completed object reference {:?}", obj);
        self.push(Node::Object(obj));
    }

    fn reduce_sockaddr(&mut self) {
        let port = self.pop();
        let addr = self.pop();

        //println!("reduce sockaddr: {:?} {:?}", addr, port);

        let val = Val::from(SocketAddrV4::new(addr.into(), port.into()));
        self.push(Node::Literal(val));
    }

    fn reduce_literal_expr(&mut self) {
        let lit = self.pop();
        self.push(Node::Expr(Expr::Literal(lit.into())));
    }

    fn reduce_ref_expr(&mut self) {
        let lit = self.pop();
        self.push(Node::Expr(Expr::ObjectRef(lit.into())));
    }

    fn reduce_call_expr(&mut self) {
        let lit = self.pop();
        self.push(Node::Expr(Expr::Call(lit.into())));
    }

    fn reduce_arg(&mut self) {
        let arg = self.pop();
        let arg_name = self.pop();
        let def = ArgExpr::new(arg_name.into(), arg.into());

        let mut list: Vec<ArgExpr> = self.pop().into();

        //println!("reduce arg: {:?} + {:?}", list, def);

        list.push(def);
        self.push(Node::ArgList(list));
    }

    fn reduce_call(&mut self) {
        let args: Vec<ArgExpr> = self.pop().into();
        let obj = self.pop();

        let call = Call {
            obj: obj.into(),
            args,
        };

        //println!("reduce call: {:?}", call);
        self.push(Node::Call(call));
    }

    fn reduce_assign(&mut self) {
        let call = self.pop();
        let target = self.pop();

        let assign = Assign {
            target: target.into(),
            rvalue: call.into(),
        };

        //println!("reduce assign: {:?}", assign);
        self.push(Node::Assign(assign));
    }

    fn reduce_expr_stmt(&mut self) {
        let expr = self.pop();

        //println!("reduce call: {:?}", call);
        self.push(Node::Stmt(Stmt::Expr(expr.into())));
    }

    fn reduce_assign_stmt(&mut self) {
        let expr = self.pop();

        //println!("reduce call: {:?}", call);
        self.push(Node::Stmt(Stmt::Assign(expr.into())));
    }

    fn reduce_import_stmt(&mut self) {
        let module = self.pop();

        let import = Import {
            module: module.into(),
        };

        //println!("reduce import stmt: {:?}", import);
        self.push(Node::Stmt(Stmt::Import(import)));
    }

    fn reduce_stmt(&mut self) {
        let stmt = self.pop();
        self.stmts.push(stmt.into());
    }

    fn state_initial(&mut self, tok: Token) -> Result<Action, Error> {
        match tok.typ {
            TokType::ImportKeyword => Ok(Action::Discard(State::Import)),
            TokType::LetKeyword => Ok(Action::Discard(State::Let)),
            TokType::Identifier => Ok(Action::Goto(State::ExprStmt)),
            TokType::Eof => Ok(Action::Accept),
            _ => Err(ParseError)
        }
    }

    fn state_import(&mut self, tok: Token) -> Result<Action, Error> {
        match tok.typ {
            TokType::Identifier => Ok(
                Action::Shift(State::ImportEnd, Node::Module(tok.into()))
            ),
            _ => Err(ParseError)
        }
    }

    fn state_import_end(&mut self, tok: Token) -> Result<Action, Error> {
        match tok.typ {
            TokType::SemiColon => Ok(Action::Discard(State::ReduceImport)),
            _ => Err(ParseError)
        }
    }

    fn state_reduce_import(&mut self, _tok: Token) -> Result<Action, Error> {
        self.reduce_import_stmt();
        Ok(Action::Goto(State::ReduceStmt))
    }

    fn state_let(&mut self, tok: Token) -> Result<Action, Error> {
        match tok.typ {
            TokType::Identifier => Ok(
                Action::Shift(State::Assign, Node::AssignTo(tok.into()))
            ),
            _ => Err(ParseError)
        }
    }

    fn state_assign(&mut self, tok: Token) -> Result<Action, Error> {
        match tok.typ {
            TokType::Equals => Ok(Action::Discard(State::ExprRvalue)),
            _ => Err(ParseError)
        }
    }

    fn state_ref_component(&mut self, tok: Token) -> Result<Action, Error> {
        match tok.typ {
            TokType::DoubleColon => Ok(Action::Discard(State::ReduceModule)),
            TokType::Dot => Ok(Action::Discard(State::ReduceObject)),
            TokType::LParen => Ok(Action::Discard(State::ReduceRefCall)),
            _ => Ok(Action::Goto(State::ReduceRefNaked))
        }
    }

    fn state_reduce_object(&mut self, _tok: Token) -> Result<Action, Error> {
        self.reduce_object();
        Ok(Action::Goto(State::RefObject))
    }

    fn state_reduce_ref_call(&mut self, _tok: Token) -> Result<Action, Error> {
        self.reduce_ref();
        self.push(Node::ArgList(Vec::new()));
        Ok(Action::Goto(State::ExprArg))
    }

    fn state_reduce_ref_naked(&mut self, _tok: Token) -> Result<Action, Error> {
        self.reduce_ref();
        Ok(Action::Goto(State::ReduceRefExpr))
    }

    fn state_reduce_module(&mut self, _tok: Token) -> Result<Action, Error> {
        self.reduce_module();
        Ok(Action::Goto(State::RefModule))
    }

    fn state_ref_module(&mut self, tok: Token) -> Result<Action, Error> {
        match tok.typ {
            TokType::Identifier => Ok(
                Action::Shift(State::RefComponent, Node::Component(tok.into()))
            ),
            _ => Err(ParseError)
        }
    }

    fn state_ref_object(&mut self, tok: Token) -> Result<Action, Error> {
        match tok.typ {
            TokType::Identifier => Ok(
                Action::Shift(State::RefObjEnd, Node::Component(tok.into())),
            ),
            _ => Err(ParseError)
        }
    }

    fn state_ref_obj_end(&mut self, tok: Token) -> Result<Action, Error> {
        Ok(match tok.typ {
            TokType::Dot => Action::Discard(State::ReduceObject),
            TokType::LParen => Action::Discard(State::ReduceRefCall),
            _ => Action::Goto(State::ReduceRefNaked)
        })
    }

    fn state_arg_next(&mut self, tok: Token) -> Result<Action, Error> {
        match tok.typ {
            TokType::Comma => Ok(Action::Discard(State::ExprArg)),
            TokType::RParen => Ok(Action::Shift(State::ReduceCall, Node::State(State::ReduceArg))),
            _ => Err(ParseError)
        }
    }

    #[inline(always)]
    fn push_literal(&mut self, tok: Token) -> Result<Action, Error> {
        match tok.typ {
            TokType::StringLiteral
            | TokType::IntegerLiteral => Ok(
                Action::Shift(State::ReduceLiteralExpr, Node::Literal(Val::from_token(tok)?))
            ),
            TokType::IPv4Literal => Ok(
                Action::Shift(State::IPv4, Node::Literal(Val::from_token(tok)?))
            ),
            _ => unreachable!()
        }
    }

    fn state_expr_arg(&mut self, tok: Token) -> Result<Action, Error> {
        Ok(match tok.typ {
            TokType::Identifier => Action::Shift(State::ArgName, Node::ArgName(Some(tok.into()))),
            _ => {
                self.push(Node::ArgName(None));
                Action::Goto(State::ArgVal)
            }
        })
    }

    fn state_arg_name(&mut self, tok: Token) -> Result<Action, Error> {
        Ok(match tok.typ {
            TokType::Colon => Action::Discard(State::ArgVal),
            _ => {
                let component: Option<String> = self.pop().into();
                self.push(Node::ArgName(None));
                self.push_goto(State::ReduceArg);
                self.push(Node::Path(PathBuilder::new()));
                self.push(Node::Component(component.unwrap()));
                Action::Goto(State::RefComponent)
            }
        })
    }

    fn state_arg_val(&mut self, tok: Token) -> Result<Action, Error> {
        self.push_goto(State::ReduceArg);
        match tok.typ {
            TokType::Identifier => {
                self.push(Node::Path(PathBuilder::new()));
                Ok(Action::Shift(State::RefComponent, Node::Component(tok.into())))
            }
            TokType::StringLiteral
            | TokType::IntegerLiteral
            | TokType::IPv4Literal => Ok(self.push_literal(tok)?),
            TokType::RParen => {
                let st = self.pop();
                let _ = self.pop();
                self.push(st);
                Ok(Action::Discard(State::ReduceCall))
            },
            _ => Err(ParseError)
        }
    }

    fn state_expr_stmt(&mut self, tok: Token) -> Result<Action, Error> {
        self.push_goto(State::ExprStmtEnd);
        match tok.typ {
            TokType::Identifier => {
                self.push(Node::Path(PathBuilder::new()));
                Ok(Action::Shift(State::RefComponent, Node::Component(tok.into())))
            }
            TokType::StringLiteral
            | TokType::IntegerLiteral
            | TokType::IPv4Literal => Ok(self.push_literal(tok)?),
            _ => Err(ParseError)
        }
    }

    fn state_expr_rvalue(&mut self, tok: Token) -> Result<Action, Error> {
        self.push_goto(State::AssignStmtEnd);
        match tok.typ {
            TokType::Identifier => {
                self.push(Node::Path(PathBuilder::new()));
                Ok(Action::Shift(State::RefComponent, Node::Component(tok.into())))
            }
            TokType::StringLiteral
            | TokType::IntegerLiteral
            | TokType::IPv4Literal => Ok(self.push_literal(tok)?),
            _ => Err(ParseError)
        }
    }

    fn state_ipv4(&mut self, tok: Token) -> Result<Action, Error> {
        Ok(match tok.typ {
            TokType::Colon => Action::Discard(State::IPv4Colon),
            _ => Action::Goto(State::ReduceLiteralExpr)
        })
    }

    fn state_ipv4_colon(&mut self, tok: Token) -> Result<Action, Error> {
        match tok.typ {
            TokType::IntegerLiteral => Ok(
                Action::Shift(State::ReduceSockAddr, Node::Literal(Val::from_token(tok)?))
            ),
            _ => Err(ParseError)
        }
    }

    fn state_reduce_arg(&mut self, _tok: Token) -> Result<Action, Error> {
        self.reduce_arg();
        Ok(Action::Goto(State::ArgNext))
    }

    fn state_reduce_literal_expr(&mut self, _tok: Token) -> Result<Action, Error> {
        self.reduce_literal_expr();
        Ok(Action::Goto(State::ReduceExpr))
    }

    fn state_reduce_ref_expr(&mut self, _tok: Token) -> Result<Action, Error> {
        self.reduce_ref_expr();
        Ok(Action::Goto(State::ReduceExpr))
    }

    fn state_reduce_call_expr(&mut self, _tok: Token) -> Result<Action, Error> {
        self.reduce_call_expr();
        Ok(Action::Goto(State::ReduceExpr))
    }

    fn state_reduce_expr(&mut self, _tok: Token) -> Result<Action, Error> {
        let a = self.pop();
        let st = self.pop();
        self.push(a);
        Ok(Action::Goto(st.into()))
    }

    fn state_reduce_sockaddr(&mut self, _tok: Token) -> Result<Action, Error> {
        self.reduce_sockaddr();
        Ok(Action::Goto(State::ReduceLiteralExpr))
    }

    fn state_reduce_call(&mut self, _tok: Token) -> Result<Action, Error> {
        self.pop(); // state for next arg
        self.reduce_call();
        Ok(Action::Goto(State::ReduceCallExpr))
    }

    fn state_expr_stmt_end(&mut self, tok: Token) -> Result<Action, Error> {
        match tok.typ {
            TokType::SemiColon => Ok(Action::Discard(State::ReduceExprStmt)),
            _ => Err(ParseError)
        }
    }

    fn state_assign_stmt_end(&mut self, tok: Token) -> Result<Action, Error> {
        match tok.typ {
            TokType::SemiColon => Ok(Action::Discard(State::ReduceAssign)),
            _ => Err(ParseError)
        }
    }

    fn state_reduce_assign(&mut self, _tok: Token) -> Result<Action, Error> {
        self.reduce_assign();
        Ok(Action::Goto(State::ReduceAssignStmt))
    }

    fn state_reduce_expr_stmt(&mut self, _tok: Token) -> Result<Action, Error> {
        self.reduce_expr_stmt();
        Ok(Action::Goto(State::ReduceStmt))
    }

    fn state_reduce_assign_stmt(&mut self, _tok: Token) -> Result<Action, Error> {
        self.reduce_assign_stmt();
        Ok(Action::Goto(State::ReduceStmt))
    }

    fn state_reduce_stmt(&mut self, _tok: Token) -> Result<Action, Error> {
        self.reduce_stmt();
        Ok(Action::Goto(State::Initial))
    }

    fn dispatch(&mut self, tok: Token) -> Result<Action, Error> {
        //println!("{:<24} {:?} {:?}", format!("State::{:?}", self.state), tok.typ, tok.val);
        match self.state {
            State::Initial => self.state_initial(tok),
            State::Import => self.state_import(tok),
            State::ImportEnd => self.state_import_end(tok),
            State::ReduceImport => self.state_reduce_import(tok),

            State::Let => self.state_let(tok),
            State::Assign => self.state_assign(tok),

            State::RefComponent => self.state_ref_component(tok),
            State::ReduceModule => self.state_reduce_module(tok),
            State::RefModule => self.state_ref_module(tok),
            State::ReduceObject => self.state_reduce_object(tok),
            State::ReduceRefCall => self.state_reduce_ref_call(tok),
            State::ReduceRefNaked => self.state_reduce_ref_naked(tok),
            State::RefObject => self.state_ref_object(tok),
            State::RefObjEnd => self.state_ref_obj_end(tok),

            State::ReduceArg => self.state_reduce_arg(tok),
            State::ArgNext => self.state_arg_next(tok),
            State::ReduceCall => self.state_reduce_call(tok),

            State::ExprArg => self.state_expr_arg(tok),
            State::ArgName => self.state_arg_name(tok),
            State::ArgVal => self.state_arg_val(tok),
            State::ExprStmt => self.state_expr_stmt(tok),
            State::ExprRvalue => self.state_expr_rvalue(tok),

            State::IPv4 => self.state_ipv4(tok),
            State::IPv4Colon => self.state_ipv4_colon(tok),

            State::ReduceLiteralExpr => self.state_reduce_literal_expr(tok),
            State::ReduceRefExpr => self.state_reduce_ref_expr(tok),
            State::ReduceCallExpr => self.state_reduce_call_expr(tok),
            State::ReduceExpr => self.state_reduce_expr(tok),
            State::ReduceSockAddr => self.state_reduce_sockaddr(tok),

            State::ExprStmtEnd => self.state_expr_stmt_end(tok),
            State::AssignStmtEnd => self.state_assign_stmt_end(tok),

            State::ReduceAssign => self.state_reduce_assign(tok),

            State::ReduceExprStmt => self.state_reduce_expr_stmt(tok),
            State::ReduceAssignStmt => self.state_reduce_assign_stmt(tok),

            State::ReduceStmt => self.state_reduce_stmt(tok),

            State::Accept => Err(ParseError),
            //_ => Err(ParseError),
        }
    }

    pub fn feed(&mut self, tok: Token) -> Result<(), Error> {
        loop {
            let action = self.dispatch(tok)?;
            match action {
                Action::Discard(st) => {
                    self.state = st;
                    //println!("");
                },
                Action::Shift(st, frag) => {
                    self.push(frag);
                    self.state = st;
                    //println!("");
                },
                Action::Goto(st) => {
                    self.state = st;
                    continue;
                },
                Action::Accept => {
                    self.state = State::Accept;
                    //println!("");
                }
            };
            return Ok(())
        }
    }

    pub fn get_results(&mut self) -> Vec<Stmt> {
        std::mem::take(&mut self.stmts)
    }
}
