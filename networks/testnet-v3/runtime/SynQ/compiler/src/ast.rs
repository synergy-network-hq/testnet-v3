//! Abstract Syntax Tree (AST) for the SynQ language.

#[derive(Debug, PartialEq, Clone)]
pub enum SourceUnit {
    Contract(ContractDefinition),
    Struct(StructDefinition),
    Event(EventDefinition),
}

#[derive(Debug, PartialEq, Clone)]
pub struct ContractDefinition {
    pub name: String,
    pub parts: Vec<ContractPart>,
}

#[derive(Debug, PartialEq, Clone)]
pub enum ContractPart {
    StateVariable(StateVariableDeclaration),
    Constructor(ConstructorDefinition),
    Function(FunctionDefinition),
    Event(EventDefinition),
}

#[derive(Debug, PartialEq, Clone)]
pub struct StateVariableDeclaration {
    pub name: String,
    pub ty: Type,
    pub is_public: bool,
}

#[derive(Debug, PartialEq, Clone)]
pub struct ConstructorDefinition {
    pub params: Vec<Parameter>,
    pub body: Block,
}

#[derive(Debug, PartialEq, Clone)]
pub struct FunctionDefinition {
    pub name: String,
    pub params: Vec<Parameter>,
    pub returns: Option<Type>,
    pub body: Block,
    pub is_public: bool,
}

#[derive(Debug, PartialEq, Clone)]
pub struct StructDefinition {
    pub name: String,
    pub fields: Vec<Parameter>,
}

#[derive(Debug, PartialEq, Clone)]
pub struct EventDefinition {
    pub name: String,
    pub params: Vec<Parameter>,
}

#[derive(Debug, PartialEq, Clone)]
pub struct Parameter {
    pub name: String,
    pub ty: Type,
    pub is_indexed: bool,
}

#[derive(Debug, PartialEq, Clone)]
pub struct Block {
    pub statements: Vec<Statement>,
}

#[derive(Debug, PartialEq, Clone)]
pub enum Statement {
    Expression(Expression),
    Require(Expression, String),
    Assignment(String, Expression),
    Return(Option<Expression>),
}

#[derive(Debug, PartialEq, Clone)]
pub enum Expression {
    Call(String, Vec<Expression>),
    Literal(Literal),
    Identifier(String),
    BinaryOp(Box<Expression>, BinaryOperator, Box<Expression>),
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum BinaryOperator {
    Add,
    Sub,
    Mul,
    Div,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

#[derive(Debug, PartialEq, Clone)]
pub enum Type {
    Address,
    UInt256,
    Bool,
    Bytes,
    DilithiumPublicKey,
    FalconPublicKey,
    KyberPublicKey,
    DilithiumSignature,
    FalconSignature,
    Mapping(Box<Type>, Box<Type>),
}

#[derive(Debug, PartialEq, Clone)]
pub enum Literal {
    String(String),
    Number(u128),      // fits in u128 (≤ 2^128-1)
    BigNumber(String), // decimal string for values > u128::MAX (full UInt256)
    Bool(bool),
}
