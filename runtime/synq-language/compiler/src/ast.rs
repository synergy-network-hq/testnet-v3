//! Abstract Syntax Tree (AST) for the SynQ language.

use std::collections::HashMap;

#[derive(Debug, PartialEq, Clone)]
pub enum SourceUnit {
    Contract(ContractDefinition),
    Struct(StructDefinition),
    Event(EventDefinition),
}

#[derive(Debug, PartialEq, Clone)]
pub struct Annotation {
    pub name: String,
    pub args: Vec<Expression>,
}

#[derive(Debug, PartialEq, Clone)]
pub struct ContractDefinition {
    pub name: String,
    pub annotations: Vec<Annotation>,
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
    pub annotations: Vec<Annotation>,
}

#[derive(Debug, PartialEq, Clone)]
pub struct ConstructorDefinition {
    pub params: Vec<Parameter>,
    pub body: Block,
    pub annotations: Vec<Annotation>,
}

#[derive(Debug, PartialEq, Clone)]
pub struct FunctionDefinition {
    pub name: String,
    pub params: Vec<Parameter>,
    pub returns: Option<Type>,
    pub body: Block,
    pub is_public: bool,
    pub annotations: Vec<Annotation>,
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
    pub annotations: Vec<Annotation>,
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
    VariableDeclaration(String, Type, Option<Expression>),
    Assignment(String, Expression),
    Return(Option<Expression>),
    Require(Expression, String),
    Revert(String),
    If(Expression, Block, Option<Block>),
    For(String, Expression, Expression, Block),
    Emit(String, Vec<Expression>),
    RequirePqc(Block, Option<Box<Statement>>), // require_pqc block with optional fallback (revert/return)
}

#[derive(Debug, PartialEq, Clone)]
pub enum Expression {
    Call(String, Vec<Expression>),
    MemberAccess(Box<Expression>, String),
    IndexAccess(Box<Expression>, Box<Expression>),
    Literal(Literal),
    Identifier(String),
    Binary(BinaryOp, Box<Expression>, Box<Expression>),
    Unary(UnaryOp, Box<Expression>),
    Ternary(Box<Expression>, Box<Expression>, Box<Expression>),
}

#[derive(Debug, PartialEq, Clone)]
pub enum BinaryOp {
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    And,
    Or,
    Shl,
    Shr,
}

#[derive(Debug, PartialEq, Clone)]
pub enum UnaryOp {
    Not,
    Neg,
    Inc,
    Dec,
}

#[derive(Debug, PartialEq, Clone)]
pub enum Type {
    Address,
    UInt256,
    UInt8,
    UInt32,
    UInt64,
    UInt128,
    Int256,
    Int8,
    Int32,
    Int64,
    Int128,
    Bool,
    Bytes,
    String,
    Array(Box<Type>, Option<u32>),
    Mapping(Box<Type>, Box<Type>),
    Struct(String),
    MLDSAPublicKey,
    MLDSAKeyPair,
    MLDSASignature,
    FNDSAPublicKey,
    FNDSAKeyPair,
    FNDSASignature,
    MLKEMPublicKey,
    MLKEMKeyPair,
    MLKEMCiphertext,
    SLHDSAPublicKey,
    SLHDSAKeyPair,
    SLHDSASignature,
    Generic(String, Vec<Type>),
}

#[derive(Debug, PartialEq, Clone)]
pub enum Literal {
    String(String),
    Number(u64),
    Bool(bool),
    Address(String),
    Bytes(Vec<u8>),
}

// Semantic analysis types
#[derive(Debug, PartialEq, Clone)]
pub struct Symbol {
    pub name: String,
    pub ty: Type,
    pub scope: Scope,
    pub is_mutable: bool,
}

#[derive(Debug, PartialEq, Clone)]
pub enum Scope {
    Global,
    Contract(String),
    Function(String),
    Block,
}

#[derive(Debug, PartialEq, Clone)]
pub struct SemanticError {
    pub message: String,
    pub line: Option<usize>,
    pub column: Option<usize>,
}

#[derive(Debug, PartialEq, Clone)]
pub struct SemanticContext {
    pub symbols: HashMap<String, Symbol>,
    pub current_contract: Option<String>,
    pub current_function: Option<String>,
    pub errors: Vec<SemanticError>,
}
