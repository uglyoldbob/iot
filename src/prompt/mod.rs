//! A module for prompting a user to fill out a struct

pub trait Error: Sized + std::error::Error {}

pub trait PromptVisitor {
    type Value;
    fn visit_u8<E>(self, name: &str, v: u8) -> Result<Self::Value, E>;
}

pub trait Prompter {
    type Error;
    fn prompt_u8<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: PromptVisitor;
}

pub trait Prompting: Sized {
    fn prompt<T>(prompter: T) -> Result<Self, T::Error>
    where
        T: Prompter;
}
