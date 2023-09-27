use crate::did::Did;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Hash)]
pub enum DelegatedSubject<D: Did> {
    Specific(D),
    Any,
}
