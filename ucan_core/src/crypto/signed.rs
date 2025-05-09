//! Signed payload wrapper.

/// Signed payload wrapper.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Signed<T, S> {
    varsig_header: (),
    payload: T,
    signature: S,
}
