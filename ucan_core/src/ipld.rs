//! Internal IPLD representation.
//!
//! This is here becuase `ipld-core` doesn't implement various traits.
//! It is not a simple newtype wrapper because IPLD has recursive values,
//! and this implementation is simpler. If it is a performance bottleneck,
//! please let the maintainers know.

use ipld_core::{cid::Cid, ipld::Ipld};
use std::collections::BTreeMap;

use crate::delegation::policy::selector::{error::SelectorErrorReason, selectable::Selectable};

#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(any(test, feature = "arb"), derive(arbitrary::Arbitrary))]
pub enum InternalIpld {
    /// Represents the absence of a value or the value undefined.
    Null,
    /// Represents a boolean value.
    Bool(bool),
    /// Represents an integer.
    Integer(i128),
    /// Represents a floating point value.
    Float(f64),
    /// Represents an UTF-8 string.
    String(String),
    /// Represents a sequence of bytes.
    Bytes(Vec<u8>),
    /// Represents a list.
    List(Vec<InternalIpld>),
    /// Represents a map of strings.
    Map(BTreeMap<String, InternalIpld>),
    /// Represents a map of integers.
    Link(Cid),
}

impl From<InternalIpld> for Ipld {
    fn from(value: InternalIpld) -> Self {
        match value {
            InternalIpld::Null => Ipld::Null,
            InternalIpld::Bool(b) => Ipld::Bool(b),
            InternalIpld::Integer(i) => Ipld::Integer(i),
            InternalIpld::Float(f) => Ipld::Float(f),
            InternalIpld::String(s) => Ipld::String(s),
            InternalIpld::Bytes(b) => Ipld::Bytes(b),
            InternalIpld::List(l) => Ipld::List(l.into_iter().map(Into::into).collect()),
            InternalIpld::Map(m) => {
                let map = m.into_iter().map(|(k, v)| (k, v.into())).collect();
                Ipld::Map(map)
            }
            InternalIpld::Link(cid) => Ipld::Link(cid),
        }
    }
}

impl From<Ipld> for InternalIpld {
    fn from(ipld: Ipld) -> Self {
        match ipld {
            Ipld::Null => InternalIpld::Null,
            Ipld::Bool(b) => InternalIpld::Bool(b),
            Ipld::Integer(i) => InternalIpld::Integer(i),
            Ipld::Float(f) => InternalIpld::Float(f),
            Ipld::String(s) => InternalIpld::String(s),
            Ipld::Bytes(b) => InternalIpld::Bytes(b),
            Ipld::List(l) => {
                let list = l.into_iter().map(Into::into).collect();
                InternalIpld::List(list)
            }
            Ipld::Map(m) => {
                let map = m.into_iter().map(|(k, v)| (k, v.into())).collect();
                InternalIpld::Map(map)
            }
            Ipld::Link(cid) => InternalIpld::Link(cid),
        }
    }
}

impl Selectable for InternalIpld {
    fn try_select(ipld: Ipld) -> Result<Self, SelectorErrorReason> {
        Ok(InternalIpld::from(ipld))
    }
}
