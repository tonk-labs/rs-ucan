//! Varsig header

use crate::{codec::Codec, verify::Verify};
use serde::{Deserialize, Serialize};
use std::{io::Cursor, marker::PhantomData};

/// Top-level Varsig header type.
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Ord, Eq, Hash)]
pub struct Varsig<V: Verify, C: Codec<T>, T> {
    verifier: V,
    codec: C,
    _data: PhantomData<T>,
}

impl<V: Verify, C: Codec<T>, T> Serialize for Varsig<V, C, T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut bytes = Vec::new();

        // Varsig tag
        leb128::write::unsigned(&mut bytes, 0x34).map_err(|e| {
            serde::ser::Error::custom(format!(
                "unable to varsig prefix tag write into new owned vec: {e}"
            ))
        })?;

        // Version tag
        leb128::write::unsigned(&mut bytes, 0x01).map_err(|e| {
            serde::ser::Error::custom(format!(
                "unable to write varsig version tag into owned vec with one element: {e}"
            ))
        })?;

        // Signature tag
        leb128::write::unsigned(&mut bytes, self.verifier.prefix()).map_err(|e| {
            serde::ser::Error::custom(format!(
                "unable to write verifier prefix tag into owned vec: {e}"
            ))
        })?;

        for segment in &self.verifier.config_tags() {
            leb128::write::unsigned(&mut bytes, *segment).map_err(|e| {
                serde::ser::Error::custom(format!(
                    "unable to write varsig config segment into owned vec {segment}: {e}",
                ))
            })?;
        }

        // Codec tag
        leb128::write::unsigned(&mut bytes, self.codec.multicodec_code()).map_err(|e| {
            serde::ser::Error::custom(format!(
                "unable to write varsig version tag into owned vec with one element: {e}"
            ))
        })?;

        serializer.serialize_bytes(&bytes)
    }
}

impl<'de, V: Verify, C: Codec<T>, T> Deserialize<'de> for Varsig<V, C, T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes = Vec::<u8>::deserialize(deserializer).map_err(|e| {
            serde::de::Error::custom(format!("unable to deserialize varsig header: {e}"))
        })?;

        let len = bytes.len() as u64;
        let mut cursor = Cursor::new(bytes);

        let varsig_tag = leb128::read::unsigned(&mut cursor).map_err(|e| {
            serde::de::Error::custom(format!("unable to read leb128 unsigned: {e}"))
        })?;

        if varsig_tag != 0x34 {
            return Err(serde::de::Error::custom(format!(
                "expected varsig tag 0x34, found {varsig_tag:#x}"
            )));
        }

        let version_tag = leb128::read::unsigned(&mut cursor).map_err(|e| {
            serde::de::Error::custom(format!("unable to read leb128 unsigned: {e}"))
        })?;

        if version_tag != 0x01 {
            return Err(serde::de::Error::custom(format!(
                "expected varsig version tag 0x01, found {version_tag:#x}"
            )));
        }

        let mut remaining = Vec::new();

        while cursor.position() < len {
            match leb128::read::unsigned(&mut cursor) {
                Ok(segment) => remaining.push(segment),
                Err(e) => {
                    return Err(serde::de::Error::custom(format!(
                        "unable to read leb128 unsigned segment: {e}"
                    )));
                }
            }
        }

        let (verifier, more) = V::try_from_tags(remaining.as_slice()).expect("FIXME");
        let codec = C::try_from_tags(more).expect("FIXME");

        Ok(Varsig {
            verifier,
            codec,
            _data: PhantomData,
        })
    }
}
