//! Varsig header

use crate::{
    codec::Codec,
    signer::{AsyncSign, Sign, SignerError},
    verify::Verify,
};
use serde::{Deserialize, Serialize};
use std::{io::Cursor, marker::PhantomData};

/// Top-level Varsig header type.
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Ord, Eq, Hash)]
pub struct Varsig<V: Verify, C: Codec<T>, T> {
    verifier_cfg: V,
    codec: C,
    _data: PhantomData<T>,
}

impl<V: Verify, C: Codec<T>, T> Varsig<V, C, T> {
    /// Create a new Varsig header.
    ///
    /// ## Parameters
    ///
    /// - `verifier`: The verifier to use for the Varsig header.
    /// - `codec`: The codec to use for encoding the payload.
    pub fn new(verifier_cfg: V, codec: C) -> Self {
        Varsig {
            verifier_cfg,
            codec,
            _data: PhantomData,
        }
    }

    /// Get the verifier for this Varsig header.
    pub fn verifier_cfg(&self) -> &V {
        &self.verifier_cfg
    }

    /// Get the codec for this Varsig header.
    pub fn codec(&self) -> &C {
        &self.codec
    }

    /// Try to synchronously sign a payload with the provided signing key.
    pub fn try_sign(
        &self,
        sk: &V::Signer,
        payload: &T,
    ) -> Result<(V::Signature, Vec<u8>), SignerError<C::EncodingError, V::SignError>>
    where
        V: Sign,
        C: Codec<T>,
        T: Serialize,
    {
        Ok(self.verifier_cfg.try_sign(&self.codec, &sk, payload)?)
    }

    /// Try to asynchronously sign a payload with the provided signing key.
    pub async fn try_sign_async(
        &self,
        sk: &V::AsyncSigner,
        payload: &T,
    ) -> Result<(V::Signature, Vec<u8>), SignerError<C::EncodingError, V::AsyncSignError>>
    where
        V: AsyncSign,
        C: Codec<T>,
        T: Serialize,
    {
        Ok(self
            .verifier_cfg
            .try_sign_async(&self.codec, &sk, payload)
            .await?)
    }

    /// Try to verify a signature for some payload.
    pub fn try_verify(
        &self,
        verifier: &V::Verifier,
        payload: &T,
        signature: &V::Signature,
    ) -> Result<(), crate::verify::VerificationError<C::EncodingError>> {
        self.verifier_cfg()
            .try_verify(&self.codec, verifier, signature, payload)
    }
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
        leb128::write::unsigned(&mut bytes, self.verifier_cfg.prefix()).map_err(|e| {
            serde::ser::Error::custom(format!(
                "unable to write verifier prefix tag into owned vec: {e}"
            ))
        })?;

        for segment in &self.verifier_cfg.config_tags() {
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

        let (verifier_cfg, more) = V::try_from_tags(remaining.as_slice())
            .ok_or_else(|| serde::de::Error::custom("unable to create verifier from tags"))?;

        let codec = C::try_from_tags(more)
            .ok_or_else(|| serde::de::Error::custom("unable to create codec from tags"))?;

        Ok(Varsig {
            verifier_cfg,
            codec,
            _data: PhantomData,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signature::Ed25519;

    use serde_ipld_dagcbor::codec::DagCborCodec;
    use testresult::TestResult;

    #[test]
    fn test_ed25519_varsig_header_round_trip() -> TestResult {
        let input = [0x34, 0x01, 0xed, 0x01, 0xed, 0x01, 0x13, 0x71];
        let dag_json = serde_ipld_dagcbor::to_vec(&input)?;
        let varsig: Varsig<Ed25519, DagCborCodec, String> =
            serde_ipld_dagcbor::from_slice(&dag_json)?;
        assert_eq!(varsig, Varsig::new(Ed25519, DagCborCodec));
        Ok(())
    }

    #[test]
    fn test_verifier_reader() -> TestResult {
        let varsig: Varsig<Ed25519, DagCborCodec, String> = Varsig::new(Ed25519, DagCborCodec);
        assert_eq!(varsig.verifier_cfg(), &Ed25519);
        Ok(())
    }

    #[test]
    fn test_codec_reader() -> TestResult {
        let varsig: Varsig<Ed25519, DagCborCodec, String> = Varsig::new(Ed25519, DagCborCodec);
        assert_eq!(varsig.codec(), &DagCborCodec);
        Ok(())
    }

    #[test]
    fn test_try_verify() -> TestResult {
        #[derive(Debug, PartialEq, Serialize, Deserialize)]
        struct TestPayload {
            message: String,
            count: u8,
        }

        let payload = TestPayload {
            message: "Hello, Varsig!".to_string(),
            count: 42,
        };

        let mut csprng = rand::thread_rng();
        let sk = ed25519_dalek::SigningKey::generate(&mut csprng);
        let varsig: Varsig<Ed25519, DagCborCodec, TestPayload> = Varsig::new(Ed25519, DagCborCodec);

        let (sig, _encoded) = varsig.try_sign(&sk, &payload)?;
        varsig.try_verify(&sk.verifying_key(), &payload, &sig)?;

        Ok(())
    }
}
