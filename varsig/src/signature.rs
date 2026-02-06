//! Varsig signature — header type, signing/verification traits, and error types.

pub mod error;
pub mod signer;
pub mod verifier;

use crate::{algorithm::SignatureAlgorithm, codec::Codec};
pub use error::{SignError, VerificationError};
use serde::{Deserialize, Serialize};
pub use signer::Signer;
use std::marker::PhantomData;
pub use verifier::Verifier;

#[cfg(feature = "dag_cbor")]
use serde_ipld_dagcbor::codec::DagCborCodec;

#[cfg(feature = "dag_json")]
use serde_ipld_dagjson::codec::DagJsonCodec;

/// Top-level Varsig header type.
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Ord, Eq, Hash)]
pub struct Varsig<V: SignatureAlgorithm, C: Codec<T>, T> {
    algorithm: V,
    codec: C,
    _data: PhantomData<T>,
}

impl<V: SignatureAlgorithm, C: Codec<T>, T> Varsig<V, C, T> {
    /// Create a new Varsig header.
    ///
    /// The signature algorithm is constructed via `Default`.
    ///
    /// ## Parameters
    ///
    /// - `codec`: The codec to use for encoding the payload.
    pub fn new(codec: C) -> Self {
        Varsig {
            algorithm: V::default(),
            codec,
            _data: PhantomData,
        }
    }

    /// Get the signature algorithm for this Varsig header.
    pub const fn algorithm(&self) -> &V {
        &self.algorithm
    }

    /// Get the codec for this Varsig header.
    pub const fn codec(&self) -> &C {
        &self.codec
    }

    /// Sign a payload with the provided signer.
    ///
    /// The signer's `Signature` type must match this header's `Signature` type.
    ///
    /// # Errors
    ///
    /// Returns a `VerificationError` if encoding fails, or `signature::Error` if signing fails.
    pub async fn sign<S: Signer<Signature = V::Signature>>(
        &self,
        signer: &S,
        payload: &T,
    ) -> Result<(V::Signature, Vec<u8>), SignError<C::EncodingError>>
    where
        C: Codec<T>,
        T: Serialize,
    {
        let mut buffer = Vec::new();
        self.codec
            .encode_payload(payload, &mut buffer)
            .map_err(SignError::EncodingError)?;
        let sig = signer
            .sign(&buffer)
            .await
            .map_err(SignError::SigningError)?;
        Ok((sig, buffer))
    }

    /// Verify a signature with the provided verifier.
    ///
    /// The verifier's `Signature` type must match this header's `Signature` type.
    ///
    /// # Errors
    ///
    /// Returns a `VerificationError` if encoding or verification fails.
    pub async fn verify<Ver: Verifier<Signature = V::Signature>>(
        &self,
        verifier: &Ver,
        payload: &T,
        signature: &V::Signature,
    ) -> Result<(), VerificationError<C::EncodingError>> {
        let mut buffer = Vec::new();
        self.codec
            .encode_payload(payload, &mut buffer)
            .map_err(VerificationError::EncodingError)?;
        verifier
            .verify(&buffer, signature)
            .await
            .map_err(VerificationError::VerificationError)
    }
}

#[cfg(feature = "dag_cbor")]
impl<V: SignatureAlgorithm + Default, T> Default for Varsig<V, DagCborCodec, T>
where
    DagCborCodec: Codec<T>,
{
    fn default() -> Self {
        Varsig {
            algorithm: V::default(),
            codec: DagCborCodec,
            _data: PhantomData,
        }
    }
}

#[cfg(feature = "dag_json")]
impl<V: SignatureAlgorithm + Default, T> Default for Varsig<V, DagJsonCodec, T>
where
    DagJsonCodec: Codec<T>,
{
    fn default() -> Self {
        Varsig {
            algorithm: V::default(),
            codec: DagJsonCodec,
            _data: PhantomData,
        }
    }
}

impl<V: SignatureAlgorithm, C: Codec<T>, T> Serialize for Varsig<V, C, T> {
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

        // Signature algorithm tag
        leb128::write::unsigned(&mut bytes, self.algorithm.prefix()).map_err(|e| {
            serde::ser::Error::custom(format!(
                "unable to write signature algorithm prefix tag: {e}"
            ))
        })?;

        for segment in &self.algorithm.config_tags() {
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

impl<'de, V: SignatureAlgorithm, C: Codec<T>, T> Deserialize<'de> for Varsig<V, C, T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes: serde_bytes::ByteBuf =
            serde::Deserialize::deserialize(deserializer).map_err(|e| {
                serde::de::Error::custom(format!("unable to deserialize varsig header: {e}"))
            })?;

        let mut cursor = std::io::Cursor::new(bytes.as_slice());
        let len = bytes.len() as u64;

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
            let seg = leb128::read::unsigned(&mut cursor).map_err(|e| {
                serde::de::Error::custom(format!("unable to read leb128 unsigned segment: {e}"))
            })?;
            remaining.push(seg);
        }

        let (algorithm, more) = V::try_from_tags(remaining.as_slice()).ok_or_else(|| {
            serde::de::Error::custom("unable to create signature algorithm from tags")
        })?;
        let codec = C::try_from_tags(more)
            .ok_or_else(|| serde::de::Error::custom("unable to create codec from tags"))?;

        Ok(Varsig {
            algorithm,
            codec,
            _data: std::marker::PhantomData,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::algorithm::eddsa::Ed25519;

    use serde_ipld_dagcbor::codec::DagCborCodec;
    use testresult::TestResult;

    #[test]
    fn test_ed25519_varsig_header_round_trip() -> TestResult {
        let fixture: Varsig<Ed25519, DagCborCodec, String> = Varsig::new(DagCborCodec);
        let dag_cbor = serde_ipld_dagcbor::to_vec(&fixture)?;
        let round_tripped: Varsig<Ed25519, DagCborCodec, String> =
            serde_ipld_dagcbor::from_slice(&dag_cbor)?;
        assert_eq!(fixture, round_tripped);
        Ok(())
    }

    #[test]
    fn test_ed25519_varsig_header_fixture() -> TestResult {
        let dag_cbor = [0x48, 0x34, 0x01, 0xed, 0x01, 0xed, 0x01, 0x13, 0x71];
        let varsig: Varsig<Ed25519, DagCborCodec, String> =
            serde_ipld_dagcbor::from_slice(&dag_cbor)?;
        assert_eq!(varsig, Varsig::<Ed25519, _, String>::new(DagCborCodec));
        Ok(())
    }

    #[test]
    fn test_algorithm_reader() -> TestResult {
        let varsig: Varsig<Ed25519, DagCborCodec, String> = Varsig::new(DagCborCodec);
        assert_eq!(varsig.algorithm(), &Ed25519::default());
        Ok(())
    }

    #[test]
    fn test_codec_reader() -> TestResult {
        let varsig: Varsig<Ed25519, DagCborCodec, String> = Varsig::new(DagCborCodec);
        assert_eq!(varsig.codec(), &DagCborCodec);
        Ok(())
    }

    #[tokio::test]
    async fn test_sign_and_verify() -> TestResult {
        use super::signer::Signer;
        use super::verifier::Verifier;
        use crate::algorithm::eddsa::Ed25519Signature;

        // Lightweight wrappers that impl Signer/Verifier for tests.
        struct TestSigner(ed25519_dalek::SigningKey);
        struct TestVerifier(ed25519_dalek::VerifyingKey);

        impl Signer for TestSigner {
            type Signature = Ed25519Signature;
            async fn sign(&self, msg: &[u8]) -> Result<Ed25519Signature, signature::Error> {
                use signature::Signer as _;
                let sig = self.0.try_sign(msg)?;
                Ok(Ed25519Signature::from(sig))
            }
        }

        impl Verifier for TestVerifier {
            type Signature = Ed25519Signature;
            async fn verify(
                &self,
                msg: &[u8],
                signature: &Ed25519Signature,
            ) -> Result<(), signature::Error> {
                use signature::Verifier as _;
                let dalek_sig = ed25519_dalek::Signature::from(*signature);
                self.0.verify(msg, &dalek_sig)
            }
        }

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
        let dalek_sk = ed25519_dalek::SigningKey::generate(&mut csprng);
        let sk = TestSigner(dalek_sk.clone());
        let vk = TestVerifier(dalek_sk.verifying_key());
        let varsig: Varsig<Ed25519, DagCborCodec, TestPayload> = Varsig::new(DagCborCodec);

        let (sig, _encoded) = varsig.sign(&sk, &payload).await?;
        varsig.verify(&vk, &payload, &sig).await?;

        Ok(())
    }
}
