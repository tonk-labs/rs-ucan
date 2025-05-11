//! IPLD Codec trait.

use std::{
    error::Error,
    io::{BufRead, Write},
};

/// IPLD Codec trait.
///
/// This trait is a generalization of the `libipld_core::codec::Codec` trait.
/// Specifically this allows an application to accept multiple codecs
/// and distinguish with a runtime enum. This is important for Varsig,
/// since it may need to encode to the configured codec for signature verification.
///
/// An implementation is provided for types that have `ipld_core::codec::Codec`.
pub trait Codec<T> {
    /// Encoding error type.
    type EncodingError: Error;

    /// Decoding error type.
    type DecodingError: Error;

    /// Multicodec code.
    ///
    /// This is not a `const` because an implementation may
    /// support more than one IPLD codec, so it is runtime dependent.
    fn multicodec_code(&self) -> u64;

    /// Encode the payload to the given buffer.
    fn encode_payload<W: Write>(
        &self,
        payload: &T,
        buffer: &mut W,
    ) -> Result<(), Self::EncodingError>;

    /// Decode the payload from the given reader.
    fn decode_payload<R: BufRead>(reader: R) -> Result<T, Self::DecodingError>;
}

impl<T, C: ipld_core::codec::Codec<T>> Codec<T> for C
where
    C::Error: Error,
{
    type EncodingError = C::Error;
    type DecodingError = C::Error;

    fn multicodec_code(&self) -> u64 {
        C::CODE
    }

    fn encode_payload<W: Write>(
        &self,
        payload: &T,
        buffer: &mut W,
    ) -> Result<(), Self::EncodingError> {
        C::encode(buffer, payload)
    }

    fn decode_payload<R: BufRead>(reader: R) -> Result<T, Self::DecodingError> {
        C::decode(reader)
    }
}
