//! Codec trait for encoding/decoding varsig payloads.

use std::{
    error::Error,
    io::{BufRead, Write},
};

/// Codec trait for encoding and decoding payloads.
///
/// This trait is a generalization of IPLD codec traits.
/// Specifically this allows an application to accept multiple codecs
/// and distinguish with a runtime enum. This is important for Varsig,
/// since it may need to encode to the configured codec for signature verification.
pub trait Codec<T>: Sized {
    /// Encoding error type.
    type EncodingError: Error;

    /// Decoding error type.
    type DecodingError: Error;

    /// Multicodec code.
    ///
    /// This is not a `const` because an implementation may
    /// support more than one codec, so it is runtime dependent.
    fn multicodec_code(&self) -> u64;

    /// Try to create a codec from a series of tags.
    fn try_from_tags(code: &[u64]) -> Option<Self>;

    /// Encode the payload to the given buffer.
    ///
    /// ## Parameters
    ///
    /// - `payload`: The payload to encode.
    /// - `buffer`: The buffer to write the encoded payload to.
    ///
    /// ## Returns
    ///
    /// Returns `Ok(())` on success, or an error of type `Self::EncodingError` on failure.
    ///
    /// ## Errors
    ///
    /// If the encoding fails, it returns an error of type `Self::EncodingError`.
    fn encode_payload<W: Write>(
        &self,
        payload: &T,
        buffer: &mut W,
    ) -> Result<(), Self::EncodingError>;

    /// Decode the payload from the given reader.
    ///
    /// ## Parameters
    ///
    /// - `reader`: The reader to read the encoded payload from.
    ///
    /// ## Returns
    ///
    /// Returns the decoded payload of type `T` on success,
    /// or an error of type `Self::DecodingError` on failure.
    ///
    /// ## Errors
    ///
    /// If the decoding fails, it returns an error of type `Self::DecodingError`.
    fn decode_payload<R: BufRead>(&self, reader: &mut R) -> Result<T, Self::DecodingError>;
}
