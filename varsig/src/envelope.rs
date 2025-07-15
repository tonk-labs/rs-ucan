//! Top-level Varsig envelope.

use crate::{codec::Codec, header::Varsig, verify::Verify};
use serde::{Deserialize, Serialize};
use signature::SignatureEncoding;

// FIXME move to own library and/or UCAN
/// Top-level Varsig envelope type.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)] // NOTE: important!
pub struct Envelope<V: Verify<Signature = S>, C: Codec<T>, T, S: SignatureEncoding>(
    /// Envelope signature.
    pub S,
    /// Varsig envelope
    pub EnvelopePayload<V, C, T>,
);

// FIXME move to own library and/or UCAN
/// Inner Varsig envelope payload type.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)] // NOTE: important!
pub struct EnvelopePayload<V: Verify, C: Codec<T>, T> {
    /// Varsig header.
    #[serde(rename = "h")]
    pub header: Varsig<V, C, T>,

    /// Payload data.
    #[serde(flatten)]
    pub payload: T,
}
