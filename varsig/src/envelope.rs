use crate::{header::traits::Header, signer::Header};
use serde::{Deserialize, Serialize};
use signature::SignatureEncoding;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope<V: Header<T, Signature = S>, T, S: SignatureEncoding>(
    pub EnvelopePayload<V, T>,
    pub S,
);

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvelopePayload<V: Header<T>, T> {
    #[serde(rename = "h")]
    pub header: V,

    #[serde(flatten)]
    pub payload: T,
}
