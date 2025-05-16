use std::marker::PhantomData;

use serde::{Deserialize, Serialize};
use serde_ipld_dagcbor::codec::DagCborCodec;
use signature::SignatureEncoding;

use crate::{
    codec::Codec,
    curve::Secp256k1,
    hash::Sha2_256,
    header::{traits::Verify, EcDsa},
};

pub struct Varsig<V: Verify, C: Codec<T>, T> {
    codec: C,
    verifier: V,
    _data: PhantomData<T>,
}

pub trait Foo {
    fn prefix(&self) -> u32;
    fn config(&self) -> Vec<u8>;
}

impl<V: Verify, C: Codec<T>, T> Serialize for Varsig<V, C, T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut bytes = vec![0x34, 0x01];

        let prefix = self.verifier.prefix();
        let prefix_varint = prefix.expect("FIXME");
        bytes.append(prefix_varint);

        bytes.append(self.verifier.to_bytes()); // FIXME varints
        bytes.serialize(serializer)
    }
}

pub type Es256DagCbor<T> = Varsig<EcDsa<Secp256k1, Sha2_256>, DagCborCodec, T>;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope<V: Verify<Signature = S>, C: Codec<T>, T, S: SignatureEncoding>(
    pub EnvelopePayload<V, C, T>,
    pub S,
);

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvelopePayload<V: Verify, C: Codec<T>, T> {
    #[serde(rename = "h")]
    pub header: Varsig<V, C, T>,

    #[serde(flatten)]
    pub payload: T,
}
