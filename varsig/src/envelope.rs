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

#[derive(Debug, Clone, PartialEq, PartialOrd, Ord, Eq, Hash)]
pub struct Varsig<V: Verify, C: Codec<T>, T> {
    codec: C,
    verifier: V,
    _data: PhantomData<T>,
}

pub struct Leb128(Vec<u8>);

impl<V: Verify, C: Codec<T>, T> Serialize for Varsig<V, C, T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut bytes = vec![0x34, 0x01];
        leb128::write::unsigned(&mut bytes, self.verifier.prefix());
        for segment in self.verifier.config_tags().iter() {
            leb128::write::unsigned(&mut bytes, *segment);
        }
        serializer.serialize_bytes(&bytes)
    }
}

impl<'de, V: Verify, C: Codec<T>, T> Deserialize<'de> for Varsig<V, C, T> {
    fn deserialize<D>(_deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        todo!()
        // let bytes = Vec::<u8>::deserialize(deserializer)?;
        // let mut cursor = std::io::Cursor::new(bytes);
        // let prefix = leb128::read::unsigned(&mut cursor).map_err(serde::de::Error::custom)?;
        // let mut tags = Vec::new();
        // while let Ok(tag) = leb128::read::unsigned(&mut cursor) {
        //     tags.push(tag);
        // }
        // Ok(Varsig {
        //     codec: DagCborCodec,
        //     verifier: V::from_prefix_and_tags(prefix, tags),
        //     _data: PhantomData,
        // })
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
