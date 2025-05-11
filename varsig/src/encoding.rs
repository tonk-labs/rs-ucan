use ipld_core::ipld::Ipld;
use thiserror::Error;

use crate::codec::Codec;
use std::io::{BufRead, Write};

#[repr(u64)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Encoding {
    #[cfg(feature = "raw")]
    Raw = 0x5f,

    #[cfg(feature = "dag_pb")]
    DagPb = 0x70,

    #[cfg(feature = "dag_cbor")]
    DagCbor = 0x71,

    #[cfg(feature = "dag_json")]
    DagJson = 0x0129,

    #[cfg(feature = "jwt")]
    Jwt = 0x6a77,

    #[cfg(feature = "eip191")]
    Eip191 = 0xe191,
}

impl Codec<Ipld> for Encoding {
    type EncodingError = EncodingError;
    type DecodingError = DecodingError;

    fn multicodec_code(&self) -> u64 {
        (*self as u32) as u64
    }

    /// Encode the payload to the given buffer.
    fn encode_payload<W: Write>(
        &self,
        payload: &Ipld,
        buffer: &mut W,
    ) -> Result<(), Self::EncodingError> {
        match self {
            #[cfg(feature = "raw")]
            Encoding::Raw => todo!(),

            #[cfg(feature = "dag_pb")]
            Encoding::DagPb => Ok(serde_ipld_dagpb::to_writer(buffer, payload)?),

            #[cfg(feature = "dag_cbor")]
            Encoding::DagCbor => Ok(serde_ipld_dagcbor::to_writer(buffer, payload)?),

            #[cfg(feature = "dag_json")]
            Encoding::DagJson => Ok(serde_ipld_dagjson::to_writer(buffer, payload)?),

            #[cfg(feature = "jwt")]
            Encoding::Jwt => todo!(),

            #[cfg(feature = "eip191")]
            Encoding::Eip191 => todo!(),
        };

        todo!()
    }

    fn decode_payload<R: BufRead>(self, reader: R) -> Result<Ipld, Self::DecodingError> {
        match self {
            #[cfg(feature = "raw")]
            Encoding::Raw => todo!(),

            #[cfg(feature = "dag_pb")]
            Encoding::DagPb => payload.encode(ipld_serde_),

            #[cfg(feature = "dag_cbor")]
            Encoding::DagCbor => Ok(serde_ipld_dagcbor::from_reader(reader)?),

            #[cfg(feature = "dag_json")]
            Encoding::DagJson => todo!(),

            #[cfg(feature = "jwt")]
            Encoding::Jwt => todo!(),

            #[cfg(feature = "eip191")]
            Encoding::Eip191 => todo!(),
        };

        todo!()
    }
}

#[derive(Debug, Error)]
pub enum EncodingError {
    #[cfg(feature = "dag_pb")]
    #[error("Encoding error: {0}")]
    PbError(#[from] serde_ipld_dagpb::error::Error),

    #[cfg(feature = "dag_cbor")]
    #[error("Decoding error: {0}")]
    CborError(#[from] serde_ipld_dagcbor::EncodeError<std::io::Error>),

    #[cfg(feature = "dag_json")]
    #[error("Decoding error: {0}")]
    JsonError(#[from] serde_ipld_dagjson::error::EncodeError),
}

#[derive(Debug, Error)]
pub enum DecodingError {
    #[cfg(feature = "dag_pb")]
    #[error("Encoding error: {0}")]
    PbError(#[from] serde_ipld_dagpb::error::Error),

    #[cfg(feature = "dag_cbor")]
    #[error("Decoding error: {0}")]
    CborError(#[from] serde_ipld_dagcbor::DecodeError<std::io::Error>),

    #[cfg(feature = "dag_json")]
    #[error("Decoding error: {0}")]
    JsonError(#[from] serde_ipld_dagjson::error::DecodeError),
}
