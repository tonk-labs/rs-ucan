//! Preset IPLD encoding types.

use ipld_core::ipld::Ipld;
use thiserror::Error;

use crate::codec::Codec;
use std::io::{BufRead, Write};

/// IPLD encoding types.
#[repr(u64)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Encoding {
    /// Identity encoding (raw bytes).
    #[cfg(feature = "identity")]
    Identity = 0x5f,

    /// `DAG-PB` encoding.
    #[cfg(feature = "dag_pb")]
    DagPb = 0x70,

    /// `DAG-CBOR` encoding.
    #[cfg(feature = "dag_cbor")]
    DagCbor = 0x71,

    /// `DAG-JSON` encoding.
    #[cfg(feature = "dag_json")]
    DagJson = 0x0129,

    /// Canonicalized JWT encoding.
    #[cfg(feature = "jwt")]
    Jwt = 0x6a77,

    /// EIP-191 encoding.
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
            #[cfg(feature = "identity")]
            Encoding::Identity => {
                match payload {
                    Ipld::Bytes(bytes) => {
                        buffer
                            .write(bytes.as_slice())
                            .map_err(|e| EncodingError::IdentityError(e))?;
                    }
                    _ => {
                        return Err(EncodingError::IdentityError(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "Invalid payload",
                        )))
                    }
                };

                Ok(())
            }

            #[cfg(feature = "dag_pb")]
            Encoding::DagPb => {
                let bytes = ipld_dagpb::from_ipld(payload)?;
                buffer.write(bytes.as_slice())?;
                Ok(())
            }

            #[cfg(feature = "dag_cbor")]
            Encoding::DagCbor => Ok(serde_ipld_dagcbor::to_writer(buffer, payload)?),

            #[cfg(feature = "dag_json")]
            Encoding::DagJson => Ok(serde_ipld_dagjson::to_writer(buffer, payload)?),

            #[cfg(feature = "jwt")]
            Encoding::Jwt => todo!(),

            #[cfg(feature = "eip191")]
            Encoding::Eip191 => todo!(),
        }
    }

    fn decode_payload<R: BufRead>(&self, reader: &mut R) -> Result<Ipld, Self::DecodingError> {
        match self {
            #[cfg(feature = "identity")]
            Encoding::Identity => {
                let mut bytes = Vec::new();
                reader
                    .read_to_end(&mut bytes)
                    .map_err(|e| DecodingError::IdentityError(e))?;
                Ok(Ipld::Bytes(bytes))
            }

            #[cfg(feature = "dag_pb")]
            Encoding::DagPb => {
                let mut vec = Vec::new();
                reader
                    .read_to_end(&mut vec)
                    .map_err(|e| DecodingError::PbError(ipld_dagpb::Error::from(e)))?;
                let bytes = bytes::Bytes::from_owner(vec);
                Ok(ipld_dagpb::PbNode::from_bytes(bytes)?.into())
            }

            #[cfg(feature = "dag_cbor")]
            Encoding::DagCbor => {
                Ok::<Ipld, Self::DecodingError>(serde_ipld_dagcbor::from_reader(reader)?)
            }

            #[cfg(feature = "dag_json")]
            Encoding::DagJson => Ok(serde_ipld_dagjson::from_reader(reader)?),

            #[cfg(feature = "jwt")]
            Encoding::Jwt => todo!(),

            #[cfg(feature = "eip191")]
            Encoding::Eip191 => todo!(),
        }
    }
}

/// Encoding errors for the enabled encoding types.
#[derive(Debug, Error)]
pub enum EncodingError {
    #[cfg(feature = "identity")]
    #[error("Identity encoding error: {0}")]
    IdentityError(#[from] std::io::Error),

    /// Encoding error from `DAG-PB`.
    #[cfg(feature = "dag_pb")]
    #[error(transparent)]
    PbError(#[from] ipld_dagpb::Error),

    /// Encoding error from `DAG-CBOR`.
    #[cfg(feature = "dag_cbor")]
    #[error(transparent)]
    CborError(#[from] serde_ipld_dagcbor::EncodeError<std::io::Error>),

    /// Encoding error from `DAG-JSON`.
    #[cfg(feature = "dag_json")]
    #[error(transparent)]
    JsonError(#[from] serde_ipld_dagjson::error::EncodeError),
}

/// Decoding errors for the enabled encoding types.
#[derive(Debug, Error)]
pub enum DecodingError {
    /// Decoding error when reading from the raw buffer.
    #[cfg(feature = "identity")]
    #[error("Identity decoding error: {0}")]
    IdentityError(#[from] std::io::Error),

    /// Decoding error from `DAG-PB`.
    #[cfg(feature = "dag_pb")]
    #[error(transparent)]
    PbError(#[from] ipld_dagpb::Error),

    /// Decoding error from `DAG-CBOR`.
    #[cfg(feature = "dag_cbor")]
    #[error(transparent)]
    CborError(#[from] serde_ipld_dagcbor::DecodeError<std::io::Error>),

    /// Decoding error from `DAG-JSON`.
    #[cfg(feature = "dag_json")]
    #[error(transparent)]
    JsonError(#[from] serde_ipld_dagjson::error::DecodeError),
}
