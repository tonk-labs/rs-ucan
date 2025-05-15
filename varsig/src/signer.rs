use std::error::Error;

use async_signature::AsyncSigner;
use signature::Signer;
use thiserror::Error;

use crate::{
    envelope::{Envelope, EnvelopePayload},
    header::traits::Verify,
};

pub trait Header<T>: Verify<T> {
    type Signer: Signer<Self::Signature>;
    type Error: Error;

    fn try_sign(
        &self,
        signer: &Self::Signer,
        payload: &T,
    ) -> Result<Self::Signature, SigningError<Self::EncodingError, Self::Error>> {
        let mut buffer = Vec::new();
        self.encode_payload(payload, &mut buffer)?;
        Ok(signer.sign(&buffer)?)
    }

    fn try_sign_envelope(
        self,
        signer: &Self::Signer,
        payload: T,
    ) -> Result<Self::Signature, SigningError<Self::EncodingError, Self::Error>> {
        let envelope = EnvelopePayload {
            header: self,
            payload,
        };
        let signature = envelope.header.try_sign(signer, &envelope)?;
        Ok(Envelope(envelope, payload))
    }
}

// FIXME tracing

pub trait AsyncHeader<T>: Verify<T> {
    type AsyncSigner: AsyncSigner<Self::Signature>;
    type AsyncError: Error;

    async fn try_sign_async(
        &self,
        signer: &Self::AsyncSigner,
        payload: &T,
    ) -> Result<Self::Signature, SigningError<Self::EncodingError, Self::AsyncError>> {
        let mut buffer = Vec::new();
        self.encode_payload(payload, &mut buffer)?;
        Ok(signer.sign_async(&buffer).await?)
    }

    async fn try_sign_envelope_async(
        self,
        signer: &Self::AsyncSigner,
        payload: T,
    ) -> Result<Self::Signature, SigningError<Self::EncodingError, Self::AsyncError>> {
        let envelope = EnvelopePayload {
            header: self,
            payload,
        };
        let signature = envelope.header.try_sign_async(signer, &envelope).await?;
        Ok(Envelope(envelope, payload))
    }
}

#[derive(Error)]
pub enum SigningError<Ee: Error, Ve: Error> {
    #[error(transparent)]
    EncodingError(Ee),

    #[error(transparent)]
    SigningError(#[from] signature::Error),

    #[error(transparent)]
    VarsigError(Ve),
}
