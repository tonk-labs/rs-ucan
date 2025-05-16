use async_signature::AsyncSigner;
use signature::Signer;
use std::error::Error;
use thiserror::Error;

use crate::{codec::Codec, header::traits::Verify};

pub trait Sign: Verify {
    type Signer: Signer<Self::Signature>;
    type SignError: Error;

    #[tracing::instrument(skip_all)]
    fn try_sign<T, C: Codec<T>>(
        &self,
        codec: &C,
        signer: &Self::Signer,
        payload: &T,
    ) -> Result<Self::Signature, SignerError<C::EncodingError, Self::SignError>> {
        let mut buffer = Vec::new();
        codec
            .encode_payload(payload, &mut buffer)
            .map_err(SignerError::EncodingError)?;
        Ok(signer
            .try_sign(&buffer)
            .map_err(SignerError::SigningError)?)
    }
}

pub trait AsyncSign: Verify {
    type AsyncSigner: AsyncSigner<Self::Signature>;
    type AsyncSignError: Error;

    #[tracing::instrument(skip_all)]
    async fn try_sign_async<T, C: Codec<T>>(
        &self,
        codec: &C,
        signer: &Self::AsyncSigner,
        payload: &T,
    ) -> Result<Self::Signature, SignerError<C::EncodingError, Self::AsyncSignError>> {
        let mut buffer = Vec::new();
        codec
            .encode_payload(payload, &mut buffer)
            .map_err(SignerError::EncodingError)?;
        Ok(signer
            .sign_async(&buffer)
            .await
            .map_err(SignerError::SigningError)?)
    }
}

#[derive(Error)]
pub enum SignerError<Ee: Error, Ve: Error> {
    #[error(transparent)]
    EncodingError(Ee),

    #[error("Signing error: {0}")]
    SigningError(signature::Error),

    #[error(transparent)]
    VarsigError(Ve),
}
