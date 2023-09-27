use signature::{SignatureEncoding, Signer, Verifier};
use std::{fmt::Debug, str::FromStr};

pub trait Did: PartialEq + ToString + FromStr + Verifier<Self::Signature> {
    type Signature: SignatureEncoding + PartialEq + Debug;
    type Signer: Signer<Self::Signature> + Debug;
}
