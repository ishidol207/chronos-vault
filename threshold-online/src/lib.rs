// Copyright (c) 2023 Bolt Labs Holdings, Inc
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Online phase shared by the threshold ECDSA protocol driver and Bitcoin.
//! Key generation and interactive preprocessing live in TShare and TPreSign.
use k256::elliptic_curve::{ff::Field, ops::Reduce, point::AffineCoordinates, scalar::IsHigh};
use k256::{AffinePoint, Scalar, U256};
use serde::{Deserialize, Serialize};
use zeroize::ZeroizeOnDrop;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartialSignature<S> {
    pub r: S,
    pub share: S,
}

pub trait SigningScalar: Copy {
    fn partial(r: Self, k: Self, chi: Self, digest: Self) -> PartialSignature<Self>;
    fn combine(shares: &[PartialSignature<Self>]) -> Option<(Self, Self)>;
}

impl<S: Field + IsHigh> SigningScalar for S {
    fn partial(r: S, k: S, chi: S, digest: S) -> PartialSignature<S> {
        PartialSignature {
            r,
            share: k * digest + r * chi,
        }
    }

    fn combine(shares: &[PartialSignature<S>]) -> Option<(S, S)> {
        let r = shares.first()?.r;
        if bool::from(r.is_zero()) || shares.iter().any(|part| part.r != r) {
            return None;
        }
        let s: S = shares.iter().map(|part| part.share).sum();
        if bool::from(s.is_zero()) {
            return None;
        }
        Some((r, if bool::from(s.is_high()) { -s } else { s }))
    }
}

/// Party-local wire format of tpresign::TpresignRecord<K256>.
/// Each record belongs to one signing quorum and may release at most one share.
#[derive(Serialize, Deserialize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct PresignRecord {
    #[serde(rename = "R")]
    nonce_point: AffinePoint,
    k: Scalar,
    chi: Scalar,
}

impl PresignRecord {
    /// Public one-use identifier. Using the reduced x coordinate also detects -R.
    pub fn nonce_id(&self) -> [u8; 32] {
        let r = <Scalar as Reduce<U256>>::reduce_bytes(&self.nonce_point.x());
        r.to_bytes().into()
    }

    /// The caller must durably reserve nonce_id before releasing the result.
    pub fn sign(self, prehash: [u8; 32]) -> Option<PartialSignature<Scalar>> {
        let r = <Scalar as Reduce<U256>>::reduce_bytes(&self.nonce_point.x());
        if r == Scalar::ZERO {
            return None;
        }
        let digest = <Scalar as Reduce<U256>>::reduce_bytes(&prehash.into());
        Some(Scalar::partial(r, self.k, self.chi, digest))
    }
}

pub type Secp256k1Share = PartialSignature<Scalar>;

/// Produces compact (r,s) for independent prehash verification by the caller.
pub fn combine_pair(a: &Secp256k1Share, b: &Secp256k1Share) -> Option<[u8; 64]> {
    let (r, s) = Scalar::combine(&[a.clone(), b.clone()])?;
    let mut compact = [0; 64];
    compact[..32].copy_from_slice(&r.to_bytes());
    compact[32..].copy_from_slice(&s.to_bytes());
    Some(compact)
}
