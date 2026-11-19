// Copyright (c) 2022-2023 Bolt Labs Holdings, Inc
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

use crate::{
    curve::{CurveTrait, ScalarTrait, VerifyingKeyTrait},
    errors::{CallerError, InternalError, Result},
    keygen::KeySharePublic,
    tshare::{self, CoeffPrivate},
    ParticipantIdentifier,
};

use tracing::error;

use super::CoeffPublic;

/// Output type from key generation, including all parties' public key shares,
/// this party's private key share, and the public commitment to the
/// coefficients corresponding to the final shamir secret sharing.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(bound = "C: CurveTrait")]
pub struct Output<C: CurveTrait> {
    // Public keys for each participant
    public_key_shares: Vec<KeySharePublic<C>>,
    // A Scalar representing the private share,
    private_key_share: C::Scalar,
    // The rid
    rid: [u8; 32],
    threshold: usize,
}

impl<C: CurveTrait> Output<C> {
    pub fn new(
        public_key_shares: Vec<KeySharePublic<C>>,
        private_key_share: C::Scalar,
        rid: [u8; 32],
        threshold: usize,
    ) -> Self {
        Self {
            public_key_shares,
            private_key_share,
            rid,
            threshold,
        }
    }

    /// Construct the generated public key.
    pub fn public_key(&self) -> Result<C::VerifyingKey> {
        let participants: Vec<_> = self
            .public_key_shares
            .iter()
            .map(|s| s.participant())
            .collect();

        if self.public_key_shares.len() < self.threshold {
            return Err(InternalError::InternalInvariantFailed.into());
        }

        let point = self
            .public_key_shares
            .iter()
            .fold(C::IDENTITY, |sum, share| {
                let lagrange = crate::tshare::TshareParticipant::<C>::lagrange_coefficient_at_zero(
                    &share.participant(),
                    &participants,
                );
                sum + share.as_ref().multiply_by_scalar(&lagrange)
            });

        C::VerifyingKey::from_point(point)
    }

    pub fn public_key_as_C(&self) -> Result<C> {
        let participants: Vec<_> = self
            .public_key_shares
            .iter()
            .map(|s| s.participant())
            .collect();

        if self.public_key_shares.len() < self.threshold {
            return Err(InternalError::InternalInvariantFailed.into());
        }

        let point = self
            .public_key_shares
            .iter()
            .fold(C::IDENTITY, |sum, share| {
                let lagrange = crate::tshare::TshareParticipant::<C>::lagrange_coefficient_at_zero(
                    &share.participant(),
                    &participants,
                );
                sum + share.as_ref().multiply_by_scalar(&lagrange)
            });

        Ok(point)
    }

    /// Get the individual shares of the public key.
    pub fn public_key_shares(&self) -> &[KeySharePublic<C>] {
        &self.public_key_shares
    }

    /// Get the private share
    pub fn private_key_share(&self) -> &C::Scalar {
        &self.private_key_share
    }

    /// Get the rid.
    pub fn rid(&self) -> &[u8; 32] {
        &self.rid
    }

    pub fn threshold(&self) -> usize {
        self.threshold
    }

    /// Get the [`ParticipantIdentifier`] corresponding to the
    /// private key share.
    pub(crate) fn private_pid(&self) -> Result<ParticipantIdentifier> {
        // 자신의 f(i)에 해당하는 g^f(i)계산
        let expectected_public_share = C::GENERATOR.multiply_by_scalar(self.private_key_share());

        let found_share = self
            .public_key_shares()
            .iter()
            .find(|share| share.as_ref() == &expectected_public_share);

        match found_share {
            Some(share) => Ok(share.participant()),
            None => {
                error!("Unable find a public verification share corresponding to the private key share");
                Err(InternalError::InternalInvariantFailed.into())
            }
        }
    }

    /// Create a new `Output` from its constitutent parts.
    ///
    /// This method should only be used with components that were previously
    /// derived via the [`Output::into_parts()`] method; the calling application
    /// should not try to form public and private key shares independently.
    ///
    /// The provided components must satisfy the following properties:
    /// - `public_coeffs` is a list of group elements corresponding to a
    ///   commitment to a polynomial `f` that is unknown to any one party
    /// - `public_keys` contains ECDSA public key shares of other parties,
    ///   derived from `public_coeffs`.
    /// - `private_key_share` corresponds to f(i) for some i and is this party's
    ///   private ECDSA key share
    /// - The public key shares must be from a unique set of participants.
    pub fn from_parts(
        public_keys: Vec<KeySharePublic<C>>,
        private_key_share: C::Scalar,
        rid: [u8; 32],
        threshold: usize,
    ) -> Result<Self> {
        let pids = public_keys
            .iter()
            .map(KeySharePublic::participant)
            .collect::<HashSet<_>>();
        if pids.len() != public_keys.len() {
            error!("Tried to create a keygen output using a set of public material from non-unique participants");
            Err(CallerError::BadInput)?
        }

        Ok(Self {
            public_key_shares: public_keys,
            private_key_share,
            rid,
            threshold,
        })
    }

    /// Decompose the `Output` into its constituent parts.
    ///
    /// # 🔒 Storage requirements
    /// The private_key_share must be stored securely by the calling
    /// application, and a best effort should be made to drop it from memory
    /// after it's securely stored.
    ///
    /// The public components (including the byte array and the public key
    /// shares) can be stored in the clear.
    #[allow(clippy::type_complexity)]
    pub fn into_parts(self) -> (Vec<KeySharePublic<C>>, C::Scalar, [u8; 32], usize) {
        (
            self.public_key_shares,
            self.private_key_share,
            self.rid,
            self.threshold,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        curve::{CurveTrait, TestCurve},
        threshold,
        tshare::{self, CoeffPublic, TshareParticipant},
        utils::testing::init_testing,
        ParticipantIdentifier,
    };
    use itertools::Itertools;
    use k256::elliptic_curve::Field;
    use libpaillier::unknown_order::BigNumber;
    use rand::Rng;
    type Output<C> = super::Output<C>;
    type CoeffPrivate<C> = tshare::CoeffPrivate<C>;

    impl<C: CurveTrait> Output<C> {
        /// !!!received shares는 제대로 계산하지 않음!!!
        /// Simulate the valid output of a keygen run with the given
        /// participants.
        ///
        /// This should __never__ be called outside of tests! The given `pids`
        /// must not contain duplicates. Self is the last participant in `pids`.

        pub(crate) fn simulate(pids: &[ParticipantIdentifier], threshold: usize) -> Self {
            let (private_key_shares, public_key_shares): (Vec<_>, Vec<_>) = pids
                .iter()
                .map(|&pid| {
                    // TODO #340: Replace with KeyShare methods once they exist.
                    let secret = BigNumber::random(&C::order());
                    let public = C::GENERATOR
                        .multiply_by_bignum(&secret)
                        .expect("can't multiply by generator");
                    (secret, KeySharePublic::new(pid, public))
                })
                .unzip();

            let rng = &mut init_testing();
            let rid = rng.gen();

            Self::from_parts(
                public_key_shares,
                C::bn_to_scalar(&private_key_shares.last().unwrap())
                    .expect("Failed to convert to scalar"),
                rid,
                threshold,
            )
            .expect("Failed to form output")
        }
    }

    #[test]
    fn from_into_parts_works() {
        let rng = &mut init_testing();
        let pids = std::iter::repeat_with(|| ParticipantIdentifier::random(rng))
            .take(5)
            .collect::<Vec<_>>();
        let threshold = 3;
        let output: Output<TestCurve> = Output::simulate(&pids, threshold);

        let (public_keys, private_key, rid, threshold) = output.into_parts();
        assert!(Output::from_parts(public_keys, private_key, rid, threshold).is_ok());
    }

    #[test]
    fn public_shares_must_not_have_duplicate_pids() {
        let mut rng = &mut init_testing();
        let mut pids = std::iter::repeat_with(|| ParticipantIdentifier::random(rng))
            .take(5)
            .collect::<Vec<_>>();
        let threshold = 3;

        // Duplicate one of the PIDs
        pids.push(pids[4]);

        // Form output with the duplicated PID
        let (mut private_key_shares, public_key_shares): (Vec<_>, Vec<_>) = pids
            .iter()
            .map(|&pid| {
                // TODO #340: Replace with KeyShare methods once they exist.
                let secret = <<TestCurve as CurveTrait>::Scalar as Field>::random(&mut rng);
                let public = TestCurve::GENERATOR.multiply_by_scalar(&secret);
                (secret, KeySharePublic::new(pid, public))
            })
            .multiunzip();

        let rng = &mut init_testing();
        let rid = rng.gen();

        assert!(Output::from_parts(
            public_key_shares,
            private_key_shares.pop().unwrap(),
            rid,
            threshold
        )
        .is_err());
    }
}
