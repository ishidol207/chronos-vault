// Copyright (c) Facebook, Inc. and its affiliates.
// Modifications Copyright (c) 2022-2023 Bolt Labs Holdings, Inc
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use crate::paillier::Nonce;
use crate::{
    auxinfo::AuxInfoPublic,
    curve::CurveTrait,
    errors::{InternalError, Result},
    keygen::KeySharePublic,
    messages::{Message, MessageType, TpresignMessageType},
    paillier::Ciphertext,
    tpresign::{
        participant::ParticipantTpresignContext,
        round_one::{Private as RoundOnePrivate, PublicBroadcast as RoundOnePublicBroadcast},
    },
    zkp::{
        piaffg::{PiAffgInput, PiAffgProof},
        pilog::{CommonInput, PiLogProof},
        Proof,
    },
    ParticipantIdentifier,
};
use libpaillier::unknown_order::BigNumber;
use merlin::Transcript;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use zeroize::ZeroizeOnDrop;

#[derive(Clone, ZeroizeOnDrop)]
pub(crate) struct Private {
    pub beta: BigNumber,
    pub beta_hat: BigNumber,
    pub s: Nonce,
    pub s_hat: Nonce,
    pub r: Nonce,
    pub r_hat: Nonce,
}

impl Debug for Private {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("tpresign::round_two::Private")
            .field("beta", &"[redacted]")
            .field("beta_hat", &"[redacted]")
            .finish()
    }
}

/// Public information produced in round two of the tpresign protocol.
///
/// This type implements [`TryFrom`] on [`Message`], which validates that
/// [`Message`] is a valid serialization of `Public`, but _not_ that `Public` is
/// necessarily valid (i.e., that all the components are valid with respect to
/// each other); use [`Public::verify`] to check this latter condition.
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Public<C> {
    pub D: Ciphertext,
    pub D_hat: Ciphertext,
    pub F: Ciphertext,
    pub F_hat: Ciphertext,
    pub Gamma: C,
    pub psi: PiAffgProof<C>,
    pub psi_hat: PiAffgProof<C>,
    pub psi_prime: PiLogProof<C>,
}

impl<C: CurveTrait> Public<C> {
    pub(crate) fn parse_broadcast_part(
        &self,
        verifier_pid: ParticipantIdentifier,
    ) -> PublicBroadcast {
        PublicBroadcast {
            D: self.D.clone(),
            D_hat: self.D_hat.clone(),
            F: self.F.clone(),
            F_hat: self.F_hat.clone(),
            verifier_pid,
        }
    }

    /// Verify the validity of [`Public`] against the sender's
    /// [`AuxInfoPublic`], [`KeySharePublic`], and
    /// [`PublicBroadcast`](crate::tpresign::round_one::PublicBroadcast) values.
    pub(crate) fn verify(
        self,
        context: &ParticipantTpresignContext<C>,
        verifier_auxinfo_public: &AuxInfoPublic,
        verifier_r1_private: &RoundOnePrivate,
        prover_auxinfo_public: &AuxInfoPublic,
        prover_keyshare_public: &KeySharePublic<C>,
        prover_r1_public_broadcast: &RoundOnePublicBroadcast,
    ) -> Result<()> {
        let g = C::GENERATOR;

        // Verify the psi proof
        let psi_input = PiAffgInput::new(
            verifier_auxinfo_public.params(),
            verifier_auxinfo_public.pk(),
            prover_auxinfo_public.pk(),
            &verifier_r1_private.K,
            &self.D,
            &self.F,
            &self.Gamma,
        );
        let mut transcript = Transcript::new(b"PiAffgProof");

        self.psi.verify(psi_input, context, &mut transcript)?;

        // Verify the psi_hat proof
        let psi_hat_input = PiAffgInput::new(
            verifier_auxinfo_public.params(),
            verifier_auxinfo_public.pk(),
            prover_auxinfo_public.pk(),
            &verifier_r1_private.K,
            &self.D_hat,
            &self.F_hat,
            prover_keyshare_public.as_ref(),
        );
        let mut transcript = Transcript::new(b"PiAffgProof");
        self.psi_hat
            .verify(psi_hat_input, context, &mut transcript)?;

        // Verify the psi_prime proof
        let psi_prime_input = CommonInput::new(
            &prover_r1_public_broadcast.G,
            &self.Gamma,
            verifier_auxinfo_public.params().scheme(),
            prover_auxinfo_public.pk(),
            &g,
        );
        let mut transcript = Transcript::new(b"PiLogProof");
        self.psi_prime
            .verify(psi_prime_input, context, &mut transcript)?;

        Ok(())
    }
}

impl<C: CurveTrait> TryFrom<&Message> for Public<C> {
    type Error = InternalError;

    fn try_from(message: &Message) -> std::result::Result<Self, Self::Error> {
        message.check_type(MessageType::Tpresign(TpresignMessageType::RoundTwo))?;
        let public: Self = deserialize!(&message.unverified_bytes)?;
        Ok(public)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct PublicBroadcast {
    pub D: Ciphertext,
    pub D_hat: Ciphertext,
    pub F: Ciphertext,
    pub F_hat: Ciphertext,
    pub verifier_pid: ParticipantIdentifier,
}

impl TryFrom<&Message> for PublicBroadcast {
    type Error = InternalError;

    fn try_from(message: &Message) -> std::result::Result<Self, Self::Error> {
        message.check_type(MessageType::Tpresign(
            TpresignMessageType::RoundTwoBroadcast,
        ))?;
        let public: Self = deserialize!(&message.unverified_bytes)?;
        Ok(public)
    }
}

impl PartialEq for PublicBroadcast {
    fn eq(&self, other: &Self) -> bool {
        self.D == other.D
            && self.D_hat == other.D_hat
            && self.F == other.F
            && self.F_hat == other.F_hat
            && self.verifier_pid == other.verifier_pid
    }
}
