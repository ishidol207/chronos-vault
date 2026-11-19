//! Types and functions related to the trefresh protocol.

// Copyright (c) Facebook, Inc. and its affiliates.
// Modifications Copyright (c) 2022-2023 Bolt Labs Holdings, Inc
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use std::collections::HashMap;

use crate::{
    curve::CurveTrait,
    errors::{CallerError, InternalError, Result},
    keygen::{self, KeySharePrivate, KeySharePublic, KeygenParticipant},
    local_storage::LocalStorage,
    messages::{Message, MessageType, TrefreshMessageType},
    participant::{InnerProtocolParticipant, ProcessOutcome, ProtocolParticipant},
    protocol::{ParticipantIdentifier, ProtocolType, SharedContext},
    tshare::{
        share::{EvalEncrypted, EvalPrivate, EvalPublic},
        CoeffPrivate, CoeffPublic, Output,
    },
    zkp::pisch::{CommonInput, PiSchPrecommit, PiSchProof, ProverSecret},
    Identifier, ParticipantConfig,
};

use crate::curve::ScalarTrait;
use merlin::Transcript;
use rand::{CryptoRng, RngCore};
use tracing::{error, info, instrument, warn};

use super::commit::{TrefreshCommit, TrefreshDecommit};
use super::input::Input;

mod storage {
    use std::marker::PhantomData;

    use super::*;
    use crate::{
        local_storage::TypeTag,
        trefresh::commit::{TrefreshCommit, TrefreshDecommit},
        tshare::{
            share::{EvalPrivate, EvalPublic},
            CoeffPrivate, CoeffPublic,
        },
    };

    pub(super) struct Commit;
    impl TypeTag for Commit {
        type Value = TrefreshCommit;
    }
    pub(super) struct Decommit<C>(PhantomData<C>);
    impl<C: Send + Sync + 'static> TypeTag for Decommit<C> {
        type Value = TrefreshDecommit<C>;
    }
    pub(super) struct SchnorrPrecom<C>(PhantomData<C>);
    impl<C: Send + Sync + 'static> TypeTag for SchnorrPrecom<C> {
        type Value = PiSchPrecommit<C>;
    }
    pub(super) struct GlobalRid;
    impl TypeTag for GlobalRid {
        type Value = [u8; 32];
    }
    pub(super) struct PrivateCoeffs<C>(PhantomData<C>);
    impl<C: CurveTrait + Send + Sync> TypeTag for PrivateCoeffs<C> {
        type Value = Vec<CoeffPrivate<C>>;
    }
    pub(super) struct PublicCoeffs<C>(PhantomData<C>);
    impl<C: Send + Sync + 'static> TypeTag for PublicCoeffs<C> {
        type Value = Vec<CoeffPublic<C>>;
    }
    pub(super) struct ValidPublicShare<C>(PhantomData<C>);
    impl<C: Send + Sync + 'static> TypeTag for ValidPublicShare<C> {
        type Value = EvalPublic<C>;
    }
    pub(super) struct ValidPrivateEval<C>(PhantomData<C>);
    impl<C: CurveTrait + Send + Sync> TypeTag for ValidPrivateEval<C> {
        type Value = EvalPrivate<C>;
    }
}

/**
A [`ProtocolParticipant`] that runs the trefresh protocol.
This is a protocol that converts additive shares to Shamir shares.

# Protocol input
- The threshold `t` of parties needed to reconstruct the shared secret.
- The auxiliary information for encryption.
- Optionally, an existing n-out-of-n share to be converted to t-out-of-n share.

# Protocol output
- The public commitment to the shared polynomial. It is represented in coefficients form in the exponent (EC points).
The constant term corresponds to the shared value. This can be used to evaluate the commitment to the share of any participant.
- The private evaluation of the shared polynomial for our participant. `t` of those can reconstruct the secret.

# 🔒 Storage requirements
The private_key_share must be stored securely by the calling application, and a best effort should be made to drop it
from memory after it's securely stored. The public components (including the byte array and the public key shares)
can be stored in the clear.
**/
#[derive(Debug, Default)]
pub struct TrefreshParticipant<C: CurveTrait> {
    /// The current session identifier
    sid: Identifier,
    /// The current protocol input.
    input: Input<C>,
    /// A unique identifier for this participant.
    id: ParticipantIdentifier,
    /// A list of all other participant identifiers participating in the
    /// protocol
    other_participant_ids: Vec<ParticipantIdentifier>,
    /// Local storage for this participant to store secrets
    local_storage: LocalStorage,
}

#[derive(Debug)]
pub struct ToutofTHelper<C> {
    pub keygen_outputs: HashMap<ParticipantIdentifier, keygen::Output<C>>,
    pub public_keys: Vec<KeySharePublic<C>>,
    pub all_participants: Vec<ParticipantIdentifier>,
    pub rid: [u8; 32],
}

impl<C: CurveTrait> ProtocolParticipant for TrefreshParticipant<C> {
    type Input = Input<C>;
    type Output = Output<C>;

    fn new(
        sid: Identifier,
        id: ParticipantIdentifier,
        other_participant_ids: Vec<ParticipantIdentifier>,
        input: Self::Input,
    ) -> Result<Self> {
        input.check_participant_config(&ParticipantConfig::new(id, &other_participant_ids)?)?;

        Ok(Self {
            sid,
            input,
            id,
            other_participant_ids: other_participant_ids.clone(),
            local_storage: Default::default(),
        })
    }

    fn ready_type() -> MessageType {
        MessageType::Trefresh(TrefreshMessageType::Ready)
    }

    fn protocol_type() -> ProtocolType {
        ProtocolType::Trefresh
    }

    fn id(&self) -> ParticipantIdentifier {
        self.id
    }

    fn other_ids(&self) -> &[ParticipantIdentifier] {
        &self.other_participant_ids
    }

    fn sid(&self) -> Identifier {
        self.sid
    }

    #[cfg_attr(feature = "flame_it", flame("tref"))]
    #[instrument(skip_all)]
    fn process_message<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        message: &Message,
    ) -> Result<ProcessOutcome<Self::Output>> {
        info!(
            "TREFRESH: Player {}: received {:?} from {}",
            self.id(),
            message.message_type(),
            message.from()
        );

        match message.message_type() {
            MessageType::Trefresh(TrefreshMessageType::Ready) => {
                let res = self.gen_round_one_msgs(rng, self.sid());
                if let Err(e) = res {
                    error!("Failed to generate round one messages: {:?}", e);
                    return Err(e);
                } else {
                    let msgs = res.unwrap();
                    info!(
                        "THRESHOLD KEYGEN: Player {}: generated round one message {:?}",
                        self.id(),
                        msgs
                    );
                    return Ok(ProcessOutcome::Continue(msgs));
                }
            }
            MessageType::Trefresh(TrefreshMessageType::R1CommitHash) => {
                self.handle_round_one_msg(rng, message.clone())?;
                if self.is_r1_done() {
                    info!("TS: Player {}: round one done", self.id());
                    let res = self.gen_round_two_msgs(rng, self.sid());
                    if let Err(e) = res {
                        error!("Failed to generate round two messages: {:?}", e);
                        return Err(e);
                    } else {
                        let msgs = res.unwrap();
                        info!(
                            "THRESHOLD KEYGEN: Player {}: generated round two message {:?}",
                            self.id(),
                            msgs
                        );
                        return Ok(ProcessOutcome::Continue(msgs));
                    }
                } else {
                    info!(
                        "THRESHOLD KEYGEN: Player {}: still waiting for round one messages",
                        self.id()
                    );
                    return Ok(ProcessOutcome::Continue(vec![]));
                }
            }

            MessageType::Trefresh(TrefreshMessageType::R2Decommit) => {
                self.handle_round_two_msg(message)?;
                let is_r2_done = self.is_r2_done();
                if is_r2_done {
                    info!("THRESHOLD KEYGEN: Player {}: round two done", self.id());
                    let res = self.gen_round_three_msgs();
                    if let Err(e) = res {
                        error!("Failed to generate round three messages: {:?}", e);
                        return Err(e);
                    } else {
                        let msgs = res.unwrap();
                        info!(
                            "THRESHOLD KEYGEN: Player {}: generated round three message {:?}",
                            self.id(),
                            msgs
                        );
                        return Ok(ProcessOutcome::Continue(msgs));
                    }
                } else {
                    info!(
                        "THRESHOLD KEYGEN: Player {}: still waiting for round two messages",
                        self.id()
                    );
                    return Ok(ProcessOutcome::Continue(vec![]));
                }
            }

            MessageType::Trefresh(TrefreshMessageType::R2PrivateShare) => {
                self.handle_round_two_msg_private(message)?;
                let is_r2_done = self.is_r2_done();
                if is_r2_done {
                    info!("THRESHOLD KEYGEN: Player {}: round two done", self.id());
                    let res = self.gen_round_three_msgs();
                    if let Err(e) = res {
                        error!("Failed to generate round three messages: {:?}", e);
                        return Err(e);
                    } else {
                        let msgs = res.unwrap();
                        info!(
                            "THRESHOLD KEYGEN: Player {}: generated round three message {:?}",
                            self.id(),
                            msgs
                        );
                        return Ok(ProcessOutcome::Continue(msgs));
                    }
                } else {
                    info!(
                        "THRESHOLD KEYGEN: Player {}: still waiting for round two messages",
                        self.id()
                    );
                    return Ok(ProcessOutcome::Continue(vec![]));
                }
            }

            MessageType::Trefresh(TrefreshMessageType::R3Proof) => {
                self.handle_round_three_msg(message)?;
                let is_r3_done = self.is_r3_done();
                if is_r3_done {
                    info!("THRESHOLD KEYGEN: Player {}: round three done", self.id());
                    let res = self.gen_output();
                    if let Err(e) = res {
                        error!("Failed to generate output: {:?}", e);
                        return Err(e);
                    } else {
                        let output = res.unwrap();
                        info!(
                            "THRESHOLD KEYGEN: Player {}: generated output {:?}",
                            self.id(),
                            output
                        );
                        return Ok(ProcessOutcome::Done(output));
                    }
                } else {
                    info!(
                        "THRESHOLD KEYGEN: Player {}: still waiting for round three messages",
                        self.id()
                    );
                    return Ok(ProcessOutcome::Continue(vec![]));
                }
            }

            _ => {
                error!(
                    "THRESHOLD KEYGEN: Player {}: received unexpected message type {:?}",
                    self.id(),
                    message.message_type()
                );
                return Err(CallerError::WrongProtocol.into());
            }
        }
    }
}

impl<C: CurveTrait> InnerProtocolParticipant for TrefreshParticipant<C> {
    type Context = SharedContext<C>;

    fn retrieve_context(&self) -> <Self as InnerProtocolParticipant>::Context {
        SharedContext::collect(self)
    }

    fn local_storage(&self) -> &LocalStorage {
        &self.local_storage
    }

    fn local_storage_mut(&mut self) -> &mut LocalStorage {
        &mut self.local_storage
    }
}

impl<C: CurveTrait> TrefreshParticipant<C> {
    /// Generate the protocol's round one message.
    ///
    /// The outcome is a broadcast message containing a commitment to:
    /// - a verifiable secret sharing of `private` [`CoeffPublic`] X_ij,
    /// - a "pre-commitment" A to a Schnorr proof.
    #[cfg_attr(feature = "flame_it", flame("trefresh"))]
    #[instrument(skip_all, err(Debug))]
    fn gen_round_one_msgs<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        sid: Identifier,
    ) -> Result<Vec<Message>> {
        info!("Generating round one trefresh messages.");

        let my_old_share = self.input.share().private_key_share();
        let lagrange_coeff =
            Self::lagrange_coefficient_at_zero(&self.id(), &self.all_participants());
        let new_constant_term = my_old_share.mul(&lagrange_coeff);

        // Generate Feldman's VSS params
        let (coeff_privates, coeff_publics) = {
            let mut privates = vec![];
            let mut publics = vec![];

            for _ in 0..(self.input.threshold() - 1) {
                let (private, public) = CoeffPublic::<C>::new_pair()?;
                privates.push(private);
                publics.push(public);
            }

            // 변환된 x_i'을 VSS 다항식의 상수항으로 사용
            let const_private = CoeffPrivate {
                x: new_constant_term,
            };
            let const_public = const_private.to_public();

            privates.insert(0, const_private);
            publics.insert(0, const_public);

            (privates, publics)
        };

        // Generate proof precommitments.
        let sch_precom = PiSchProof::precommit(rng)?;

        // Store the beginning of our proofs so we can continue the proofs later.
        self.local_storage
            .store::<storage::SchnorrPrecom<C>>(self.id(), sch_precom.clone());

        let decom = TrefreshDecommit::new(
            rng,
            &sid,
            &self.id(),
            &coeff_publics,
            *sch_precom.precommitment(),
        );

        // Store the private coeffs from us to others to use for sharing later.
        self.local_storage
            .store::<storage::PrivateCoeffs<C>>(self.id(), coeff_privates);

        // Store the public coeffs from us to others to use for sharing later.
        self.local_storage
            .store::<storage::PublicCoeffs<C>>(self.id(), coeff_publics);

        let com = decom.commit()?;
        let com_bytes = serialize!(&com)?;

        self.local_storage.store::<storage::Commit>(self.id(), com);

        // Store our committed values so we can open the commitment later.
        self.local_storage
            .store::<storage::Decommit<C>>(self.id(), decom);

        let broadcast_msg = Message::new_from_serialized_data(
            MessageType::Trefresh(TrefreshMessageType::R1CommitHash),
            self.sid,
            self.id,
            None,
            true,
            com_bytes,
        )?;

        Ok(vec![broadcast_msg])
    }

    /// Handle round one messages from the protocol participants.
    ///
    /// In round one, each participant broadcasts its commitment to its initial
    /// share of the public key and a "precommitment" to a Schnorr proof.
    /// Once all such commitments have been received, this participant will
    /// send an opening of its own commitment to all other parties.
    #[cfg_attr(feature = "flame_it", flame("trefresh"))]
    #[instrument(skip_all, err(Debug))]
    fn handle_round_one_msg<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        broadcast_msg: Message,
    ) -> Result<()> {
        info!("Handling round one trefresh message.");
        broadcast_msg.check_broadcast_message()?;
        let trefresh_commit = TrefreshCommit::from_message(&broadcast_msg)?;
        self.local_storage
            .store_once::<storage::Commit>(broadcast_msg.from(), trefresh_commit)?;
        Ok(())
    }

    /// Check if the participant has received all round one messages
    pub(crate) fn is_r1_done(&self) -> bool {
        self.local_storage
            .contains_for_all_ids::<storage::Commit>(self.other_ids())
    }

    /// Generate the protocol's round two messages.
    ///
    /// The outcome is an opening to the commitment generated in round one. Each
    /// party then sends out shares corresponding to the polynomial it committed
    /// to in the first round.
    #[cfg_attr(feature = "flame_it", flame("trefresh"))]
    #[instrument(skip_all, err(Debug))]
    fn gen_round_two_msgs<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        sid: Identifier,
    ) -> Result<Vec<Message>> {
        info!("Generating round two trefresh messages.");

        if !self.is_r1_done() {
            error!("Cannot generate round two messages before round one is complete.");
            return Err(CallerError::ProtocolNotReady.into());
        }

        let decom = self
            .local_storage
            .retrieve::<storage::Decommit<C>>(self.id())?;
        let broadcast_msg = Message::new(
            MessageType::Trefresh(TrefreshMessageType::R2Decommit),
            self.sid(),
            self.id(),
            None,
            true,
            decom,
        )?;

        let private_coeffs = self
            .local_storage
            .retrieve::<storage::PrivateCoeffs<C>>(self.id())?;

        // Encrypt the private shares to each participant.
        let encrypted_shares = self
            .other_ids()
            .iter()
            .map(|other_participant_id| {
                let private_share = Self::eval_private_share(private_coeffs, *other_participant_id);

                let auxinfo = self.input.find_auxinfo_public(*other_participant_id)?;
                EvalEncrypted::encrypt(&private_share, auxinfo.pk(), rng)
            })
            .collect::<Result<Vec<_>>>()?;

        let mut messages = vec![];

        messages.extend(
            self.other_ids()
                .iter()
                .zip(encrypted_shares.iter())
                .map(|(other_participant_id, encrypted_share)| {
                    Message::new(
                        MessageType::Trefresh(TrefreshMessageType::R2PrivateShare),
                        self.sid(),
                        self.id(),
                        Some(*other_participant_id),
                        false,
                        encrypted_share,
                    )
                })
                .collect::<Result<Vec<Message>>>()?,
        );

        messages.push(broadcast_msg);
        Ok(messages)
    }

    /// Handle the protocol's round two private messages.
    /// Must be called before handle_round_two_msg.
    ///
    /// Here we validate and store a private share from someone to us.
    #[cfg_attr(feature = "flame_it", flame("trefresh"))]
    #[instrument(skip_all, err(Debug))]
    fn handle_round_two_msg_private(&mut self, message: &Message) -> Result<()> {
        info!("Handling round two trefresh private message.");

        message.check_type(MessageType::Trefresh(TrefreshMessageType::R2PrivateShare))?;
        let encrypted_share: EvalEncrypted = deserialize!(&message.unverified_bytes)?;

        // Get my private key from the AuxInfo protocol.
        let my_dk = self.input.private_auxinfo().decryption_key();

        // Decrypt the private share.
        let private_share = encrypted_share.decrypt(my_dk)?;
        // Write the private share to the storage
        self.local_storage
            .store_once::<storage::ValidPrivateEval<C>>(message.from(), private_share)?;

        Ok(())
    }

    /// Handle the protocol's round two messages.
    /// Must be called after handle_round_two_msg_private.
    ///
    /// Here we check that the decommitments from each participant are valid.
    #[cfg_attr(feature = "flame_it", flame("trefresh"))]
    #[instrument(skip_all, err(Debug))]
    // todo: Feldman’s VSS was done using the secret exponent corresponding to their share of the old public key 증명

    fn handle_round_two_msg(&mut self, message: &Message) -> Result<()> {
        info!("Handling round two trefresh message.");

        let got_all_private_shares = self
            .local_storage
            .contains_for_all_ids::<storage::ValidPrivateEval<C>>(self.other_ids());

        if !got_all_private_shares {
            error!("Cannot handle round two message before receiving all private shares.");
            return Err(CallerError::ProtocolNotReady.into());
        }

        // Check that the decommitment contained in the message is valid against
        // the previously received commitment and protocol rules.
        let com = self
            .local_storage
            .retrieve::<storage::Commit>(message.from())?;
        let decom = TrefreshDecommit::from_message(message, com)?;

        // Feldman's VSS commitment 검증
        {
            let sender_pid = message.from();
            let received_commitment = &decom.coeff_publics[0];

            let old_pk_share = self
                .input
                .share()
                .public_key_shares()
                .iter()
                .find(|x| x.participant() == sender_pid)
                .ok_or(InternalError::InternalInvariantFailed)?;

            // P_i: P_j의 Lagrange coeff (L_j(0)) 계산
            let lagrange_coeff =
                Self::lagrange_coefficient_at_zero(&sender_pid, &self.all_participants());

            // P_i: 예상되는 commitment 값  X_j ^ L_j(0) 계산
            let expected_commitment = old_pk_share.as_ref().mul(&lagrange_coeff);

            if *received_commitment.as_ref() != expected_commitment {
                error!(
                "Participant {} provided an invalid VSS commitment during key refresh. Proof `A_j,0 == X_j^L_j(0)` failed.",
                sender_pid
            );
                return Err(InternalError::InvalidRefreshShareCommitment(sender_pid));
            }
        }

        self.local_storage
            .store_once::<storage::Decommit<C>>(message.from(), decom.clone())?;
        self.local_storage
            .store::<storage::PublicCoeffs<C>>(message.from(), decom.coeff_publics);

        Ok(())
    }

    pub(crate) fn is_r2_done(&self) -> bool {
        // We are done with round two if we have received all decommitments
        // and private shares.
        self.local_storage
            .contains_for_all_ids::<storage::Decommit<C>>(self.other_ids())
    }

    /// Generate the protocol's round three messages.
    ///
    /// At this point, we have validated each participant's commitment, and can
    /// now calculate our final share of the public key and prove we know the
    /// private share value via Schnorr.
    #[cfg_attr(feature = "flame_it", flame("trefresh"))]
    #[instrument(skip_all, err(Debug))]
    fn gen_round_three_msgs(&mut self) -> Result<Vec<Message>> {
        info!("Generating round three trefresh messages.");

        // Auxiliary macro to xor two 256-bit arrays given as Vectors of 32 bytes
        macro_rules! xor_256_bits {
            ($a:expr, $b:expr) => {{
                let mut result = [0u8; 32];
                for i in 0..32 {
                    result[i] = $a[i] ^ $b[i];
                }
                result
            }};
        }

        // Compute the random identifier from individual contributions
        let my_decom = self
            .local_storage
            .retrieve::<storage::Decommit<C>>(self.id)?;
        let mut global_rid = my_decom.rid;
        for &other_participant_id in self.other_participant_ids.iter() {
            let decom = self
                .local_storage
                .retrieve::<storage::Decommit<C>>(other_participant_id)?;

            global_rid = xor_256_bits!(global_rid, decom.rid);
        }

        self.local_storage
            .store::<storage::GlobalRid>(self.id(), global_rid);

        let transcript = schnorr_proof_transcript(self.sid(), &global_rid, self.id())?;

        let private_coeffs = self
            .local_storage
            .retrieve::<storage::PrivateCoeffs<C>>(self.id())?;

        let my_private_share = Self::eval_private_share(private_coeffs, self.id());
        // let my_contant_term = Self::eval_private_share_at_zero(private_coeffs);
        // trefresh를 Key refresh 모드로도 사용 ->
        // if let Some(private) = self.input.share() {
        //     assert_eq!(my_contant_term, private.x);
        // }

        // Have we got the private shares from everybody to us?
        let got_all_private_shares = self
            .local_storage
            .contains_for_all_ids::<storage::ValidPrivateEval<C>>(self.other_ids());

        if got_all_private_shares {
            // Compute the one's own private evaluation.

            // Get a slice of EvalPrivate from other participants
            let mut from_all_to_me_private = vec![];
            for pid in self.other_ids() {
                let private_share = self
                    .local_storage
                    .retrieve::<storage::ValidPrivateEval<C>>(*pid)?;
                from_all_to_me_private.push(private_share.clone());
            }

            let other_private_shares = Self::aggregate_private_shares(&from_all_to_me_private);
            let final_private_share = other_private_shares + &my_private_share;
            let final_public_share = EvalPublic::new(final_private_share.public_point());

            // Generate proofs for each share.
            let precom = self
                .local_storage
                .retrieve::<storage::SchnorrPrecom<C>>(self.id())?;

            let pk = &final_public_share;
            let input = CommonInput::<C>::new(pk);
            let sk = &final_private_share.x;

            let proof = PiSchProof::prove_from_precommit(
                &self.retrieve_context(),
                precom,
                &input,
                &ProverSecret::new(&C::scalar_to_bn(sk)),
                &transcript,
            )?;

            self.local_storage
                .store::<storage::ValidPrivateEval<C>>(self.id(), final_private_share.clone());
            self.local_storage
                .store::<storage::ValidPublicShare<C>>(self.id(), final_public_share.clone());

            // Send all proofs to everybody.
            let broadcast_msg = Message::new(
                MessageType::Trefresh(TrefreshMessageType::R3Proof),
                self.sid(),
                self.id(),
                None,
                true,
                &proof,
            )?;

            Ok(vec![broadcast_msg])
        } else {
            Err(InternalError::ProtocolError(None))
        }
    }

    /// Assign a non-null x coordinate to each participant.
    fn participant_coordinate(pid: ParticipantIdentifier) -> C::Scalar {
        C::Scalar::convert_from_u128(pid.as_u128()).add(&C::Scalar::one())
    }

    /// Evaluate the private share
    pub fn eval_private_share(
        coeff_privates: &[CoeffPrivate<C>],
        recipient_id: ParticipantIdentifier,
    ) -> EvalPrivate<C> {
        let x = Self::participant_coordinate(recipient_id);
        assert!(x > C::Scalar::zero());
        let mut sum = C::Scalar::zero();
        for coeff in coeff_privates.iter().rev() {
            sum.mul_assign(&x);
            sum.add_assign(coeff.x);
        }
        EvalPrivate::new(sum)
    }

    /// Evaluate the private share at the point 0.
    fn eval_private_share_at_zero(coeff_privates: &[CoeffPrivate<C>]) -> C::Scalar {
        coeff_privates[0].x
    }

    /// Feldman VSS evaluation of the public share.
    /// This algorithm is slow. Consider using MSMs.
    pub(crate) fn eval_public_share(
        coeff_publics: &[CoeffPublic<C>],
        recipient_id: ParticipantIdentifier,
    ) -> Result<C> {
        let x = Self::participant_coordinate(recipient_id);
        let mut sum = C::IDENTITY;
        for coeff in coeff_publics.iter().rev() {
            sum = sum.mul(&x);
            sum = sum + *coeff.as_ref();
        }
        Ok(sum)
    }

    /// Convert Shamir shares to additive shares, for a given quorum of
    /// participants. The result can be used by the presign and sign
    /// protocols.
    ///
    /// This is done by multiplying the shares by the Lagrange coefficients.
    /// Since the constant term is the secret, we need to multiply by the
    /// Lagrange coefficient at zero.
    ///
    /// Convert a private share and the public shares of the quorum.
    #[allow(clippy::type_complexity)]
    pub fn convert_to_t_out_of_t_share(
        config: &ParticipantConfig,
        trefresh: &Output<C>,
        rid: [u8; 32],
    ) -> Result<<KeygenParticipant<C> as ProtocolParticipant>::Output> {
        let participants = config.all_participants();

        let public_key_shares = participants
            .iter()
            .map(|pid| {
                let public_t_of_n = trefresh
                    .public_key_shares()
                    .iter()
                    .find(|x| x.participant() == *pid)
                    .expect("public key share not found");

                let lagrange = Self::lagrange_coefficient_at_zero(pid, &participants);

                let public_t_of_t = public_t_of_n.as_ref().multiply_by_scalar(&lagrange);
                KeySharePublic::new(*pid, public_t_of_t)
            })
            .collect::<Vec<_>>();

        let private_key_share = {
            let lagrange = Self::lagrange_coefficient_at_zero(&config.id(), &participants);
            let private_t_of_t = trefresh.private_key_share().mul(&lagrange);
            KeySharePrivate::from_bigint(&C::scalar_to_bn(&private_t_of_t))
        };

        crate::keygen::Output::from_parts(public_key_shares, private_key_share, rid)
    }

    /// Reconstruct the secret from the shares.
    /// Use lagrange_coefficients_at_zero to get the constant term.
    pub fn reconstruct_secret(
        shares: HashMap<ParticipantIdentifier, KeySharePrivate<C>>,
        all: Vec<ParticipantIdentifier>,
    ) -> Result<C::Scalar> {
        let mut secret = C::Scalar::zero();
        // compute the coordinates
        for (id, share) in shares.iter() {
            let lagrange = Self::lagrange_coefficient_at_zero(id, &all);
            let t_out_of_t_share = lagrange.mul(&C::bn_to_scalar(share.as_ref()).unwrap());
            secret.add_assign(t_out_of_t_share);
        }
        Ok(secret)
    }

    /// Compute the Lagrange coefficient evaluated at zero.
    /// This is used to reconstruct the secret from the shares.
    pub fn lagrange_coefficient_at_zero(
        my_point: &ParticipantIdentifier,
        other_points: &[ParticipantIdentifier],
    ) -> C::Scalar {
        let mut result = C::Scalar::one();
        for point in other_points {
            if point != my_point {
                let point_coordinate = &Self::participant_coordinate(*point);
                let my_point_coordinate = &Self::participant_coordinate(*my_point);
                let numerator = C::Scalar::zero().sub(point_coordinate);
                let denominator = my_point_coordinate.sub(point_coordinate);
                let inv = denominator.invert().unwrap();
                result.mul_assign(&numerator.mul(&inv));
            }
        }
        result
    }

    /// Handle round three messages only after our own `gen_round_three_msgs`.
    fn can_handle_round_three_msg(&self) -> bool {
        self.local_storage.contains::<storage::GlobalRid>(self.id())
    }

    /// Handle the protocol's round three public messages.
    ///
    /// Here we validate the Schnorr proofs from each participant.
    #[cfg_attr(feature = "flame_it", flame("trefresh"))]
    #[instrument(skip_all, err(Debug))]
    fn handle_round_three_msg(&mut self, message: &Message) -> Result<()> {
        info!("Handling round three trefresh broadcast message.");
        if !self.can_handle_round_three_msg() {
            info!("Not yet ready to handle round three trefresh broadcast message.");
            return Err(CallerError::ProtocolNotReady.into());
        }
        let global_rid = *self
            .local_storage
            .retrieve::<storage::GlobalRid>(self.id())?;
        let proof = PiSchProof::<C>::from_message(message)?;
        let decom = self
            .local_storage
            .retrieve::<storage::Decommit<C>>(message.from())?;
        let mut final_public_share = C::IDENTITY;
        for pid in self.all_participants().iter() {
            let coeff_publics = self
                .local_storage
                .retrieve::<storage::PublicCoeffs<C>>(*pid)?;
            let public_share = Self::eval_public_share(coeff_publics, message.from())?;
            final_public_share = final_public_share + public_share;
        }
        let mut transcript = schnorr_proof_transcript(self.sid(), &global_rid, message.from())?;
        proof.verify_with_precommit(
            CommonInput::<C>::new(&final_public_share),
            &self.retrieve_context(),
            &mut transcript,
            &decom.precom,
        )?;

        let final_public_share = EvalPublic::new(final_public_share);
        // Only if the proof verifies do we store the participant's shares.
        self.local_storage
            .store_once::<storage::ValidPublicShare<C>>(
                message.from(),
                final_public_share.clone(),
            )?;
        Ok(())
    }

    fn is_r3_done(&self) -> bool {
        self.local_storage
            .contains_for_all_ids::<storage::ValidPublicShare<C>>(&self.all_participants())
    }

    #[cfg_attr(feature = "flame_it", flame("keygen"))]
    #[instrument(skip_all, err(Debug))]
    fn gen_output(&mut self) -> Result<Output<C>> {
        if !self.is_r3_done() {
            error!("Cannot generate output before round three is complete.");
            return Err(CallerError::ProtocolNotReady.into());
        }
        // Compute the public polynomial.
        let coeffs_from_all = self
            .all_participants()
            .iter()
            .map(|pid| self.local_storage.remove::<storage::PublicCoeffs<C>>(*pid))
            .collect::<Result<Vec<_>>>()?;
        let all_public_coeffs = Self::aggregate_public_coeffs(&coeffs_from_all);

        // Read my_private_share from the storage, it was already aggregated in the end
        // of round 2
        let my_private_share = self
            .local_storage
            .retrieve::<storage::ValidPrivateEval<C>>(self.id())?;

        // Double-check that the aggregated private share matches the aggregated public
        // coeffs.
        let my_public_share = my_private_share.public_point();
        let mut all_public_keys = vec![];
        for pid in self.other_participant_ids.iter() {
            let public_share = Self::eval_public_share(&all_public_coeffs, *pid)?;
            let public_share = KeySharePublic::new(*pid, public_share);
            all_public_keys.push(public_share);
        }
        all_public_keys.push(KeySharePublic::new(self.id(), my_public_share));

        let global_rid = *self.local_storage.retrieve::<storage::GlobalRid>(self.id)?;

        let mut normalized_public_keys: Vec<KeySharePublic<C>> = all_public_keys
            .iter()
            .map(|share| {
                let affine_point = share.as_ref().normalize();
                KeySharePublic::new(share.participant(), affine_point)
            })
            .collect();

        normalized_public_keys.sort_by_key(|share| share.participant());

        let output = Output::from_parts(
            normalized_public_keys,
            my_private_share.x,
            global_rid,
            self.input.threshold(),
        )?;

        Ok(output)
    }

    fn aggregate_private_shares(private_shares: &[EvalPrivate<C>]) -> EvalPrivate<C> {
        EvalPrivate::sum(private_shares)
    }

    /// Return coeffs.sum(axis=0)
    fn aggregate_public_coeffs(coeffs_from_all: &[Vec<CoeffPublic<C>>]) -> Vec<CoeffPublic<C>> {
        let n_coeffs = coeffs_from_all[0].len();
        (0..n_coeffs)
            .map(|i| {
                let sum = coeffs_from_all
                    .iter()
                    .fold(C::IDENTITY, |sum, coeffs| sum + *coeffs[i].as_ref());
                CoeffPublic::new(sum)
            })
            .collect()
    }
}

/// Generate a [`Transcript`] for [`PiSchProof`].
fn schnorr_proof_transcript(
    sid: Identifier,
    global_rid: &[u8; 32],
    sender_id: ParticipantIdentifier,
) -> Result<Transcript> {
    let mut transcript = Transcript::new(b"trefresh schnorr");
    transcript.append_message(b"sid", &serialize!(&sid)?);
    transcript.append_message(b"rid", &serialize!(global_rid)?);
    transcript.append_message(b"sender_id", &serialize!(&sender_id)?);
    Ok(transcript)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::{super::input::Input, *};
    use crate::{
        auxinfo,
        curve::{CurveTrait, TestCurve},
        tshare,
        utils::testing::init_testing,
        Identifier, ParticipantConfig,
    };
    use itertools::Itertools;
    use k256::elliptic_curve::PrimeField;
    use keygen::KeygenParticipant;
    use libpaillier::unknown_order::BigNumber;
    use rand::{CryptoRng, Rng, RngCore};
    use std::{collections::HashMap, iter::zip};
    use tracing::debug;

    /// Test utility to convert the trefreshs to t-out-of-t shares of all
    /// participants.
    #[cfg(test)]
    #[allow(clippy::type_complexity)]
    pub fn convert_to_t_out_of_t_shares<C: CurveTrait>(
        trefreshs: HashMap<ParticipantIdentifier, Output<C>>,
        all_participants: Vec<ParticipantIdentifier>,
        rid: [u8; 32],
        sum_trefresh_input: C::Scalar,
        threshold: usize,
    ) -> Result<HashMap<ParticipantIdentifier, <KeygenParticipant<C> as ProtocolParticipant>::Output>>
    {
        let real = all_participants.len();
        let mut new_private_shares = HashMap::new();
        let mut public_keys = vec![];

        // Compute the new private shares and public keys.
        for pid in trefreshs.keys() {
            if all_participants.contains(pid) {
                let output = trefreshs.get(pid).unwrap();
                let private_key = output.private_key_share();
                let private_share: KeySharePrivate<C> =
                    KeySharePrivate::from_bigint(&C::scalar_to_bn(private_key));
                let public_share = C::GENERATOR.multiply_by_scalar(private_key);
                let lagrange: C::Scalar =
                    TrefreshParticipant::<C>::lagrange_coefficient_at_zero(pid, &all_participants);
                let new_private_share: BigNumber =
                    private_share.clone().as_ref() * BigNumber::from_slice(lagrange.to_bytes());
                let new_public_share = public_share.as_ref().multiply_by_scalar(&lagrange);
                assert!(new_private_shares
                    .insert(*pid, KeySharePrivate::from_bigint(&new_private_share))
                    .is_none());
                public_keys.push(KeySharePublic::new(*pid, new_public_share));
            }
        }
        public_keys.sort_by_key(|k| k.participant());

        // Compute the new outputs
        let mut keygen_outputs: HashMap<
            ParticipantIdentifier,
            <KeygenParticipant<C> as ProtocolParticipant>::Output,
        > = HashMap::new();
        for (pid, private_key_share) in new_private_shares {
            let other_pids = all_participants
                .iter()
                .filter(|x| x != &&pid)
                .copied()
                .collect_vec();
            let config = ParticipantConfig::new(pid, &other_pids)?;
            let trefresh = trefreshs.get(&pid).unwrap();

            let output = TrefreshParticipant::convert_to_t_out_of_t_share(&config, trefresh, rid)?;

            // Test the function `convert_to_t_out_of_t_share`.
            // Compare its output with `new_private_shares` and `public_keys`, which were
            // computed with a different method above.
            assert_eq!(output.private_key_share(), &private_key_share);
            assert_eq!(
                output
                    .public_key_shares()
                    .iter()
                    .sorted_by_key(|k| k.participant())
                    .cloned()
                    .collect_vec(),
                public_keys,
            );

            assert!(keygen_outputs.insert(pid, output).is_none());
        }

        let mut sum_toft_private_shares = keygen_outputs
            .values()
            .map(|output| output.private_key_share().as_ref().clone())
            .fold(BigNumber::zero(), |acc, x| acc + x);
        sum_toft_private_shares %= <C as CurveTrait>::order();

        // Check the sum is indeed the sum of original private keys used as input of
        // trefresh reduced mod the order
        dbg!(real);
        dbg!(threshold);
        if real >= threshold {
            assert_eq!(
                C::bn_to_scalar(&sum_toft_private_shares).unwrap(),
                sum_trefresh_input
            );
        }

        Ok(keygen_outputs)
    }

    impl<C: CurveTrait> TrefreshParticipant<C> {
        pub fn new_quorum<R: RngCore + CryptoRng>(
            sid: Identifier,
            quorum_size: usize,
            share: tshare::Output<C>,
            rng: &mut R,
        ) -> Result<Vec<Self>> {
            // Prepare prereqs for making TrefreshParticipant's. Assume all the
            // simulations are stable (e.g. keep config order)
            let configs = ParticipantConfig::random_quorum(quorum_size, rng)?;
            let auxinfo_outputs = auxinfo::Output::simulate_set(&configs, rng);

            // Make the participants
            zip(configs, auxinfo_outputs)
                .map(|(config, auxinfo_output)| {
                    let input = Input::new(auxinfo_output, share.clone(), 2)?;
                    Self::new(sid, config.id(), config.other_ids().to_vec(), input)
                })
                .collect::<Result<Vec<_>>>()
        }
    }

    fn is_trefresh_done<C: CurveTrait>(quorum: &[TrefreshParticipant<C>]) -> bool {
        quorum.iter().all(|p| {
            p.local_storage
                .contains_for_all_ids::<storage::GlobalRid>(&p.all_participants())
        })
    }

    // #[cfg_attr(feature = "flame_it", flame)]
    // #[test]
    // fn trefresh_always_produces_valid_outputs() -> Result<()> {
    //     for size in 2..4 {
    //         trefresh_produces_valid_outputs(size)?;
    //     }
    //     Ok(())
    // }

    // fn trefresh_produces_valid_outputs(quorum_size: usize) -> Result<()> {
    //     let mut rng = init_testing();
    //     let sid = Identifier::random(&mut rng);
    //     let test_share = CoeffPrivate::<TestCurve> {
    //         x: <TestCurve as CurveTrait>::Scalar::convert_from_u128(42),
    //     };

    //     let mut participants =
    //         TrefreshParticipant::new_quorum(sid, quorum_size, test_share, &mut rng)?;
    //     let mut outputs = std::iter::repeat_with(|| None as Option<Output<TestCurve>>)
    //         .take(quorum_size)
    //         .collect::<Vec<_>>();

    //     // --- ROUND 1: Generate and deliver all R1 messages ---
    //     let mut round_1_inbox: HashMap<ParticipantIdentifier, Vec<Message>> =
    //         participants.iter().map(|p| (p.id(), Vec::new())).collect();

    //     for p in participants.iter_mut() {
    //         let mut broadcast_msg = p.gen_round_one_msgs(&mut rng, sid)?;
    //         for other_p in p.other_participant_ids.iter() {
    //             broadcast_msg[0].set_to(Some(*other_p));
    //             round_1_inbox
    //                 .get_mut(other_p)
    //                 .unwrap()
    //                 .push(broadcast_msg[0].clone());
    //         }
    //     }

    //     // Each participant processes all R1 messages
    //     for p in participants.iter_mut() {
    //         for msg in round_1_inbox.get(&p.id()).unwrap() {
    //             p.handle_round_one_msg(&mut rng, msg.clone())?;
    //         }
    //     }

    //     // Check if all participants have completed round one
    //     assert!(participants.iter().all(|p| p.is_r1_done()));

    //     // --- ROUND 2: Generate and deliver all R2 messages ---
    //     let mut round_2_inbox: HashMap<ParticipantIdentifier, Vec<Message>> =
    //         participants.iter().map(|p| (p.id(), Vec::new())).collect();

    //     for p in participants.iter_mut() {
    //         let mut messages = p.gen_round_two_msgs(&mut rng, sid)?;
    //         for msg in messages.iter() {
    //             if msg.check_is_broadcast() {
    //                 for other_p in p.other_participant_ids.iter() {
    //                     let mut broadcast_msg = msg.clone();
    //                     broadcast_msg.set_to(Some(*other_p));
    //                     round_2_inbox.get_mut(other_p).unwrap().push(broadcast_msg);
    //                 }
    //             } else {
    //                 let to = msg.to().ok_or(InternalError::InternalInvariantFailed)?;
    //                 round_2_inbox.get_mut(&to).unwrap().push(msg.clone());
    //             }
    //         }
    //     }

    //     // Each participant processes all R2 messages
    //     for p in participants.iter_mut() {
    //         for msg in round_2_inbox.get(&p.id()).unwrap() {
    //             if !msg.check_is_broadcast() {
    //                 p.handle_round_two_msg_private(&msg)?;
    //             }
    //         }
    //         for msg in round_2_inbox.get(&p.id()).unwrap() {
    //             if msg.check_is_broadcast() {
    //                 p.handle_round_two_msg(&msg)?;
    //             }
    //         }
    //     }

    //     // Check if all participants have completed round two
    //     assert!(participants.iter().all(|p| p.is_r2_done()));

    //     // --- ROUND 3: Generate and deliver all R3 messages ---
    //     let mut round_3_inbox: HashMap<ParticipantIdentifier, Vec<Message>> =
    //         participants.iter().map(|p| (p.id(), Vec::new())).collect();

    //     for p in participants.iter_mut() {
    //         let mut broadcast_msg = p.gen_round_three_msgs()?;
    //         for other_p in p.other_participant_ids.iter() {
    //             broadcast_msg[0].set_to(Some(*other_p));
    //             round_3_inbox
    //                 .get_mut(other_p)
    //                 .unwrap()
    //                 .push(broadcast_msg[0].clone());
    //         }
    //     }

    //     // Each participant processes all R3 messages
    //     for p in participants.iter_mut() {
    //         for msg in round_3_inbox.get(&p.id()).unwrap() {
    //             p.handle_round_three_msg(&msg)?;
    //         }
    //     }

    //     // Check if all participants have completed round three
    //     assert!(participants.iter().all(|p| p.is_r3_done()));

    //     // --- FINALIZE: Generate outputs for all participants ---
    //     let mut outputs = Vec::new();
    //     for p in participants.iter_mut() {
    //         if let Ok(output) = p.gen_output() {
    //             outputs.push(output);
    //         } else {
    //             warn!("Participant {} failed to generate output", p.id());
    //         }
    //     }

    //     // Make sure every player got an output
    //     assert_eq!(outputs.len(), quorum_size);

    //     // Make sure everybody agrees on the public parts.
    //     assert!(outputs
    //         .windows(2)
    //         .all(|o| o[0].public_coeffs() == o[1].public_coeffs()));
    //     assert!(outputs.windows(2).all(|o| {
    //         let first_pks = o[0].public_key_shares();
    //         let second_pks = o[1].public_key_shares();
    //         // for each element in first_pks, there must be a corresponding element in
    //         // second_pks
    //         first_pks.iter().all(|x| second_pks.iter().any(|y| x == y))
    //     }));

    //     // Check returned outputs
    //     //
    //     // Every participant should have a public output from every other participant
    //     // and, for a given participant, they should be the same in every output

    //     // let qurorum_size = participants.len();
    //     // for participant in participants.iter_mut() {
    //     //     // Check that each participant fully completed its broadcast portion.
    //     //     assert_eq!(qurorum_size, participant.other_ids().len());
    //     // }

    //     // Check that each participant's own `CoeffPublic` corresponds to their
    //     // `CoeffPrivate`
    //     for (output, pid) in outputs
    //         .iter()
    //         .zip(participants.iter().map(ProtocolParticipant::id))
    //     {
    //         let publics_coeffs = output
    //             .public_coeffs()
    //             .iter()
    //             .map(|coeff| CoeffPublic::new(*coeff.as_ref()))
    //             .collect::<Vec<_>>();
    //         let public_share = TrefreshParticipant::eval_public_share(&publics_coeffs, pid)?;

    //         let expected_public_share = TestCurve::GENERATOR.mul(output.private_key_share());
    //         // if the output already contains the public key, then we don't need to
    //         // recompute and check it here.
    //         assert_eq!(public_share, expected_public_share);

    //         // get the public key from output and validate against the expected public share
    //         let public_key = output
    //             .public_key_shares()
    //             .iter()
    //             .find(|x| x.participant() == pid)
    //             .unwrap();
    //         assert_eq!(public_key.as_ref(), &public_share);
    //     }

    //     // validate the final public key, which is given by the sum of the public keys
    //     // of all participants
    //     let mut sum_public_keys_first = TestCurve::IDENTITY;
    //     for public_key in outputs.first().unwrap().public_key_shares() {
    //         sum_public_keys_first = sum_public_keys_first + *public_key.as_ref();
    //     }
    //     for output in outputs.iter().skip(1) {
    //         let mut sum_public_keys = TestCurve::IDENTITY;
    //         for public_key in output.public_key_shares() {
    //             sum_public_keys = sum_public_keys + *public_key.as_ref();
    //         }
    //         assert_eq!(sum_public_keys, sum_public_keys_first);
    //     }

    //     Ok(())
    // }

    fn generate_polynomial(t: usize) -> Vec<<TestCurve as CurveTrait>::Scalar> {
        let mut coefficients = Vec::with_capacity(t);
        for _ in 0..t {
            coefficients.push(<TestCurve as CurveTrait>::Scalar::random());
        }
        coefficients
    }

    pub fn evaluate_polynomial(
        coefficients: &[<TestCurve as CurveTrait>::Scalar],
        x: &<TestCurve as CurveTrait>::Scalar,
    ) -> <TestCurve as CurveTrait>::Scalar {
        coefficients
            .iter()
            .rev()
            .fold(<TestCurve as CurveTrait>::Scalar::zero(), |acc, coef| {
                acc * x + coef
            })
    }

    fn evaluate_at_points(
        coefficients: &[<TestCurve as CurveTrait>::Scalar],
        points: &[<TestCurve as CurveTrait>::Scalar],
    ) -> Vec<<TestCurve as CurveTrait>::Scalar> {
        points
            .iter()
            .map(|x| evaluate_polynomial(coefficients, x))
            .collect()
    }

    #[test]
    fn test_evaluate_points_at_zero() {
        let t: u128 = 3;
        let n: u128 = 7;
        let coefficients = generate_polynomial(t as usize);

        // test that reconstruction works as long as we have enough points
        for n in t..n {
            let points: Vec<<TestCurve as CurveTrait>::Scalar> = (1..=n)
                .map(|i: u128| <TestCurve as CurveTrait>::Scalar::from_u128(i + 1))
                .collect();
            let values = evaluate_at_points(&coefficients, &points);

            let zero = <TestCurve as CurveTrait>::Scalar::zero();
            let zero_value = evaluate_polynomial(&coefficients, &zero);

            let points: Vec<ParticipantIdentifier> = (1..=n)
                .map(|i: u128| ParticipantIdentifier::from_u128(i))
                .collect();
            let zero_value_reconstructed = values
                .iter()
                .zip(&points)
                .map(|(value, point)| {
                    *value
                        * TrefreshParticipant::<TestCurve>::lagrange_coefficient_at_zero(
                            point, &points,
                        ) as <TestCurve as CurveTrait>::Scalar
                })
                .fold(<TestCurve as CurveTrait>::Scalar::zero(), |acc, x| acc + x);

            assert_eq!(zero_value, zero_value_reconstructed);
        }
    }
}
