//! Types and functions related to the key refresh sub-protocol Participant.

// Copyright (c) Facebook, Inc. and its affiliates.
// Modifications Copyright (c) 2022-2023 Bolt Labs Holdings, Inc
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use std::vec;

use crate::{
    curve::CurveTrait,
    errors::{CallerError, InternalError, Result},
    keyrefresh::{
        keyrefresh_commit::{KeyrefreshCommit, KeyrefreshDecommit},
        keyshare::{KeyUpdateEncrypted, KeyUpdatePrivate, KeyUpdatePublic},
    },
    local_storage::LocalStorage,
    messages::{KeyrefreshMessageType, Message, MessageType},
    participant::{InnerProtocolParticipant, ProcessOutcome, ProtocolParticipant},
    protocol::{ParticipantIdentifier, ProtocolType, SharedContext},
    zkp::pisch::{CommonInput, PiSchPrecommit, PiSchProof, ProverSecret},
    Identifier, ParticipantConfig,
};

use merlin::Transcript;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use tracing::{error, info, instrument, warn};

use super::{input::Input, Output};

mod storage {
    use std::marker::PhantomData;

    use super::*;
    use crate::local_storage::TypeTag;

    pub(super) struct Commit;
    impl TypeTag for Commit {
        type Value = KeyrefreshCommit;
    }
    pub(super) struct Decommit<C>(PhantomData<C>);
    impl<C: Send + Sync + 'static> TypeTag for Decommit<C> {
        type Value = KeyrefreshDecommit<C>;
    }
    pub(super) struct VecSchnorrPrecom<C>(PhantomData<C>);
    impl<C: Send + Sync + 'static> TypeTag for VecSchnorrPrecom<C> {
        type Value = Vec<PiSchPrecommit<C>>;
    }
    pub(super) struct GlobalRid;
    impl TypeTag for GlobalRid {
        type Value = [u8; 32];
    }
    pub(super) struct PrivateUpdatesForOthers<C>(PhantomData<C>);
    impl<C: Send + Sync + 'static> TypeTag for PrivateUpdatesForOthers<C> {
        type Value = Vec<super::KeyUpdatePrivate<C>>;
    }
    pub(super) struct ValidPublicUpdates<C>(PhantomData<C>);
    impl<C: Send + Sync + 'static> TypeTag for ValidPublicUpdates<C> {
        type Value = Vec<super::KeyUpdatePublic<C>>;
    }
    pub(super) struct ValidPrivateUpdate<C>(PhantomData<C>);
    impl<C: Send + Sync + 'static> TypeTag for ValidPrivateUpdate<C> {
        type Value = super::KeyUpdatePrivate<C>;
    }
}

/**
A [`ProtocolParticipant`] that runs the key refresh protocol.

# Protocol input
- Encryption and decryption keys from the Aux-Info protocol.

# Protocol output
Upon successful completion, the participant produces [`Output`], which
includes:
- A list of *updated* public key shares, one for each participant (including this
  participant);
- A single *updated* private key share for this participant.

This is the same output structure as the keygen protocol.
# 🔒 Storage requirements
The [private key share](crate::keygen::KeySharePrivate) in the output requires secure
persistent storage.
**/
#[derive(Debug, Default)]
pub struct KeyrefreshParticipant<C: CurveTrait> {
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

impl<C: CurveTrait> ProtocolParticipant for KeyrefreshParticipant<C> {
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
        MessageType::Keyrefresh(KeyrefreshMessageType::Ready)
    }

    fn protocol_type() -> ProtocolType {
        ProtocolType::Keyrefresh
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

    #[cfg_attr(feature = "flame_it", flame("keyrefresh"))]
    #[instrument(skip_all)]
    fn process_message<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        message: &Message,
    ) -> Result<ProcessOutcome<Self::Output>> {
        info!(
            "KEYREFRESH: Player {}: received {:?} from {}",
            self.id(),
            message.message_type(),
            message.from()
        );

        match message.message_type() {
            MessageType::Keyrefresh(KeyrefreshMessageType::Ready) => {
                let res = self.gen_round_one_msgs(rng, self.sid);
                if let Err(e) = res {
                    error!("Failed to generate round one messages: {:?}", e);
                    return Err(e);
                } else {
                    let msgs = res.unwrap();
                    info!(
                        "KEYREFRESH: Player {} generated round one message: {:?}",
                        self.id, msgs
                    );
                    return Ok(ProcessOutcome::Continue(msgs));
                }
            }
            MessageType::Keyrefresh(KeyrefreshMessageType::R1CommitHash) => {
                self.handle_round_one_msg(rng, message.clone())?;
                let is_r1_done = self.is_r1_done();

                if is_r1_done {
                    info!("KEYREFRESH: Player {} completed round one.", self.id);
                    let res = self.gen_round_two_msgs(rng, self.sid);
                    if let Err(e) = res {
                        error!("Failed to generate round two messages: {:?}", e);
                        return Err(e);
                    } else {
                        let msgs = res.unwrap();
                        info!(
                            "KEYREFRESH: Player {} generated round two message: {:?}",
                            self.id, msgs
                        );
                        return Ok(ProcessOutcome::Continue(msgs));
                    }
                } else {
                    info!(
                        "KEYREFRESH: Player {}: still waiting for round one messages",
                        self.id
                    );
                    return Ok(ProcessOutcome::Continue(vec![]));
                }
            }
            MessageType::Keyrefresh(KeyrefreshMessageType::R2Decommit) => {
                self.handle_round_two_msg(rng, message)?;
                let is_r2_done = self.is_r2_done();

                if is_r2_done {
                    info!("KEYREFRESH: Player {}: round two done", self.id());
                    let res = self.gen_round_three_msgs(rng);
                    if let Err(e) = res {
                        error!("Failed to generate round three messages: {:?}", e);
                        return Err(e);
                    } else {
                        let msgs = res.unwrap();
                        info!(
                            "KEYREFRESH: Player {} generated round three messages: {:?}",
                            self.id, msgs
                        );
                        return Ok(ProcessOutcome::Continue(msgs));
                    }
                } else {
                    info!(
                        "KEYREFRESH: Player {}: still waiting for round two messages",
                        self.id
                    );
                    return Ok(ProcessOutcome::Continue(vec![]));
                }
            }
            MessageType::Keyrefresh(KeyrefreshMessageType::R3Proofs) => {
                self.handle_round_three_msg(message)?;
                let is_r3_done = self.is_r3_done();

                if is_r3_done {
                    info!("KEYREFRESH: Player {}: round three done", self.id());
                    let res = self.gen_output();
                    if let Err(e) = res {
                        error!("Failed to generate output: {:?}", e);
                        return Err(e);
                    } else {
                        let output = res.unwrap();
                        info!(
                            "KEYREFRESH: Player {} generated output: {:?}",
                            self.id, output
                        );
                        return Ok(ProcessOutcome::Done(output));
                    }
                } else {
                    info!(
                        "KEYREFRESH: Player {}: still waiting for round three messages",
                        self.id
                    );
                    return Ok(ProcessOutcome::Continue(vec![]));
                }
            }
            MessageType::Keyrefresh(KeyrefreshMessageType::R3PrivateUpdate) => {
                self.handle_round_three_msg_private(message)?;

                let is_r3_done = self.is_r3_done();
                if is_r3_done {
                    info!("KEYREFRESH: Player {}: round three done", self.id());
                    let res = self.gen_output();
                    if let Err(e) = res {
                        error!("Failed to generate output: {:?}", e);
                        return Err(e);
                    } else {
                        let output = res.unwrap();
                        info!(
                            "KEYREFRESH: Player {} generated output: {:?}",
                            self.id, output
                        );
                        return Ok(ProcessOutcome::Done(output));
                    }
                } else {
                    info!(
                        "KEYREFRESH: Player {}: still waiting for round three messages",
                        self.id
                    );
                    return Ok(ProcessOutcome::Continue(vec![]));
                }
            }
            _ => {
                error!(
                    "KEYREFRESH: Player {}: received unexpected message type {:?}",
                    self.id,
                    message.message_type()
                );
                Err(CallerError::BadInput)?
            }
        }
    }
}

impl<C: CurveTrait> InnerProtocolParticipant for KeyrefreshParticipant<C> {
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

impl<C: CurveTrait> KeyrefreshParticipant<C> {
    #[cfg(test)]
    pub fn get_input(&self) -> &Input<C> {
        &self.input
    }
    /// Generate the protocol's round one message.
    ///
    /// The outcome is a broadcast message containing a commitment to:
    /// - updates [`KeyUpdatePublic`] X_ij for all other participants,
    /// - "pre-commitments" A_ij for Schnorr proofs.
    #[cfg_attr(feature = "flame_it", flame("keyrefresh"))]
    #[instrument(skip_all, err(Debug))]
    fn gen_round_one_msgs<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        sid: Identifier,
    ) -> Result<Vec<Message>> {
        info!("Generating round one keyrefresh messages.");

        // Generate keyshare updates for all participants.
        let (update_privates, update_publics) = {
            let mut privates = vec![];
            let mut publics = vec![];

            // Random shares for others.
            for pid in self.other_ids() {
                let (private, public) = KeyUpdatePublic::new_keyshare(*pid, rng)?;
                privates.push(private);
                publics.push(public);
            }

            // Compute one's own update such that the sum of updates is 0.
            let my_update_private = KeyUpdatePrivate::zero_sum(&privates);
            let my_update_public =
                KeyUpdatePublic::new(self.id(), my_update_private.public_point()?);
            privates.push(my_update_private);
            publics.push(my_update_public);

            (privates, publics)
        };

        // This corresponds to `A_ij` in the paper.
        let sch_precoms = (0..update_publics.len())
            .map(|_| PiSchProof::precommit(rng))
            .collect::<Result<Vec<_>>>()?;

        let decom = KeyrefreshDecommit::new(
            rng,
            &sid,
            &self.id(),
            update_publics,
            sch_precoms
                .iter()
                .map(|sch_precom| *sch_precom.precommitment())
                .collect(),
        );

        // Store the beginning of our proofs so we can continue the proofs later.
        self.local_storage
            .store::<storage::VecSchnorrPrecom<C>>(self.id(), sch_precoms);

        // Mark our own public updates as verified.
        self.local_storage
            .store::<storage::ValidPublicUpdates<C>>(self.id(), decom.update_publics.clone());

        // Store the private update from ourselves to ourselves.
        self.local_storage.store::<storage::ValidPrivateUpdate<C>>(
            self.id(),
            update_privates[update_privates.len() - 1].clone(),
        );

        // Store the private updates from us to others so we can share them later.
        self.local_storage
            .store::<storage::PrivateUpdatesForOthers<C>>(self.id(), update_privates);

        // Mark our own commitment as ready. This corresponds to `V_i` in the paper.
        let com = decom.commit()?;
        self.local_storage
            .store::<storage::Commit>(self.id(), com.clone());

        // Store our committed values so we can open the commitment later.
        self.local_storage
            .store::<storage::Decommit<C>>(self.id(), decom);

        let message = Message::new_from_serialized_data(
            MessageType::Keyrefresh(KeyrefreshMessageType::R1CommitHash),
            self.sid,
            self.id,
            None,
            true,
            serialize!(&com)?,
        )?;

        Ok(vec![message])
    }

    /// Handle round one messages from the protocol participants.
    ///
    /// In round one, each participant broadcasts its commitment to its public
    /// key share and a "precommitment" to a Schnorr proof. Once all such
    /// commitments have been received, this participant will send an opening of
    /// its own commitment to all other parties.
    #[cfg_attr(feature = "flame_it", flame("keyrefresh"))]
    #[instrument(skip_all, err(Debug))]
    fn handle_round_one_msg<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        broadcast_msg: Message,
    ) -> Result<()> {
        info!("Handling round one keyrefresh message.");
        broadcast_msg.check_broadcast_message()?;

        let keyrefresh_commit = KeyrefreshCommit::from_message(&broadcast_msg)?;
        self.local_storage
            .store_once::<storage::Commit>(broadcast_msg.from(), keyrefresh_commit)?;

        Ok(())
    }

    /// Check if the participant has received all round one messages
    pub(crate) fn is_r1_done(&self) -> bool {
        // todo: 중앙 서버 모델에서는 self.all_participants()를 사용해도 될지도?
        self.local_storage
            .contains_for_all_ids::<storage::Commit>(&self.other_ids())
    }

    /// Generate the protocol's round two messages.
    ///
    /// The outcome is an opening to the commitment generated in round one.
    #[cfg_attr(feature = "flame_it", flame("keyrefresh"))]
    #[instrument(skip_all, err(Debug))]
    fn gen_round_two_msgs<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        sid: Identifier,
    ) -> Result<Vec<Message>> {
        info!("Generating round two keyrefresh messages.");
        if !self.is_r1_done() {
            return Err(CallerError::ProtocolNotReady.into());
        }

        let decom = self
            .local_storage
            .retrieve::<storage::Decommit<C>>(self.id())?;

        let broadcast_msgs = Message::new(
            MessageType::Keyrefresh(KeyrefreshMessageType::R2Decommit),
            self.sid,
            self.id,
            None,
            true,
            &decom,
        )?;

        Ok(vec![broadcast_msgs])
    }

    /// Handle the protocol's round two messages.
    ///
    /// Here we check that the decommitments from each participant are valid.
    #[cfg_attr(feature = "flame_it", flame("keyrefresh"))]
    #[instrument(skip_all, err(Debug))]
    fn handle_round_two_msg<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        broadcast_msg: &Message,
    ) -> Result<()> {
        info!("Handling round two keyrefresh message.");
        broadcast_msg.check_broadcast_message()?;

        // Check that the decommitment contained in the message is valid against
        // the previously received commitment and protocol rules.
        let com = self
            .local_storage
            .retrieve::<storage::Commit>(broadcast_msg.from())?;
        let decom = KeyrefreshDecommit::from_message(broadcast_msg, com, &self.all_participants())?;
        self.local_storage
            .store_once::<storage::Decommit<C>>(broadcast_msg.from(), decom)?;

        Ok(())
    }

    // Check if we've received all the decommits
    pub(crate) fn is_r2_done(&self) -> bool {
        // Check if we have received all round two messages.
        self.local_storage
            .contains_for_all_ids::<storage::Decommit<C>>(&self.all_participants())
    }

    /// Generate the protocol's round three messages.
    ///
    /// At this point, we have validated each participant's commitment, and can
    /// now proceed to constructing a Schnorr proof that this participant knows
    /// the private value corresponding to its public key share.
    #[cfg_attr(feature = "flame_it", flame("keyrefresh"))]
    #[instrument(skip_all, err(Debug))]
    fn gen_round_three_msgs<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
    ) -> Result<Vec<Message>> {
        info!("Generating round three keyrefresh messages.");
        if !self.is_r2_done() {
            return Err(CallerError::ProtocolNotReady.into());
        }

        // Construct `global rid` out of each participant's `rid`s.
        let my_rid = self
            .local_storage
            .retrieve::<storage::Decommit<C>>(self.id())?
            .rid;
        let rids: Vec<[u8; 32]> = self
            .other_ids()
            .iter()
            .map(|&other_participant_id| {
                let decom = self
                    .local_storage
                    .retrieve::<storage::Decommit<C>>(other_participant_id)?;
                Ok(decom.rid)
            })
            .collect::<Result<Vec<[u8; 32]>>>()?;
        let mut global_rid = my_rid;
        // xor all the rids together.
        for rid in rids.iter() {
            for i in 0..32 {
                global_rid[i] ^= rid[i];
            }
        }
        self.local_storage
            .store::<storage::GlobalRid>(self.id(), global_rid);

        let decom = self
            .local_storage
            .retrieve::<storage::Decommit<C>>(self.id())?;

        let transcript = schnorr_proof_transcript(self.sid(), &global_rid, self.id())?;

        // Generate proofs for each update.
        let precoms = self
            .local_storage
            .retrieve::<storage::VecSchnorrPrecom<C>>(self.id())?;

        let private_updates = self
            .local_storage
            .retrieve::<storage::PrivateUpdatesForOthers<C>>(self.id())?;

        let mut proofs: Vec<PiSchProof<C>> = vec![];
        for i in 0..precoms.len() {
            let pk = &decom.update_publics[i];
            let input = CommonInput::<C>::new(pk);
            let precom = &precoms[i];
            let sk = &private_updates[i];

            let proof = PiSchProof::prove_from_precommit(
                &self.retrieve_context(),
                precom,
                &input,
                &ProverSecret::new(sk.as_ref()),
                &transcript,
            )?;

            proofs.push(proof);
        }

        // Encrypt the private updates to each participant.
        let encrypted_updates = self
            .other_ids()
            .iter()
            .zip(private_updates.iter())
            .map(|(other_participant_id, update_private)| {
                let auxinfo = self.input.find_auxinfo_public(*other_participant_id)?;
                KeyUpdateEncrypted::encrypt(update_private, auxinfo.pk(), rng)
            })
            .collect::<Result<Vec<_>>>()?;

        let mut messages = Vec::new();

        // Broadcast all proofs
        messages.push(Message::new(
            MessageType::Keyrefresh(KeyrefreshMessageType::R3Proofs),
            self.sid(),
            self.id(),
            None,
            true,
            &proofs,
        )?);

        // Send their private updates to each individual participant.
        messages.extend(
            self.other_ids()
                .iter()
                .zip(encrypted_updates.iter())
                .map(|(other_participant_id, encrypted_update)| {
                    Message::new(
                        MessageType::Keyrefresh(KeyrefreshMessageType::R3PrivateUpdate),
                        self.sid(),
                        self.id(),
                        Some(*other_participant_id),
                        false,
                        encrypted_update,
                    )
                })
                .collect::<Result<Vec<Message>>>()?,
        );

        Ok(messages)
    }

    /// Handle round three messages only after our own `gen_round_three_msgs`.
    fn can_handle_round_three_msg(&self) -> bool {
        self.local_storage.contains::<storage::GlobalRid>(self.id())
    }

    /// Handle the protocol's round three public messages.
    ///
    /// Here we validate the Schnorr proofs from each participant.
    #[cfg_attr(feature = "flame_it", flame("keyrefresh"))]
    #[instrument(skip_all, err(Debug))]
    fn handle_round_three_msg(&mut self, message: &Message) -> Result<()> {
        info!("Handling round three keyrefresh broadcast message.");
        if !self.can_handle_round_three_msg() {
            info!("Not yet ready to handle round three keyrefresh broadcast message.");
            return Err(CallerError::ProtocolNotReady.into());
        }

        message.check_type(MessageType::Keyrefresh(KeyrefreshMessageType::R3Proofs))?;

        let global_rid = *self
            .local_storage
            .retrieve::<storage::GlobalRid>(self.id())?;

        let proofs = PiSchProof::from_message_multi(message)?;
        let decom = self
            .local_storage
            .retrieve::<storage::Decommit<C>>(message.from())?;

        // Check that there is one proof per participant.
        if proofs.len() != self.all_participants().len() {
            error!("Received incorrect number of proofs",);
            return Err(InternalError::ProtocolError(Some(message.from())));
        }

        for ((proof, precommit), update_public) in proofs
            .into_iter()
            .zip(decom.As.iter())
            .zip(decom.update_publics.iter())
        {
            let mut transcript = schnorr_proof_transcript(self.sid(), &global_rid, message.from())?;
            proof.verify_with_precommit(
                CommonInput::<C>::new(update_public),
                &self.retrieve_context(),
                &mut transcript,
                precommit,
            )?;
        }

        // Only if the proof verifies do we store the participant's updates.
        self.local_storage
            .store_once::<storage::ValidPublicUpdates<C>>(
                message.from(),
                decom.update_publics.clone(),
            )?;

        Ok(())
    }

    /// Handle the protocol's round three private messages.
    ///
    /// Here we validate and store a private update from someone to us.
    #[cfg_attr(feature = "flame_it", flame("keyrefresh"))]
    #[instrument(skip_all, err(Debug))]
    fn handle_round_three_msg_private(&mut self, message: &Message) -> Result<()> {
        info!("Handling round three keyrefresh private message.");
        if !self.can_handle_round_three_msg() {
            info!("Not yet ready to handle round three keyrefresh private message.");
            return Err(CallerError::ProtocolNotReady.into());
        }

        message.check_type(MessageType::Keyrefresh(
            KeyrefreshMessageType::R3PrivateUpdate,
        ))?;
        // 논문의 C_{i,j}
        let encrypted_update: KeyUpdateEncrypted<C> = deserialize!(&message.unverified_bytes)?;

        // Get my private key from the AuxInfo protocol.
        // 논문의 \rho_{j,i}
        let my_dk = self.input.private_auxinfo().decryption_key();

        // Decrypt the private update.
        // 논문의 x_{j,i}
        let update_private = encrypted_update.decrypt(my_dk)?;

        // Check that this private share matches our public share in KeyrefreshDecommit
        // from this participant.
        let implied_public = update_private.public_point()?;
        let decom = self
            .local_storage
            .retrieve::<storage::Decommit<C>>(message.from())?;
        let expected_public = decom
            .update_publics
            .iter()
            .find(|kup| kup.participant() == self.id())
            .ok_or(InternalError::InternalInvariantFailed)?
            .as_ref();
        if implied_public != *expected_public {
            error!("the private update does not match the public update");
            return Err(InternalError::ProtocolError(Some(message.from())));
        }

        self.local_storage
            .store::<storage::ValidPrivateUpdate<C>>(message.from(), update_private);

        Ok(())
    }

    /// Checks if all necessary messages for protocol completion have been received.
    pub(crate) fn is_r3_done(&self) -> bool {
        // Have we validated and stored the public updates from everybody to everybody?
        let got_all_public_updates = self
            .local_storage
            .contains_for_all_ids::<storage::ValidPublicUpdates<C>>(&self.all_participants());

        // Have we got the private updates from everybody to us?
        let got_all_private_updates = self
            .local_storage
            .contains_for_all_ids::<storage::ValidPrivateUpdate<C>>(&self.all_participants());
        got_all_public_updates && got_all_private_updates
    }

    /// Generate the protocol's output.
    fn gen_output(&mut self) -> Result<Output<C>> {
        // Check if we have all the necessary messages to produce an output.
        info!("Generating keyrefresh output.");
        if self.is_r3_done() {
            // Compute the update to the public key share of each participant.
            let from_all_to_all_public = self
                .all_participants()
                .iter()
                .map(|pid| {
                    self.local_storage
                        .remove::<storage::ValidPublicUpdates<C>>(*pid)
                })
                .collect::<Result<Vec<_>>>()?;
            let all_public_updates =
                Self::aggregate_public_updates(&self.all_participants(), &from_all_to_all_public)?;

            // Apply the updates to everybody's public key shares.
            let new_public_shares = self
                .input
                .public_key_shares()
                .iter()
                .map(|current_pk| {
                    let pk_update = all_public_updates
                        .iter()
                        .find(|update| update.participant() == current_pk.participant())
                        .ok_or(InternalError::InternalInvariantFailed)?;

                    Ok(pk_update.apply(current_pk))
                })
                .collect::<Result<Vec<_>>>()?;

            // Compute the update to one's own private key share.
            let from_all_to_me_private = self
                .all_participants()
                .iter()
                .map(|pid| {
                    self.local_storage
                        .remove::<storage::ValidPrivateUpdate<C>>(*pid)
                })
                .collect::<Result<Vec<_>>>()?;
            let my_private_update = Self::aggregate_private_updates(&from_all_to_me_private);

            // Apply the update to my private key share.
            let my_new_share = my_private_update.apply(self.input.private_key_share());

            // Return the output and stop.
            let rid_before = *self.input.keygen_output().rid();
            let output = Output::from_parts(new_public_shares, my_new_share, rid_before)?;

            // Final validation that the public key of the quorum has not changed. This
            // should never fail because this is already verified in round 2 by
            // `KeyrefreshDecommit::from_message`.
            let pk_before = self.input.keygen_output().public_key()?;
            let pk_after = output.public_key()?;
            if pk_before != pk_after {
                error!("Keyrefresh output did not preserve the quorum public key.");
                return Err(InternalError::InternalInvariantFailed);
            }

            Ok(output)
        } else {
            return Err(CallerError::ProtocolNotReady.into());
        }
    }

    fn aggregate_private_updates(update_privates: &[KeyUpdatePrivate<C>]) -> KeyUpdatePrivate<C> {
        KeyUpdatePrivate::sum(update_privates)
    }

    fn aggregate_public_updates(
        participants: &[ParticipantIdentifier],
        from_all_to_all: &[Vec<KeyUpdatePublic<C>>],
    ) -> Result<Vec<KeyUpdatePublic<C>>> {
        participants
            .iter()
            .map(|p_i| {
                let from_all_to_i = Self::find_updates_for_participant(*p_i, from_all_to_all)?;

                let sum_for_i = KeyUpdatePublic::sum(*p_i, &from_all_to_i);
                Ok(sum_for_i)
            })
            .collect()
    }

    fn find_updates_for_participant(
        p_i: ParticipantIdentifier,
        from_all_to_all: &[Vec<KeyUpdatePublic<C>>],
    ) -> Result<Vec<KeyUpdatePublic<C>>> {
        let from_all_to_i = from_all_to_all
            .iter()
            .map(|from_j_to_all| {
                let from_j_to_i = from_j_to_all
                    .iter()
                    .find(|from_j_to_x| from_j_to_x.participant() == p_i)
                    .cloned()
                    .ok_or(InternalError::InternalInvariantFailed);
                from_j_to_i
            })
            .collect();
        from_all_to_i
    }
}

/// Generate a [`Transcript`] for [`PiSchProof`].
fn schnorr_proof_transcript(
    sid: Identifier,
    global_rid: &[u8; 32],
    sender_id: ParticipantIdentifier,
) -> Result<Transcript> {
    let mut transcript = Transcript::new(b"keyrefresh schnorr");
    transcript.append_message(b"sid", &serialize!(&sid)?);
    transcript.append_message(b"rid", &serialize!(global_rid)?);
    transcript.append_message(b"sender_id", &serialize!(&sender_id)?);
    Ok(transcript)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        auxinfo, curve::TestCurve, k256::K256, keygen, keyrefresh::input::Input,
        utils::testing::init_testing, Identifier, ParticipantConfig,
    };
    use rand::{CryptoRng, Rng, RngCore};
    use std::{
        collections::{HashMap, HashSet},
        iter::zip,
    };
    use tracing::debug;

    impl<C: CurveTrait> KeyrefreshParticipant<C> {
        pub fn new_quorum<R: RngCore + CryptoRng>(
            sid: Identifier,
            quorum_size: usize,
            rng: &mut R,
        ) -> Result<Vec<Self>> {
            // Prepare prereqs for making KeyRefreshParticipant's. Assume all the
            // simulations are stable (e.g. keep config order)
            let configs = ParticipantConfig::random_quorum(quorum_size, rng)?;
            let keygen_outputs = keygen::Output::simulate_set(&configs, rng);
            let auxinfo_outputs = auxinfo::Output::simulate_set(&configs, rng);

            // Make the participants
            zip(configs, zip(keygen_outputs.clone(), auxinfo_outputs))
                .map(|(config, (keygen_output, auxinfo_output))| {
                    let input = Input::<C>::new(auxinfo_output, keygen_output)?;
                    Self::new(sid, config.id(), config.other_ids().to_vec(), input)
                })
                .collect::<Result<Vec<_>>>()
        }
    }

    #[cfg_attr(feature = "flame_it", flame)]
    #[test]
    fn keyrefresh_always_produces_valid_outputs() -> Result<()> {
        for size in 2..12 {
            keyrefresh_produces_valid_outputs(size)?;
        }
        Ok(())
    }

    fn keyrefresh_produces_valid_outputs(quorum_size: usize) -> Result<()> {
        let mut rng = init_testing();
        let sid = Identifier::random(&mut rng);
        let mut participants =
            KeyrefreshParticipant::<TestCurve>::new_quorum(sid, quorum_size, &mut rng)?;
        let all_pids: Vec<_> = participants.iter().map(|p| p.id()).collect();

        let inputs = participants
            .iter()
            .map(|p| p.input.clone())
            .collect::<Vec<_>>();

        // --- ROUND 1: Generate and deliver all R1 messages ---
        let mut round_1_inbox: HashMap<ParticipantIdentifier, Vec<Message>> =
            participants.iter().map(|p| (p.id(), Vec::new())).collect();

        for p in participants.iter_mut() {
            let mut broadcast_msgs = p.gen_round_one_msgs(&mut rng, sid)?;
            for other_p in p.other_participant_ids.iter() {
                broadcast_msgs[0].set_to(Some(*other_p));
                round_1_inbox
                    .get_mut(other_p)
                    .unwrap()
                    .push(broadcast_msgs[0].clone());
            }
        }

        // Each participant processes all R1 messages
        for p in participants.iter_mut() {
            for msg in round_1_inbox.get(&p.id()).unwrap() {
                p.handle_round_one_msg(&mut rng, msg.clone())?;
            }
        }

        // Check if all participants have completed round one
        assert!(participants.iter().all(|p| p.is_r1_done()));

        // --- ROUND 2: Generate and deliver all R2 messages ---
        let mut round_2_inbox: HashMap<ParticipantIdentifier, Vec<Message>> =
            participants.iter().map(|p| (p.id(), Vec::new())).collect();

        for p in participants.iter_mut() {
            let mut broadcast_msgs = p.gen_round_two_msgs(&mut rng, sid)?;
            for other_p in p.other_participant_ids.iter() {
                broadcast_msgs[0].set_to(Some(*other_p));
                round_2_inbox
                    .get_mut(other_p)
                    .unwrap()
                    .push(broadcast_msgs[0].clone());
            }
        }

        // Each participant processes all R2 messages
        for p in participants.iter_mut() {
            for msg in round_2_inbox.get(&p.id()).unwrap() {
                p.handle_round_two_msg(&mut rng, &msg)?;
            }
        }

        // Check if all participants have completed round two
        assert!(participants.iter().all(|p| p.is_r2_done()));

        // --- ROUND 3: Generate and deliver all R3 messages ---
        let mut round_3_inbox: HashMap<ParticipantIdentifier, Vec<Message>> =
            participants.iter().map(|p| (p.id(), Vec::new())).collect();

        for p in participants.iter_mut() {
            let mut messages = p.gen_round_three_msgs(&mut rng)?;
            for msg in messages.iter() {
                if msg.check_is_broadcast() {
                    for other_p in p.other_participant_ids.iter() {
                        let mut broadcast_msg = msg.clone();
                        broadcast_msg.set_to(Some(*other_p));
                        round_3_inbox.get_mut(other_p).unwrap().push(broadcast_msg);
                    }
                } else {
                    let to = msg.to().ok_or(InternalError::InternalInvariantFailed)?;
                    round_3_inbox.get_mut(&to).unwrap().push(msg.clone());
                }
            }
        }

        // Each participant processes all R3 messages
        for p in participants.iter_mut() {
            for msg in round_3_inbox.get(&p.id()).unwrap() {
                if msg.check_is_broadcast() {
                    p.handle_round_three_msg(&msg)?;
                } else {
                    p.handle_round_three_msg_private(&msg)?;
                }
            }
        }

        // Check if all participants have completed round three
        assert!(participants.iter().all(|p| p.is_r3_done()));

        let mut outputs = Vec::new();
        for p in participants.iter_mut() {
            if let Ok(output) = p.gen_output() {
                outputs.push(output);
            } else {
                warn!("Participant {} failed to generate output", p.id());
            }
        }
        assert_eq!(outputs.len(), quorum_size);

        // Check returned outputs
        //
        // Every participant should have a public output from every other participant
        // and, for a given participant, they should be the same in every output
        for party in participants.iter_mut() {
            let pid = party.id();

            // Collect the KeySharePublic associated with pid from every output
            let mut publics_for_pid = vec![];
            for output in &outputs {
                let key_share = output
                    .public_key_shares()
                    .iter()
                    .find(|key_share| key_share.participant() == pid);

                // Make sure every participant had a key share for this pid
                assert!(key_share.is_some());
                publics_for_pid.push(key_share.unwrap());
            }

            // Make sure they're all equal
            assert!(publics_for_pid.windows(2).all(|pks| pks[0] == pks[1]));
        }

        // Check that each participant's own `PublicKeyshare` corresponds to their
        // `PrivateKeyshare`
        for (output, pid) in outputs
            .iter()
            .zip(participants.iter().map(ProtocolParticipant::id))
        {
            let public_share = output
                .public_key_shares()
                .iter()
                .find(|public_share| public_share.participant() == pid);
            assert!(public_share.is_some());

            let expected_public_share =
                TestCurve::GENERATOR.multiply_by_bignum(output.private_key_share().as_ref())?;
            assert_eq!(public_share.unwrap().as_ref(), &expected_public_share);
        }

        for (input, output) in inputs.iter().zip(outputs.iter()) {
            // The public key of the quorum has not changed.
            let pk_before = input.keygen_output().public_key()?;
            let pk_after = output.public_key()?;
            assert_eq!(pk_before, pk_after);

            // All key shares have changed.
            let public_shares_before = input
                .public_key_shares()
                .iter()
                .map(|key_share| serialize!(key_share.as_ref()).unwrap())
                .collect::<HashSet<_>>();

            let public_shares_after = output
                .public_key_shares()
                .iter()
                .map(|key_share| serialize!(key_share.as_ref()).unwrap())
                .collect::<HashSet<_>>();

            public_shares_before
                .intersection(&public_shares_after)
                .for_each(|_| {
                    panic!("All public key shares must change.");
                });

            // The rid has not changed.
            assert_eq!(input.keygen_output().rid(), output.rid());
        }

        Ok(())
    }
}
