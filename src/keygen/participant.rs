//! Types and functions related to the key generation sub-protocol Participant.

// Copyright (c) Facebook, Inc. and its affiliates.
// Modifications Copyright (c) 2022-2023 Bolt Labs Holdings, Inc
// Modifications Copyright (c) 2025 SnP Labs
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use std::{marker::PhantomData, sync::BarrierWaitResult};

use crate::{
    curve::CurveTrait,
    errors::{CallerError, Result},
    keygen::{
        keygen_commit::{KeygenCommit, KeygenDecommit},
        KeySharePublic, Output,
    },
    local_storage::LocalStorage,
    messages::{KeygenMessageType, Message, MessageType},
    participant::{InnerProtocolParticipant, ProcessOutcome, ProtocolParticipant},
    protocol::{ProtocolType, SharedContext},
    zkp::pisch::{CommonInput, PiSchProof, ProverSecret},
    Identifier, ParticipantIdentifier,
};
use hmac::digest::Key;
use merlin::Transcript;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use tracing::{error, info, instrument, warn};

mod storage {
    use super::*;
    use crate::{
        keygen::{
            keygen_commit::{KeygenCommit, KeygenDecommit},
            KeySharePrivate, KeySharePublic,
        },
        local_storage::TypeTag,
        zkp::pisch::PiSchPrecommit,
    };

    pub(super) struct Commit;
    impl TypeTag for Commit {
        type Value = KeygenCommit;
    }
    pub(super) struct Decommit<C>(PhantomData<C>);
    impl<C: Send + Sync + 'static> TypeTag for Decommit<C> {
        type Value = KeygenDecommit<C>;
    }
    pub(super) struct SchnorrPrecom<C>(PhantomData<C>);
    impl<C: Send + Sync + 'static> TypeTag for SchnorrPrecom<C> {
        type Value = PiSchPrecommit<C>;
    }
    pub(super) struct GlobalRid;
    impl TypeTag for GlobalRid {
        type Value = [u8; 32];
    }
    pub(super) struct PrivateKeyshare<C>(PhantomData<C>);
    impl<C: Send + Sync + 'static> TypeTag for PrivateKeyshare<C> {
        type Value = KeySharePrivate<C>;
    }
    pub(super) struct PublicKeyshare<C>(PhantomData<C>);
    impl<C: Send + Sync + 'static> TypeTag for PublicKeyshare<C> {
        type Value = KeySharePublic<C>;
    }
}

#[derive(Debug, Default)]
pub struct KeygenParticipant<C: CurveTrait> {
    /// The current session identifier
    sid: Identifier,
    /// A unique identifier for this participant.
    id: ParticipantIdentifier,
    /// A list of all other participant identifiers participating in the
    /// protocol
    other_participant_ids: Vec<ParticipantIdentifier>,
    /// Local storage for this participant to store secrets
    local_storage: LocalStorage,
    _curve: PhantomData<C>,
}

impl<C: CurveTrait> ProtocolParticipant for KeygenParticipant<C> {
    type Input = ();

    type Output = Output<C>;

    fn protocol_type() -> ProtocolType {
        ProtocolType::Keygen
    }

    fn new(
        sid: Identifier,
        id: ParticipantIdentifier,
        other_participant_ids: Vec<ParticipantIdentifier>,
        input: Self::Input,
    ) -> crate::errors::Result<Self>
    where
        Self: Sized,
    {
        Ok(Self {
            sid,
            id,
            other_participant_ids,
            local_storage: Default::default(),
            _curve: PhantomData,
        })
    }

    fn id(&self) -> ParticipantIdentifier {
        self.id
    }

    fn other_ids(&self) -> &[ParticipantIdentifier] {
        &self.other_participant_ids
    }

    fn process_message<R: rand::RngCore + rand::CryptoRng>(
        &mut self,
        rng: &mut R,
        message: &crate::messages::Message,
    ) -> Result<ProcessOutcome<Self::Output>> {
        info!(
            "KEYGEN: Player {}: received {:?} from {}",
            self.id(),
            message.message_type(),
            message.from()
        );

        match message.message_type() {
            MessageType::Keygen(KeygenMessageType::Ready) => {
                let res = self.gen_round_one_msgs(rng, self.sid());
                if let Err(e) = res {
                    error!("Failed to generate round one messages: {:?}", e);
                    return Err(e);
                } else {
                    let msgs = res.unwrap();
                    info!(
                        "KEYGEN: Player {}: generated round one message {:?}",
                        self.id(),
                        msgs
                    );
                    return Ok(ProcessOutcome::Continue(msgs));
                }
            }
            MessageType::Keygen(KeygenMessageType::R1CommitHash) => {
                self.handle_round_one_msg(rng, message.clone())?;
                let is_r1_done = self.is_r1_done();

                if is_r1_done {
                    info!("KEYGEN: Player {}: round one done", self.id());
                    let res = self.gen_round_two_msgs(rng, self.sid());
                    if let Err(e) = res {
                        error!("Failed to generate round two messages: {:?}", e);
                        return Err(e);
                    } else {
                        let msgs = res.unwrap();
                        info!(
                            "KEYGEN: Player {}: generated round two message {:?}",
                            self.id(),
                            msgs
                        );
                        return Ok(ProcessOutcome::Continue(msgs));
                    }
                } else {
                    info!(
                        "KEYGEN: Player {}: still waiting for round one messages",
                        self.id()
                    );
                    return Ok(ProcessOutcome::Continue(vec![]));
                }
            }
            MessageType::Keygen(KeygenMessageType::R2Decommit) => {
                self.handle_round_two_msg(message)?;
                let is_r2_done = self.is_r2_done();
                if is_r2_done {
                    info!("KEYGEN: Player {}: round two done", self.id());
                    let res = self.gen_round_three_msgs();
                    if let Err(e) = res {
                        error!("Failed to generate round three messages: {:?}", e);
                        return Err(e);
                    } else {
                        let msgs = res.unwrap();
                        info!(
                            "KEYGEN: Player {}: generated round three message {:?}",
                            self.id(),
                            msgs
                        );
                        return Ok(ProcessOutcome::Continue(msgs));
                    }
                } else {
                    info!(
                        "KEYGEN: Player {}: still waiting for round two messages",
                        self.id()
                    );
                    return Ok(ProcessOutcome::Continue(vec![]));
                }
            }
            MessageType::Keygen(KeygenMessageType::R3Proof) => {
                self.handle_round_three_msg(message)?;
                let is_r3_done = self.is_r3_done();
                if is_r3_done {
                    info!("KEYGEN: Player {}: round three done", self.id());
                    let res = self.gen_output();
                    if let Err(e) = res {
                        error!("Failed to generate output: {:?}", e);
                        return Err(e);
                    } else {
                        let output = res.unwrap();
                        info!(
                            "KEYGEN: Player {}: generated output {:?}",
                            self.id(),
                            output
                        );
                        return Ok(ProcessOutcome::Done(output));
                    }
                } else {
                    info!(
                        "KEYGEN: Player {}: still waiting for round three messages",
                        self.id()
                    );
                    return Ok(ProcessOutcome::Continue(vec![]));
                }
            }
            _ => {
                error!(
                    "KEYGEN: Player {}: received unexpected message type {:?}",
                    self.id(),
                    message.message_type()
                );
                return Err(CallerError::WrongProtocol.into());
            }
        }
    }

    fn sid(&self) -> Identifier {
        self.sid
    }

    fn ready_type() -> MessageType {
        MessageType::Keygen(KeygenMessageType::Ready)
    }
}

impl<C: CurveTrait> InnerProtocolParticipant for KeygenParticipant<C> {
    type Context = SharedContext<C>;

    fn retrieve_context(&self) -> Self::Context {
        SharedContext::collect(self)
    }

    fn local_storage(&self) -> &LocalStorage {
        &self.local_storage
    }

    fn local_storage_mut(&mut self) -> &mut LocalStorage {
        &mut self.local_storage
    }
}

impl<C: CurveTrait> KeygenParticipant<C> {
    /// Generate the protocol's round one message.
    ///
    /// The outcome is a broadcast message containing a commitment to: (1) this
    /// participant's [`KeySharePublic`] and (2) a "pre-commitment" to a Schnorr
    /// proof.
    #[cfg_attr(feature = "flame_it", flame("keygen"))]
    #[instrument(skip_all, err(Debug))]
    pub(crate) fn gen_round_one_msgs<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        sid: Identifier,
    ) -> Result<Vec<Message>> {
        info!("Generating round one keygen messages.");

        let (keyshare_private, keyshare_public) = KeySharePublic::new_keyshare(self.id(), rng)?;

        // This corresponds to `A_i` in the paper.
        let sch_precom = PiSchProof::precommit(rng)?;
        let decom = KeygenDecommit::new(rng, &sid, &self.id, &keyshare_public, &sch_precom);
        // This corresponds to `V_i` in the paper.
        let com = decom.commit()?;

        self.local_storage
            .store::<storage::Commit>(self.id, com.clone());
        self.local_storage
            .store::<storage::Decommit<C>>(self.id, decom);
        self.local_storage
            .store::<storage::SchnorrPrecom<C>>(self.id, sch_precom);

        self.local_storage
            .store::<storage::PrivateKeyshare<C>>(self.id, keyshare_private);
        self.local_storage
            .store::<storage::PublicKeyshare<_>>(self.id, keyshare_public);

        let message = Message::new(
            MessageType::Keygen(KeygenMessageType::R1CommitHash),
            self.sid,
            self.id,
            None,
            true,
            &com,
        )?;
        Ok(vec![message])
    }

    /// Handle round one messages from the protocol participants.
    ///
    /// In round one, each participant broadcasts its commitment to its public
    /// key share and a "precommitment" to a Schnorr proof. Once all such
    /// commitments have been received, this participant will send an opening of
    /// its own commitment to all other parties.
    #[cfg_attr(feature = "flame_it", flame("keygen"))]
    #[instrument(skip_all, err(Debug))]
    fn handle_round_one_msg<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        broadcast_msg: Message,
    ) -> Result<()> {
        info!("Handling round one keygen message.");
        broadcast_msg.check_broadcast_message()?;

        let keygen_commit = KeygenCommit::from_message(&broadcast_msg)?;
        self.local_storage
            .store_once::<storage::Commit>(broadcast_msg.from(), keygen_commit)?;

        Ok(())
    }

    /// Check if the participant has received all round one messages
    pub(crate) fn is_r1_done(&self) -> bool {
        // todo: 중앙 서버 모델에서는 self.all_participants()를 사용해도 될지도?
        self.local_storage
            .contains_for_all_ids::<storage::Commit>(&self.other_participant_ids)
    }

    /// Generate the protocol's round two messages.
    ///
    /// The outcome is an opening to the commitment generated in round one.
    #[cfg_attr(feature = "flame_it", flame("keygen"))]
    #[instrument(skip_all, err(Debug))]
    pub(crate) fn gen_round_two_msgs<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        sid: Identifier,
    ) -> Result<Vec<Message>> {
        info!("Generating round two keygen messages.");

        if !self.is_r1_done() {
            error!("Cannot generate round two messages before round one is complete.");
            return Err(CallerError::ProtocolNotReady.into());
        }

        let decom = self
            .local_storage
            .retrieve::<storage::Decommit<C>>(self.id)?;

        let broadcast_msg = Message::new(
            MessageType::Keygen(KeygenMessageType::R2Decommit),
            self.sid,
            self.id,
            None,
            true,
            &decom,
        )?;
        Ok(vec![broadcast_msg])
    }

    #[cfg_attr(feature = "flame_it", flame("keygen"))]
    #[instrument(skip_all, err(Debug))]
    pub fn handle_round_two_msg(&mut self, broadcast_msg: &Message) -> Result<()> {
        info!("Handling round two keygen message.");

        broadcast_msg.check_broadcast_message()?;
        // Check that the decommitment contained in the message is valid for the
        // previously received commitment.
        let com = self
            .local_storage
            .retrieve::<storage::Commit>(broadcast_msg.from())?;
        let decom = KeygenDecommit::from_message(broadcast_msg, com)?;

        self.local_storage
            .store_once::<storage::Decommit<C>>(broadcast_msg.from(), decom)?;

        Ok(())
    }

    pub(crate) fn is_r2_done(&self) -> bool {
        self.local_storage
            .contains_for_all_ids::<storage::Decommit<C>>(&self.all_participants())
    }

    /// Generate the protocol's round three messages.
    ///
    /// At this point, we have validated each participant's commitment, and can
    /// now proceed to constructing a Schnorr proof that this participant knows
    /// the private value corresponding to its public key share.
    #[cfg_attr(feature = "flame_it", flame("keygen"))]
    #[instrument(skip_all, err(Debug))]
    pub(crate) fn gen_round_three_msgs(&mut self) -> Result<Vec<Message>> {
        info!("Generating round three keygen messages.");

        if !self.is_r2_done() {
            error!("Cannot generate round three messages before round two is complete.");
            return Err(CallerError::ProtocolNotReady.into());
        }

        let my_decom = self
            .local_storage
            .retrieve::<storage::Decommit<C>>(self.id)?;

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

        let mut global_rid = my_decom.rid;
        for &other_participant_id in self.other_participant_ids.iter() {
            let decom = self
                .local_storage
                .retrieve::<storage::Decommit<C>>(other_participant_id)?;
            global_rid = xor_256_bits!(global_rid, decom.rid);
        }

        self.local_storage
            .store::<storage::GlobalRid>(self.id, global_rid);
        let transcript = schnorr_proof_transcript(self.sid(), &global_rid, self.id())?;

        let precom = self
            .local_storage
            .retrieve::<storage::SchnorrPrecom<C>>(self.id)?;

        let my_pk = self
            .local_storage
            .retrieve::<storage::PublicKeyshare<C>>(self.id)?;
        let input = CommonInput::<C>::new(my_pk);

        let my_sk = self
            .local_storage
            .retrieve::<storage::PrivateKeyshare<C>>(self.id)?;

        let proof = PiSchProof::prove_from_precommit(
            &self.retrieve_context(),
            precom,
            &input,
            &ProverSecret::new(my_sk.as_ref()),
            &transcript,
        )?;

        let broadcast_msg = Message::new(
            MessageType::Keygen(KeygenMessageType::R3Proof),
            self.sid(),
            self.id,
            None,
            true,
            &proof,
        )?;

        Ok(vec![broadcast_msg])
    }

    /// Handle the protocol's round three messages.
    ///
    /// Here we validate the Schnorr proofs from each participant. If these
    /// pass, then we are assured that all public key shares are valid, and we
    /// can terminate the protocol by outputting these alongside this
    /// participant's own private key share.
    #[cfg_attr(feature = "flame_it", flame("keygen"))]
    #[instrument(skip_all, err(Debug))]
    fn handle_round_three_msg(&mut self, broadcast_msg: &Message) -> Result<()> {
        info!("Handling round three keygen message.");
        broadcast_msg.check_broadcast_message()?;

        let proof = PiSchProof::<C>::from_message(broadcast_msg)?;
        let global_rid = *self.local_storage.retrieve::<storage::GlobalRid>(self.id)?;
        let decom = self
            .local_storage
            .retrieve::<storage::Decommit<C>>(broadcast_msg.from())?;
        let precommit = &decom.A;

        let input = CommonInput::<C>::new(&decom.pk);

        let mut transcript =
            schnorr_proof_transcript(self.sid(), &global_rid, broadcast_msg.from())?;
        proof.verify_with_precommit(input, &self.retrieve_context(), &mut transcript, precommit)?;

        // Only if the proof verifies do we store the participant's public key
        // share. This signals the end of the protocol for the participant.
        let keyshare = decom.get_keyshare();
        self.local_storage
            .store_once::<storage::PublicKeyshare<_>>(broadcast_msg.from(), keyshare.clone())?;

        Ok(())
    }

    pub(crate) fn is_r3_done(&self) -> bool {
        //check if we've stored all the public keyshares
        self.local_storage
            .contains_for_all_ids::<storage::PublicKeyshare<C>>(&self.all_participants())
    }

    #[cfg_attr(feature = "flame_it", flame("keygen"))]
    #[instrument(skip_all, err(Debug))]
    fn gen_output(&mut self) -> Result<Output<C>> {
        info!("Generating keygen output.");
        if self.is_r3_done() {
            let public_key_shares = self
                .all_participants()
                .iter()
                .map(|pid| {
                    self.local_storage
                        .remove::<storage::PublicKeyshare<_>>(*pid)
                })
                .collect::<Result<Vec<_>>>()?;
            let private_key_share = self
                .local_storage
                .remove::<storage::PrivateKeyshare<C>>(self.id)?;

            let global_rid = *self.local_storage.retrieve::<storage::GlobalRid>(self.id)?;

            let output = Output::from_parts(public_key_shares, private_key_share, global_rid)?;
            Ok(output)
        } else {
            Err(CallerError::ProtocolNotReady)?
        }
    }
}

/// Generate a [`Transcript`] for [`PiSchProof`].
fn schnorr_proof_transcript(
    sid: Identifier,
    global_rid: &[u8; 32],
    sender_id: ParticipantIdentifier,
) -> Result<Transcript> {
    let mut transcript = Transcript::new(b"keygen schnorr");
    transcript.append_message(b"sid", &serialize!(&sid)?);
    transcript.append_message(b"rid", &serialize!(global_rid)?);
    transcript.append_message(b"sender_id", &serialize!(&sender_id)?);
    Ok(transcript)
}
#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::{
        curve::TestCurve as C, utils::testing::init_testing, Identifier, ParticipantConfig,
    };
    use rand::{CryptoRng, Rng, RngCore};
    use std::collections::HashMap;
    use tracing::debug;

    impl KeygenParticipant<C> {
        pub fn new_quorum<R: RngCore + CryptoRng>(
            sid: Identifier,
            quorum_size: usize,
            rng: &mut R,
        ) -> Result<Vec<Self>> {
            ParticipantConfig::random_quorum(quorum_size, rng)?
                .into_iter()
                .map(|config| Self::new(sid, config.id(), config.other_ids().to_vec(), ()))
                .collect::<Result<Vec<_>>>()
        }
    }

    fn is_keygen_done(quorum: &[KeygenParticipant<C>]) -> bool {
        for participant in quorum {
            if !participant.is_r3_done() {
                debug!("Participant {} is not done with keygen", participant.id());
                return false;
            } else {
                debug!("Participant {} is done with keygen", participant.id());
            }
        }
        true
    }

    #[cfg_attr(feature = "flame_it", flame)]
    #[test]
    // This test is cheap. Try a bunch of message permutations to decrease error
    // likelihood
    fn keygen_always_produces_valid_outputs() -> Result<()> {
        for _ in 0..30 {
            keygen_produces_valid_outputs()?;
        }
        Ok(())
    }

    #[test]
    fn keygen_produces_valid_outputs() -> Result<()> {
        let QUORUM_SIZE = 3;
        let mut rng = init_testing();
        let sid = Identifier::random(&mut rng);
        let mut participants = KeygenParticipant::new_quorum(sid, QUORUM_SIZE, &mut rng)?;
        let all_pids: Vec<_> = participants.iter().map(|p| p.id()).collect();

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
                p.handle_round_two_msg(&msg)?;
            }
        }

        // Check if all participants have completed round two
        assert!(participants.iter().all(|p| p.is_r2_done()));

        // --- ROUND 3: Generate and deliver all R3 messages ---
        let mut round_3_inbox: HashMap<ParticipantIdentifier, Vec<Message>> =
            participants.iter().map(|p| (p.id(), Vec::new())).collect();

        for p in participants.iter_mut() {
            let mut broadcast_msgs = p.gen_round_three_msgs()?;
            for other_p in p.other_participant_ids.iter() {
                broadcast_msgs[0].set_to(Some(*other_p));
                round_3_inbox
                    .get_mut(other_p)
                    .unwrap()
                    .push(broadcast_msgs[0].clone());
            }
        }

        // Each participant processes all R3 messages
        for p in participants.iter_mut() {
            for msg in round_3_inbox.get(&p.id()).unwrap() {
                p.handle_round_three_msg(&msg)?;
            }
        }

        // Check if all participants have completed round three
        assert!(participants.iter().all(|p| p.is_r3_done()));

        // --- FINALIZE: Generate outputs for all participants ---
        let mut outputs = Vec::new();
        for p in participants.iter_mut() {
            if let Ok(output) = p.gen_output() {
                outputs.push(output);
            } else {
                warn!("Participant {} failed to generate output", p.id());
            }
        }

        // Make sure every player got an output
        assert_eq!(outputs.len(), QUORUM_SIZE);

        // Check returned outputs
        //
        // Every participant should have a public output from every other participant
        // and, for a given participant, they should be the same in every output
        for &pid_to_check in &all_pids {
            let publics_for_pid: Vec<_> = outputs
                .iter()
                .map(|output| {
                    output
                        .public_key_shares()
                        .iter()
                        .find(|key_share| key_share.participant() == pid_to_check)
                        .expect("Every participant should have a public output from every other participant")
                })
                .collect();

            // Assert that all collected public key shares are identical
            assert!(
                publics_for_pid.windows(2).all(|pks| pks[0] == pks[1]),
                "All collected public key shares must be identical"
            );
        }

        // Check that each participant's own `PublicKeyshare` corresponds to their `PrivateKeyshare`
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
                C::GENERATOR.multiply_by_bignum(output.private_key_share().as_ref())?;
            assert_eq!(public_share.unwrap().as_ref(), &expected_public_share);
        }

        // Check that every participant has the same `rid` value
        assert!(outputs
            .windows(2)
            .all(|outputs| outputs[0].rid() == outputs[1].rid()));

        Ok(())
    }
}
