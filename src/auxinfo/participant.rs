//! Types and functions related to generate auxiliary information sub-protocol
//! Participant.

// Copyright (c) Facebook, Inc. and its affiliates.
// Modifications Copyright (c) 2022-2023 Bolt Labs Holdings, Inc
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use crate::{
    auxinfo::{
        auxinfo_commit::{Commitment, CommitmentScheme},
        info::{AuxInfoPrivate, AuxInfoPublic, AuxInfoWitnesses},
        proof::{AuxInfoProof, CommonInput},
        Output,
    },
    curve::CurveTrait,
    errors::{CallerError, InternalError, Result},
    local_storage::LocalStorage,
    messages::{AuxinfoMessageType, Message, MessageType},
    paillier::DecryptionKey,
    participant::{InnerProtocolParticipant, ProcessOutcome, ProtocolParticipant},
    protocol::{Identifier, ParticipantIdentifier, ProtocolType, SharedContext},
    ring_pedersen::VerifiedRingPedersen,
};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;
use tracing::{debug, error, info, instrument};

// Local storage data types.
mod storage {
    use super::*;
    use crate::local_storage::TypeTag;

    pub(super) struct Private;
    impl TypeTag for Private {
        type Value = AuxInfoPrivate;
    }
    pub(super) struct Public;
    impl TypeTag for Public {
        type Value = AuxInfoPublic;
    }
    pub(super) struct Commit;
    impl TypeTag for Commit {
        type Value = Commitment;
    }
    pub(super) struct Decommit<C: CurveTrait> {
        _phantom: std::marker::PhantomData<C>,
    }
    impl<C: CurveTrait> TypeTag for Decommit<C> {
        type Value = CommitmentScheme<C>;
    }
    pub(super) struct GlobalRid;
    impl TypeTag for GlobalRid {
        type Value = [u8; 32];
    }
    pub(super) struct Witnesses;
    impl TypeTag for Witnesses {
        type Value = AuxInfoWitnesses;
    }
}

/// A [`ProtocolParticipant`] that runs the auxiliary information
/// protocol.
///
/// # Protocol input
/// The protocol takes no input.
///
/// # Protocol output
/// Upon succesful completion, the participant outputs the following:
/// - A [`Vec`] of [`AuxInfoPublic`]s, which correspond to the public auxiliary
///   information of each participant (including this participant), and
/// - A single [`AuxInfoPrivate`], which corresponds to the **private**
///   auxiliary information of this participant.
///
/// # 🔒 Storage requirements
/// The [`AuxInfoPrivate`] output requires secure persistent storage.
#[derive(Debug, Default)]
pub struct AuxInfoParticipant<C: CurveTrait> {
    /// The current session identifier
    sid: Identifier,
    /// A unique identifier for this participant
    id: ParticipantIdentifier,
    /// A list of all other participant identifiers participating in the
    /// protocol
    other_participant_ids: Vec<ParticipantIdentifier>,
    /// Local storage for this participant to store secrets
    local_storage: LocalStorage,
    _curve: PhantomData<C>,
}

impl<C: CurveTrait> ProtocolParticipant for AuxInfoParticipant<C> {
    type Input = ();
    // The output type includes `AuxInfoPublic` material for all participants
    // (including ourselves) and `AuxInfoPrivate` for ourselves.
    type Output = Output;

    fn new(
        sid: Identifier,
        id: ParticipantIdentifier,
        other_participant_ids: Vec<ParticipantIdentifier>,
        input: Self::Input,
    ) -> Result<Self> {
        Ok(Self {
            sid,
            id,
            other_participant_ids: other_participant_ids.clone(),
            local_storage: Default::default(),
            _curve: PhantomData,
        })
    }

    fn ready_type() -> MessageType {
        MessageType::Auxinfo(AuxinfoMessageType::Ready)
    }

    fn protocol_type() -> ProtocolType {
        ProtocolType::AuxInfo
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

    #[cfg_attr(feature = "flame_it", flame("auxinfo"))]
    #[instrument(skip_all, err(Debug))]
    fn process_message<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        message: &Message,
    ) -> Result<ProcessOutcome<Self::Output>> {
        info!("Processing auxinfo message.");

        match message.message_type() {
            MessageType::Auxinfo(AuxinfoMessageType::Ready) => {
                let res = self.gen_round_one_msgs(rng, self.sid);
                if let Err(e) = res {
                    error!("Failed to generate round one messages: {:?}", e);
                    return Err(e);
                } else {
                    let msgs = res.unwrap();
                    info!(
                        "AUXINFO: Player {} generated round one message: {:?}",
                        self.id, msgs
                    );
                    return Ok(ProcessOutcome::Continue(msgs));
                }
            }
            MessageType::Auxinfo(AuxinfoMessageType::R1CommitHash) => {
                self.handle_round_one_msg(message.clone())?;
                let is_r1_done = self.is_r1_done();

                if is_r1_done {
                    info!("AUXINFO: Player {} completed round one.", self.id);
                    let res = self.gen_round_two_msgs(self.sid);
                    if let Err(e) = res {
                        error!("Failed to generate round two messages: {:?}", e);
                        return Err(e);
                    } else {
                        let msgs = res.unwrap();
                        info!(
                            "AUXINFO: Player {} generated round two message: {:?}",
                            self.id, msgs
                        );
                        return Ok(ProcessOutcome::Continue(msgs));
                    }
                } else {
                    info!(
                        "AUXINFO: Player {}: still waiting for round one messages",
                        self.id
                    );
                    return Ok(ProcessOutcome::Continue(vec![]));
                }
            }
            MessageType::Auxinfo(AuxinfoMessageType::R2Decommit) => {
                self.handle_round_two_msg(message)?;
                let is_r2_done = self.is_r2_done();

                if is_r2_done {
                    info!("AUXINFO: Player {}: round two done", self.id());
                    let res = self.gen_round_three_msgs(rng, self.sid);
                    if let Err(e) = res {
                        error!("Failed to generate round three messages: {:?}", e);
                        return Err(e);
                    } else {
                        let msgs = res.unwrap();
                        info!(
                            "AUXINFO: Player {} generated round three messages: {:?}",
                            self.id, msgs
                        );
                        return Ok(ProcessOutcome::Continue(msgs));
                    }
                } else {
                    info!(
                        "AUXINFO: Player {}: still waiting for round two messages",
                        self.id
                    );
                    return Ok(ProcessOutcome::Continue(vec![]));
                }
            }
            MessageType::Auxinfo(AuxinfoMessageType::R3Proof) => {
                self.handle_round_three_msg(message)?;
                let is_r3_done = self.is_r3_done();

                if is_r3_done {
                    info!("AUXINFO: Player {}: round three done", self.id());
                    let res = self.gen_output();
                    if let Err(e) = res {
                        error!("Failed to generate auxinfo output: {:?}", e);
                        return Err(e);
                    } else {
                        let output = res.unwrap();
                        info!("AUXINFO: Player {} generated output: {:?}", self.id, output);
                        return Ok(ProcessOutcome::Done(output));
                    }
                } else {
                    info!(
                        "AUXINFO: Player {}: still waiting for round three messages",
                        self.id
                    );
                    return Ok(ProcessOutcome::Continue(vec![]));
                }
            }
            _ => {
                error!(
                    "AUXINFO: Player {}: received unexpected message type {:?}",
                    self.id,
                    message.message_type()
                );
                Err(CallerError::BadInput)?
            }
        }
    }
}

impl<C: CurveTrait> InnerProtocolParticipant for AuxInfoParticipant<C> {
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

impl<'a, C: CurveTrait> AuxInfoParticipant<C> {
    /// Generate the participant's round one message.
    ///
    /// This corresponds to the following lines in Round 1 of Figure 6:
    /// - Line 1: Sampling safe primes `p` and `q`.
    /// - Line 2: Generating the `𝚷[prm]` proof `\hat{ψ}_i`.
    /// - Line 6: Producing the hash commitment `V_i` on the above values.
    #[cfg_attr(feature = "flame_it", flame("auxinfo"))]
    #[instrument(skip_all, err(Debug))]
    fn gen_round_one_msgs<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        sid: Identifier,
    ) -> Result<Vec<Message>> {
        info!("Generating round one auxinfo messages.");
        // auxinfo_private: Paillier decryption key derived from p, q
        // auxinfo_public: Paillier encryption key, Pedersen parameters
        // auxinfo_witnesses: Paillier decryption key p, q (only used for proof generation)
        let (auxinfo_private, auxinfo_public, auxinfo_witnesses) = self.new_auxinfo(rng)?;
        self.local_storage
            .store::<storage::Private>(self.id, auxinfo_private);
        self.local_storage
            .store::<storage::Public>(self.id, auxinfo_public.clone());
        self.local_storage
            .store::<storage::Witnesses>(self.id, auxinfo_witnesses);

        let scheme = CommitmentScheme::new(sid, self, auxinfo_public, rng)?;
        let com = scheme.commit()?;

        self.local_storage
            .store::<storage::Commit>(self.id, com.clone());
        self.local_storage
            .store::<storage::Decommit<C>>(self.id, scheme);

        let messages = Message::new_from_serialized_data(
            MessageType::Auxinfo(AuxinfoMessageType::R1CommitHash),
            self.sid,
            self.id,
            None,
            true,
            serialize!(&com)?,
        )?;

        Ok(vec![messages])
    }

    /// Handle other participants' round one message.
    ///
    /// This message is a broadcast message containing the other participant's
    /// commitment to its [`AuxInfoPublic`] data. Once all such commitments have
    /// been received, we generate a round two message.
    #[cfg_attr(feature = "flame_it", flame("auxinfo"))]
    #[instrument(skip_all, err(Debug))]
    fn handle_round_one_msg(&mut self, broadcast_message: Message) -> Result<()> {
        broadcast_message.check_broadcast_message()?;
        info!("Handling round one auxinfo message.");

        let aux_commit = Commitment::from_message(&broadcast_message)?;

        self.local_storage
            .store_once::<storage::Commit>(broadcast_message.from(), aux_commit)?;

        Ok(())
    }

    pub(crate) fn is_r1_done(&self) -> bool {
        self.local_storage
            .contains_for_all_ids::<storage::Commit>(&self.other_participant_ids)
    }

    /// Generate this participant's round two message.
    ///
    /// This message is simply the decommitment to the commitment sent in round
    /// one.
    #[cfg_attr(feature = "flame_it", flame("auxinfo"))]
    #[instrument(skip_all, err(Debug))]
    fn gen_round_two_msgs(&mut self, sid: Identifier) -> Result<Vec<Message>> {
        info!("Generating round two auxinfo messages.");
        if !self.is_r1_done() {
            return Err(CallerError::ProtocolNotReady.into());
        }

        let decom = self
            .local_storage
            .retrieve::<storage::Decommit<C>>(self.id)?;

        let messages = Message::new(
            MessageType::Auxinfo(AuxinfoMessageType::R2Decommit),
            sid,
            self.id,
            None,
            true,
            &decom,
        )?;

        Ok(vec![messages])
    }

    /// Handle other participants' round two message.
    ///
    /// The message should correspond to a decommitment to the committed value
    /// from round one. This method checks the validity of that decommitment.
    /// Once (valid) decommitments from all other participants have been
    /// received, we proceed to generating round three messages.
    #[cfg_attr(feature = "flame_it", flame("auxinfo"))]
    #[instrument(skip_all, err(Debug))]
    fn handle_round_two_msg(&mut self, message: &Message) -> Result<()> {
        message.check_broadcast_message()?;
        info!("Handling round two auxinfo message.");

        // Convert the message into the decommitment value.
        //
        // Note: `AuxInfoDecommit::from_message` checks the validity of all its
        // messages, which includes validating the `𝚷[prm]` proof.
        let scheme = CommitmentScheme::from_message(message, &self.retrieve_context())?;
        let com = self
            .local_storage
            .retrieve::<storage::Commit>(message.from())?;
        scheme.verify(&message.id(), &message.from(), com)?;
        self.local_storage
            .store_once::<storage::Decommit<C>>(message.from(), scheme)?;

        Ok(())
    }

    pub(crate) fn is_r2_done(&self) -> bool {
        self.local_storage
            .contains_for_all_ids::<storage::Decommit<C>>(&self.all_participants())
    }

    /// Generate the participant's round three message.
    ///
    /// This corresponds to the following lines of Round 3 in Figure 6:
    ///
    /// - Step 2, Lines 1-2: Generate the `𝚷[mod]` and `𝚷[fac]` proofs.
    ///
    /// Note that Step 1 is handled in `handle_round_two_msg`.
    #[cfg_attr(feature = "flame_it", flame("auxinfo"))]
    #[instrument(skip_all, err(Debug))]
    fn gen_round_three_msgs<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        sid: Identifier,
    ) -> Result<Vec<Message>> {
        info!("Generating round three auxinfo messages.");
        if !self.is_r2_done() {
            return Err(CallerError::ProtocolNotReady.into());
        }

        // Extract all the `rid` values from all other participants.
        let rids: Vec<[u8; 32]> = self
            .other_participant_ids
            .iter()
            .map(|&other_participant_id| {
                let decom = self
                    .local_storage
                    .retrieve::<storage::Decommit<C>>(other_participant_id)?;
                Ok(decom.rid())
            })
            .collect::<Result<Vec<[u8; 32]>>>()?;
        let my_decom = self
            .local_storage
            .retrieve::<storage::Decommit<C>>(self.id)?;

        let mut global_rid = my_decom.rid();
        // xor all the rids together. In principle, many different options for combining
        // these should be okay
        for rid in rids.iter() {
            for i in 0..32 {
                global_rid[i] ^= rid[i];
            }
        }
        self.local_storage
            .store::<storage::GlobalRid>(self.id, global_rid);

        let witness = self.local_storage.retrieve::<storage::Witnesses>(self.id)?;
        let product = &witness.p * &witness.q;
        self.other_participant_ids
            .iter()
            .map(|&pid| {
                // Grab the other participant's decommitment record from storage...
                let verifier_decommit = self.local_storage.retrieve::<storage::Decommit<C>>(pid)?;
                let setup_params = verifier_decommit.clone().into_public();
                let params = setup_params.params();
                let shared_context = &self.retrieve_context();
                // ... and use its setup parameters in the proof.
                let common_input =
                    CommonInput::new(shared_context, sid, global_rid, self.id(), params, &product);
                let proof = AuxInfoProof::prove(rng, &common_input, &witness.p, &witness.q)?;
                Message::new(
                    MessageType::Auxinfo(AuxinfoMessageType::R3Proof),
                    sid,
                    self.id,
                    Some(pid),
                    false,
                    &proof,
                )
            })
            .collect::<Result<Vec<_>>>()
    }

    /// Handle other participants' round three messages.
    ///
    /// This corresponds to the following lines in Output of Figure 6:
    ///
    /// - Step 1, Line 2: Verify the `𝚷[mod]` and `𝚷[fac]` proofs.
    ///
    /// - Step 2: Output the `(N, s, t)` tuple of each participant once all
    ///   participants' proofs verify.
    #[cfg_attr(feature = "flame_it", flame("auxinfo"))]
    #[instrument(skip_all, err(Debug))]
    fn handle_round_three_msg(&mut self, message: &'a Message) -> Result<()>
    where
        C: 'a,
    {
        info!("Handling round three auxinfo message.");

        let global_rid = self.local_storage.retrieve::<storage::GlobalRid>(self.id)?;
        let decom = self
            .local_storage
            .retrieve::<storage::Decommit<C>>(message.from())?;

        let auxinfo_pub = decom.clone().into_public();
        let my_public = self.local_storage.retrieve::<storage::Public>(self.id)?;

        let proof = AuxInfoProof::from_message(message)?;
        let shared_context = &self.retrieve_context();
        let common_input = CommonInput::new(
            shared_context,
            message.id(),
            *global_rid,
            message.from(),
            my_public.params(),
            auxinfo_pub.pk().modulus(),
        );
        // Verify the public parameters for the given participant. Note that
        // this verification verifies _both_ the `𝚷[mod]` and `𝚷[fac]` proofs.
        proof.verify(&common_input)?;

        self.local_storage
            .store_once::<storage::Public>(message.from(), auxinfo_pub)?;

        Ok(())
    }

    fn is_r3_done(&self) -> bool {
        //check if we've stored all the public keyshares
        self.local_storage
            .contains_for_all_ids::<storage::Public>(&self.all_participants())
    }

    #[cfg_attr(feature = "flame_it", flame("keygen"))]
    #[instrument(skip_all, err(Debug))]
    fn gen_output(&mut self) -> Result<Output> {
        info!("Generating auxinfo output.");
        if self.is_r3_done() {
            let auxinfo_public = self
                .all_participants()
                .iter()
                .map(|pid| self.local_storage.remove::<storage::Public>(*pid))
                .collect::<Result<Vec<_>>>()?;
            let auxinfo_private = self.local_storage.remove::<storage::Private>(self.id)?;

            // The normal error type of this method is `CallerError::BadInput` because it's
            // external-facing, but in this case we somehow borked the protocol, so throw
            // the correct error.
            let output = Output::from_parts(auxinfo_public, auxinfo_private)
                .map_err(|_| InternalError::InternalInvariantFailed)?;

            Ok(output)
        } else {
            Err(CallerError::ProtocolNotReady)?
        }
    }

    #[cfg_attr(feature = "flame_it", flame("auxinfo"))]
    #[instrument(skip_all, err(Debug))]
    fn new_auxinfo<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
    ) -> Result<(AuxInfoPrivate, AuxInfoPublic, AuxInfoWitnesses)> {
        debug!("Creating new auxinfo.");

        let (decryption_key, p, q) = DecryptionKey::new(rng).map_err(|_| {
            error!("Failed to create DecryptionKey");
            InternalError::InternalInvariantFailed
        })?;
        let params = VerifiedRingPedersen::extract(&decryption_key, &self.retrieve_context(), rng)?;
        let encryption_key = decryption_key.encryption_key();

        Ok((
            decryption_key.into(),
            AuxInfoPublic::new(&self.retrieve_context(), self.id(), encryption_key, params)?,
            AuxInfoWitnesses { p, q },
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        curve::TestCurve, participant::ProcessOutcome, utils::testing::init_testing, Identifier,
        ParticipantConfig,
    };
    use rand::{CryptoRng, Rng, RngCore};
    use std::collections::HashMap;
    use tracing::warn;

    type SharedContext = super::SharedContext<TestCurve>;

    impl<C: CurveTrait> AuxInfoParticipant<C> {
        pub fn new_quorum<R: RngCore + CryptoRng>(
            sid: Identifier,
            input: (),
            quorum_size: usize,
            rng: &mut R,
        ) -> Result<Vec<Self>> {
            ParticipantConfig::random_quorum(quorum_size, rng)?
                .into_iter()
                .map(|config| Self::new(sid, config.id(), config.other_ids().to_vec(), input))
                .collect::<Result<Vec<_>>>()
        }
    }

    #[cfg_attr(feature = "flame_it", flame)]
    #[test]
    #[ignore = "slow"]
    // This test is cheap. Try a bunch of message permutations to decrease error
    // likelihood
    fn test_run_auxinfo_protocol_many_times() -> Result<()> {
        let _rng = init_testing();

        for _ in 0..20 {
            test_run_auxinfo_protocol()?;
        }
        Ok(())
    }

    #[test]
    fn test_run_auxinfo_protocol() -> Result<()> {
        let QUORUM_SIZE = 3;
        let mut rng = init_testing();
        let sid = Identifier::random(&mut rng);
        let mut participants: Vec<AuxInfoParticipant<TestCurve>> =
            AuxInfoParticipant::new_quorum(sid, (), QUORUM_SIZE, &mut rng)?;
        let all_pids: Vec<ParticipantIdentifier> = participants.iter().map(|p| p.id()).collect();

        // Round 1
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
                p.handle_round_one_msg(msg.clone())?;
            }
        }

        // Check if all participants have completed round one
        assert!(participants.iter().all(|p| p.is_r1_done()));

        // Round 2
        let mut round_2_inbox: HashMap<ParticipantIdentifier, Vec<Message>> =
            participants.iter().map(|p| (p.id(), Vec::new())).collect();

        for p in participants.iter_mut() {
            let mut broadcast_msgs = p.gen_round_two_msgs(sid)?;
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

        // ROUND 3
        let mut round_3_inbox: HashMap<ParticipantIdentifier, Vec<Message>> =
            participants.iter().map(|p| (p.id(), Vec::new())).collect();

        for p in participants.iter_mut() {
            let msgs: Vec<Message> = p.gen_round_three_msgs(&mut rng, sid)?;
            for msg in msgs.iter() {
                round_3_inbox
                    .get_mut(&msg.to().unwrap())
                    .unwrap()
                    .push(msg.clone());
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

        // FINALIZE
        let mut outputs: Vec<Output> = Vec::new();
        for p in participants.iter_mut() {
            if let Ok(output) = p.gen_output() {
                outputs.push(output);
            } else {
                warn!("Participant {} failed to generate output", p.id());
            }
        }

        // Make sure every player got an output
        assert_eq!(outputs.len(), QUORUM_SIZE);

        let context = SharedContext::fill_context(all_pids, sid);

        for party in participants.iter_mut() {
            let pid = party.id;

            // Collect the AuxInfoPublic associated with pid from every output
            let mut publics_for_pid = vec![];
            for output in &outputs {
                let public_key = output.find_public(pid);
                assert!(public_key.is_some());
                // Check that it's valid while we're here.
                assert!(public_key.unwrap().clone().verify(&context).is_ok());
                publics_for_pid.push(public_key.unwrap());
            }

            // Make sure they're all equal
            assert!(publics_for_pid.windows(2).all(|pks| pks[0] == pks[1]));
        }

        // Check that private outputs are consistent
        for (output, pid) in outputs.iter().zip(participants.iter().map(|p| p.id())) {
            let public_key = output.find_public(pid);
            assert!(public_key.is_some());
            assert_eq!(
                *public_key.unwrap().pk(),
                output.private_auxinfo().encryption_key()
            );
        }

        Ok(())
    }
}
