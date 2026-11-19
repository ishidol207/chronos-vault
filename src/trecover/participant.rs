//! Types and functions related to the tshare protocol.

// Copyright (c) Facebook, Inc. and its affiliates.
// Modifications Copyright (c) 2022-2023 Bolt Labs Holdings, Inc
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use crate::{
    curve::{CurveTrait, ScalarTrait},
    errors::{CallerError, InternalError, Result},
    keygen::KeySharePublic,
    local_storage::LocalStorage,
    messages::{Message, MessageType, TrecoverMessageType},
    participant::{InnerProtocolParticipant, ProcessOutcome},
    protocol::{ProtocolType, SharedContext},
    threshold::{self, ToutofTHelper},
    trecover::{
        commit::{TrecoveryCommit, TrecoveryDecommit},
        input::{HelperInput, TargetInput},
        recovery_data::RecoveryData,
    },
    tshare::{
        self,
        share::{EvalEncrypted, EvalPrivate},
        CoeffPrivate,
    },
    Identifier, ParticipantIdentifier, ProtocolParticipant,
};
use bincode::de;
use k256::elliptic_curve::scalar;
use rand::{CryptoRng, RngCore};
use tracing::{error, info, instrument};

mod storage {
    use std::marker::PhantomData;

    use k256::elliptic_curve::Curve;

    use crate::{
        local_storage::TypeTag,
        trecover::{commit::TrecoveryCommit, recovery_data::RecoveryData},
    };

    use super::*;
    pub(super) struct Commit;
    impl TypeTag for Commit {
        type Value = TrecoveryCommit;
    }
    pub(super) struct Decommit<C: CurveTrait> {
        _phantom: PhantomData<C>,
    }
    impl<C: CurveTrait + Send + Sync + 'static> TypeTag for Decommit<C> {
        type Value = TrecoveryDecommit<C>;
    }
    pub(super) struct RecoveryDataTag<C: CurveTrait> {
        _phantom: std::marker::PhantomData<C>,
    }
    impl<C: CurveTrait> TypeTag for RecoveryDataTag<C> {
        type Value = RecoveryData<C>;
    }
}

#[derive(Default)]
pub struct TrecoverTargetParticipant<C: CurveTrait> {
    sid: Identifier,
    input: TargetInput,
    id: ParticipantIdentifier,
    other_participant_ids: Vec<ParticipantIdentifier>,
    local_storage: LocalStorage,
    _phantom: std::marker::PhantomData<C>,
}

#[derive(Default)]
pub struct TrecoverHelperParticipant<C: CurveTrait> {
    sid: Identifier,
    input: HelperInput<C>,
    id: ParticipantIdentifier,
    other_participant_ids: Vec<ParticipantIdentifier>,
    local_storage: LocalStorage,
}

impl<C: CurveTrait> ProtocolParticipant for TrecoverTargetParticipant<C> {
    type Input = TargetInput;
    type Output = tshare::Output<C>;

    fn ready_type() -> crate::messages::MessageType {
        MessageType::Trecover(TrecoverMessageType::Ready)
    }

    fn protocol_type() -> crate::protocol::ProtocolType {
        ProtocolType::Trecover
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
            input,
            id,
            other_participant_ids: other_participant_ids.clone(),
            local_storage: LocalStorage::default(),
            _phantom: std::marker::PhantomData,
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
    ) -> crate::errors::Result<crate::participant::ProcessOutcome<Self::Output>> {
        info!("Processing trecover message - Target.");
        match message.message_type() {
            MessageType::Trecover(TrecoverMessageType::R3EncryptedShare) => {
                self.handle_round_three_msgs(message)?;
                let is_r3_done = self.is_r3_done();
                if is_r3_done {
                    info!("TREFRESH: Player {}: round three done", self.id());
                    let res = self.gen_output();
                    if let Err(e) = res {
                        error!("Failed to generate output: {:?}", e);
                        return Err(e);
                    } else {
                        let output = res.unwrap();
                        info!(
                            "TREFRESH: Player {}: generated output {:?}",
                            self.id(),
                            output
                        );
                        return Ok(ProcessOutcome::Done(output));
                    }
                } else {
                    info!(
                        "TREFRESH: Player {}: still waiting for round three messages",
                        self.id()
                    );
                    return Ok(ProcessOutcome::Continue(vec![]));
                }
            }
            _ => {
                error!("Unexpected message type for trecover target participant.");
                Err(InternalError::ProtocolError(None))
            }
        }
    }

    fn sid(&self) -> Identifier {
        self.sid
    }
}

impl<C: CurveTrait> InnerProtocolParticipant for TrecoverTargetParticipant<C> {
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

impl<C: CurveTrait> TrecoverTargetParticipant<C> {
    #[cfg_attr(feature = "flame_it", flame("trecover"))]
    #[instrument(skip_all, err(Debug))]
    fn handle_round_three_msgs(&mut self, msg: &Message) -> Result<()> {
        info!("Handling round three message: {:?}", msg);

        let recovery_data: RecoveryData<C> = deserialize!(&msg.unverified_bytes)?;
        self.local_storage
            .store_once::<storage::RecoveryDataTag<C>>(msg.from(), recovery_data)?;

        Ok(())
    }

    pub fn is_r3_done(&self) -> bool {
        // 필요한 모든 share 받았으면 자신의 다항식 복구
        self.local_storage
            .contains_for_all_ids::<storage::RecoveryDataTag<C>>(&self.input.helper_pids())
    }

    #[cfg_attr(feature = "flame_it", flame("trecover"))]
    #[instrument(skip_all, err(Debug))]
    fn gen_output(&mut self) -> Result<tshare::Output<C>> {
        info!("Generating trecover output.");
        if !self.is_r3_done() {
            error!("Not all round one messages received.");
            return Err(InternalError::ProtocolError(None));
        }

        let helper_pids: Vec<ParticipantIdentifier> = self.input.helper_pids().to_vec();

        // 모든 Helper가 동일한 공개 정보를 보냈는지 확인
        let reference_data = self
            .local_storage
            .retrieve::<storage::RecoveryDataTag<C>>(helper_pids[0])?;
        for other_pid in &helper_pids[1..] {
            let other_data = self
                .local_storage
                .retrieve::<storage::RecoveryDataTag<C>>(*other_pid)?;

            let mut ref_pks = reference_data.public_key_shares.clone();
            ref_pks.sort_by_key(|k| k.participant());

            let mut other_pks = other_data.public_key_shares.clone();
            other_pks.sort_by_key(|k| k.participant());

            if ref_pks != other_pks
                || reference_data.rid != other_data.rid
                || reference_data.threshold != other_data.threshold
            {
                error!("Inconsistent public data received from helpers during recovery.");
                return Err(InternalError::ProtocolError(None));
            }
        }

        // 모든 Helper가 동일한 공개 정보를 보냄
        let trusted_public_keys = reference_data.public_key_shares.clone();
        let trusted_rid = reference_data.rid;
        let trusted_threshold = reference_data.threshold;

        let my_paillier_sk = self
            .input
            .auxinfo_output()
            .private_auxinfo()
            .decryption_key();
        let mut recovered_share_scalar = C::Scalar::zero();

        for pid in &helper_pids {
            let recovery_data = self
                .local_storage
                .retrieve::<storage::RecoveryDataTag<C>>(*pid)?;

            let s_i_bn = my_paillier_sk
                .decrypt(&recovery_data.recovery_fragment)
                .map_err(|e| InternalError::InternalInvariantFailed)?;
            let s_i = <C as CurveTrait>::bn_to_scalar(&s_i_bn)?;

            recovered_share_scalar = recovered_share_scalar.add(&s_i);
        }

        let my_public_key_share = trusted_public_keys
            .iter()
            .find(|&pks| pks.participant() == self.id)
            .ok_or(InternalError::ProtocolError(None))?;

        let rebuilt_pk_share =
            <C as CurveTrait>::GENERATOR.multiply_by_scalar(&recovered_share_scalar);

        if rebuilt_pk_share != *my_public_key_share.as_ref() {
            error!("Verification of recovered share failed! Rebuilt public key does not match.");
            return Err(InternalError::ProtocolError(None));
        }

        let final_output = tshare::Output::from_parts(
            trusted_public_keys,
            recovered_share_scalar,
            trusted_rid,
            trusted_threshold,
        )?;

        Ok(final_output)
    }
}

impl<C: CurveTrait> ProtocolParticipant for TrecoverHelperParticipant<C> {
    type Input = HelperInput<C>;

    type Output = ();

    fn ready_type() -> MessageType {
        MessageType::Trecover(TrecoverMessageType::Ready)
    }

    fn protocol_type() -> ProtocolType {
        ProtocolType::Trecover
    }

    fn new(
        sid: Identifier,
        id: ParticipantIdentifier,
        other_participant_ids: Vec<ParticipantIdentifier>,
        input: Self::Input,
    ) -> Result<Self>
    where
        Self: Sized,
    {
        Ok(Self {
            sid,
            input,
            id,
            other_participant_ids: other_participant_ids.clone(),
            local_storage: LocalStorage::default(),
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
        message: &Message,
    ) -> Result<crate::participant::ProcessOutcome<Self::Output>> {
        match message.message_type() {
            MessageType::Trecover(TrecoverMessageType::Ready) => {
                let res = self.gen_round_one_msg(rng, self.sid);
                if let Err(e) = res {
                    error!("Failed to generate round one messages: {:?}", e);
                    return Err(e);
                } else {
                    let msgs = res.unwrap();
                    info!(
                        "TRECOVER: Player {}: generated round one message {:?}",
                        self.id(),
                        msgs
                    );
                    return Ok(ProcessOutcome::Continue(msgs));
                }
            }
            MessageType::Trecover(TrecoverMessageType::R1CommitHash) => {
                self.handle_round_one_msgs(rng, message.clone())?;
                if self.is_r1_done() {
                    info!("TRECOVER: Player {}: round one done", self.id());
                    let res = self.gen_round_two_msg(rng, self.sid());
                    if let Err(e) = res {
                        error!("Failed to generate round two messages: {:?}", e);
                        return Err(e);
                    } else {
                        let msgs = res.unwrap();
                        info!(
                            "TRECOVER: Player {}: generated round two message {:?}",
                            self.id(),
                            msgs
                        );
                        return Ok(ProcessOutcome::Continue(msgs));
                    }
                } else {
                    info!(
                        "TRECOVER: Player {}: still waiting for round one messages",
                        self.id()
                    );
                    return Ok(ProcessOutcome::Continue(vec![]));
                }
            }
            MessageType::Trecover(TrecoverMessageType::R2Decommit) => {
                self.handle_round_two_msgs(rng, message.clone())?;
                let is_r2_done = self.is_r2_done();
                if is_r2_done {
                    info!("TRECOVER: Player {}: round two done", self.id());
                    let res = self.gen_round_three_msg(rng, self.sid());
                    if let Err(e) = res {
                        error!("Failed to generate round three messages: {:?}", e);
                        return Err(e);
                    } else {
                        let msgs = res.unwrap();
                        info!(
                            "TRECOVER: Player {}: generated round three message {:?}",
                            self.id(),
                            msgs
                        );
                        return Ok(ProcessOutcome::Continue(msgs));
                    }
                } else {
                    info!(
                        "TRECOVER: Player {}: still waiting for round two messages",
                        self.id()
                    );
                    return Ok(ProcessOutcome::Continue(vec![]));
                }
            }
            _ => {
                error!("Unexpected message type for trecover helper participant.");
                Err(CallerError::BadInput.into())
            }
        }
    }

    fn sid(&self) -> Identifier {
        self.sid
    }
}

impl<C: CurveTrait> InnerProtocolParticipant for TrecoverHelperParticipant<C> {
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

impl<C: CurveTrait> TrecoverHelperParticipant<C> {
    #[cfg_attr(feature = "flame_it", flame("trecover"))]
    #[instrument(skip_all, err(Debug))]
    fn gen_round_one_msg<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        sid: Identifier,
    ) -> Result<Vec<Message>> {
        info!("Generating round one message - Helper");
        let randomizer = C::Scalar::random();

        let decom = TrecoveryDecommit::<C>::new(rng, sid, randomizer, self.id());
        let com = decom.commit()?;

        let mut msgs = Vec::new();
        for pid in self.input().other_helper_pids() {
            let msg = Message::new(
                MessageType::Trecover(TrecoverMessageType::R1CommitHash),
                self.sid(),
                self.id(),
                Some(*pid),
                false,
                &com,
            )?;
            msgs.push(msg);
        }

        self.local_storage
            .store::<storage::Decommit<C>>(self.id(), decom);
        self.local_storage.store::<storage::Commit>(self.id(), com);

        Ok(msgs)
    }

    #[cfg_attr(feature = "flame_it", flame("trecover"))]
    #[instrument(skip_all, err(Debug))]
    fn handle_round_one_msgs<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        msg: Message,
    ) -> Result<()> {
        info!("Handling round one trecover message.");

        let trecover_commit = TrecoveryCommit::from_message(&msg)?;
        self.local_storage
            .store_once::<storage::Commit>(msg.from(), trecover_commit)?;

        Ok(())
    }

    pub fn is_r1_done(&self) -> bool {
        self.local_storage
            .contains_for_all_ids::<storage::Commit>(self.input().other_helper_pids())
    }

    #[cfg_attr(feature = "flame_it", flame("trecover"))]
    #[instrument(skip_all, err(Debug))]
    fn gen_round_two_msg<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        sid: Identifier,
    ) -> Result<Vec<Message>> {
        info!("Generating round two message - Helper");

        if !self.is_r1_done() {
            error!("Cannot generate R2 message: R1 is not done.");
            return Err(CallerError::ProtocolNotReady.into());
        }
        let my_decommit = self
            .local_storage
            .retrieve::<storage::Decommit<C>>(self.id())?
            .clone();

        let mut msgs = Vec::new();

        for pid in self.input().other_helper_pids() {
            let msg = Message::new(
                MessageType::Trecover(TrecoverMessageType::R2Decommit),
                self.sid(),
                self.id(),
                Some(*pid),
                false,
                &my_decommit,
            )?;
            msgs.push(msg);
        }

        Ok(msgs)
    }

    #[cfg_attr(feature = "flame_it", flame("trecover"))]
    #[instrument(skip_all, err(Debug))]
    fn handle_round_two_msgs<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        msg: Message,
    ) -> Result<()> {
        info!("Handling round two trecovery message.");
        let sender_pid = msg.from();
        let stored_commit = self.local_storage.retrieve::<storage::Commit>(sender_pid)?;

        // commit 검증 동시에 수행
        let decommit = TrecoveryDecommit::<C>::from_message(&msg, stored_commit)?;
        self.local_storage
            .store_once::<storage::Decommit<C>>(sender_pid, decommit)?;
        Ok(())
    }

    fn is_r2_done(&self) -> bool {
        self.local_storage
            .contains_for_all_ids::<storage::Decommit<C>>(self.input().other_helper_pids())
    }

    #[cfg_attr(feature = "flame_it", flame("trecover"))]
    #[instrument(skip_all, err(Debug))]
    fn gen_round_three_msg<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        sid: Identifier,
    ) -> Result<Vec<Message>> {
        info!("Generating round one message - Helper");

        if !self.is_r2_done() {
            error!("Cannot generate R3 message: R2 is not done.");
            return Err(CallerError::ProtocolNotReady.into());
        }
        let my_pid = self.id();
        let target_pid = *self.input.target_pid();
        let my_secret_share = self.input.tshare().private_key_share();
        let other_helper_pids = self.input.other_helper_pids();

        // b_ij 가져오기
        let my_decommit = self
            .local_storage
            .retrieve::<storage::Decommit<C>>(my_pid)?;
        let my_randomizer = my_decommit.randomizer();

        // Lagrange Coefficient 계산
        let mut helper_pids = other_helper_pids.to_vec();
        helper_pids.push(my_pid);

        let eval_point =
            threshold::ToutofTHelper::<C>::participant_coordinate(*self.input.target_pid());
        let lagrange_coeff =
            threshold::ToutofTHelper::<C>::lagrange_coefficient(eval_point, &my_pid, &helper_pids);

        // 마스킹 값 계산: Σ (b_ij - b_ji)
        let mut masking_term = C::Scalar::zero();
        for other_pid in other_helper_pids {
            // b_j,i
            let other_decommit = self
                .local_storage
                .retrieve::<storage::Decommit<C>>(*other_pid)?;
            let other_randomizer = other_decommit.randomizer();

            masking_term = masking_term + my_randomizer.sub(&other_randomizer);
        }

        // s_i = L_H(T) * x_H + Σ (b_ij - b_ji) 계산
        let s_i = (lagrange_coeff.mul(my_secret_share)) + masking_term;
        let s_i = <C as CurveTrait>::scalar_to_bn(&s_i);

        let target_paillier_pk = self
            .input
            .auxinfo_output()
            .find_public(*self.input.target_pid())
            .ok_or_else(|| {
                error!("Couldn't find Paillier public key for target participant.");
                InternalError::ProtocolError(None)
            })?
            .pk();

        let (encrypted_s_i, nonce) = target_paillier_pk
            .encrypt(rng, &s_i)
            .map_err(|_| InternalError::InternalInvariantFailed)?;

        let recovery_data = RecoveryData::new(
            encrypted_s_i,
            self.input.tshare().public_key_shares().to_vec(),
            *self.input.tshare().rid(),
            self.input.tshare().threshold(),
        );

        let msg = Message::new(
            MessageType::Trecover(TrecoverMessageType::R3EncryptedShare),
            self.sid(),
            my_pid,
            Some(target_pid),
            false,
            &recovery_data,
        )?;

        Ok(vec![msg])
    }

    fn input(&self) -> &HelperInput<C> {
        &self.input
    }
}
