use crate::auxinfo::AuxInfoPublic;
use crate::curve::CurveTrait;
use crate::errors::{CallerError, InternalError, Result};
use crate::k256::{k256_order, K256};
use crate::keygen::KeySharePublic;
use crate::local_storage::LocalStorage;
use crate::messages::{Message, MessageType, TpresignAbortMessageType};
use crate::paillier::{Ciphertext, DecryptionKey, Nonce};
use crate::parameters::ELL_PRIME;
use crate::participant::{InnerProtocolParticipant, ProcessOutcome};
use crate::protocol::{ProtocolType, SharedContext};
use crate::threshold::ToutofTHelper;
use crate::tpresign::participant::storage as tpresign_storage;
use crate::utils::{random_plusminus_by_size, random_positive_bn};
use crate::zkp::piaffgstar::{PiAffgStarInput, PiAffgStarProof, PiAffgStarSecret};
use crate::zkp::pidec::{PiDecInput, PiDecProof, PiDecSecret};
use crate::zkp::Proof;
use crate::{auxinfo, tshare, Identifier, ParticipantIdentifier, ProtocolParticipant};
use libpaillier::unknown_order::BigNumber;
use merlin::Transcript;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::marker::PhantomData;
use tracing::{error, info};

enum FailedProof<C> {
    None,
    PiAffgStar(PiAffgStarProof<C>),
    PiDec(PiDecProof<C>),
}

mod storage {
    use super::*;
    use crate::local_storage::TypeTag;
    use std::marker::PhantomData;

    pub(super) struct VerifyResult<C>(PhantomData<C>);
    impl<C: Send + Sync + 'static> TypeTag for VerifyResult<C> {
        type Value = FailedProof<C>;
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct PublicMessage<C> {
    pub dec_proof: PiDecProof<C>,
    pub affg_star_proofs: Vec<PiAffgStarProof<C>>,
}

impl<C: CurveTrait> TryFrom<&Message> for PublicMessage<C> {
    type Error = InternalError;

    fn try_from(message: &Message) -> std::result::Result<Self, Self::Error> {
        message
            .check_type(MessageType::TpresignAbort(
                TpresignAbortMessageType::RoundOneS,
            ))
            .or(message.check_type(MessageType::TpresignAbort(
                TpresignAbortMessageType::RoundOneDelta,
            )))?;
        let public: Self = deserialize!(&message.unverified_bytes)?;
        Ok(public)
    }
}

#[derive(Debug, Default)]
pub struct TpresignAbortParticipant<C: CurveTrait> {
    /// The current session identifier
    sid: Identifier,
    /// A unique identifier for this participant.
    id: ParticipantIdentifier,
    /// A list of all other participant identifiers participating in the
    /// protocol
    other_participant_ids: Vec<ParticipantIdentifier>,
    /// Local storage for this participant to store secrets
    local_storage: LocalStorage,
    auxinfo_output: auxinfo::Output,
    tshare_output: tshare::Output<C>,
    _curve: PhantomData<C>,
}

impl<C: CurveTrait> TpresignAbortParticipant<C> {
    pub(crate) fn find_auxinfo_public(&self, pid: ParticipantIdentifier) -> Result<&AuxInfoPublic> {
        self.auxinfo_output.find_public(pid)
            .ok_or_else(|| {
                error!("Presign input doesn't contain a public auxinfo for {}, even though we checked for it at construction.", pid);
                InternalError::InternalInvariantFailed
            })
    }

    pub(crate) fn find_tshare_output_public(
        &self,
        pid: ParticipantIdentifier,
    ) -> Result<&KeySharePublic<C>> {
        self.tshare_output.public_key_shares().iter().find(
            |p|p.participant() == pid
        ).ok_or_else(|| {
            error!("Presign input doesn't contain a public keyshare for {}, even though we checked for it at construction.", pid);
            InternalError::InternalInvariantFailed
        })
    }
}

#[derive(Debug)]
pub struct Input<C: CurveTrait> {
    local_storage: LocalStorage,
    auxinfo_output: auxinfo::Output,
    tshare_output: tshare::Output<C>,
}

impl<C: CurveTrait> Input<C> {
    pub fn new(
        local_storage: LocalStorage,
        auxinfo_output: auxinfo::Output,
        tshare_output: tshare::Output<C>,
    ) -> Self {
        Self {
            local_storage,
            auxinfo_output,
            tshare_output,
        }
    }
}

impl<C: CurveTrait> ProtocolParticipant for TpresignAbortParticipant<C> {
    type Input = Input<C>;
    type Output = Vec<ParticipantIdentifier>;

    fn protocol_type() -> ProtocolType {
        ProtocolType::TpresignAbort
    }

    /// input 으로 Abort 된 Presign 의 LocalStorage 와 auxinfo 를 주입합니다.
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
            id,
            other_participant_ids,
            local_storage: input.local_storage,
            auxinfo_output: input.auxinfo_output,
            tshare_output: input.tshare_output,
            _curve: PhantomData,
        })
    }

    fn id(&self) -> ParticipantIdentifier {
        self.id
    }

    fn other_ids(&self) -> &[ParticipantIdentifier] {
        &self.other_participant_ids
    }

    fn process_message<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        message: &Message,
    ) -> Result<ProcessOutcome<Self::Output>> {
        info!(
            "TPRESIGN_ABORT: Player {}: received {:?} from {}",
            self.id(),
            message.message_type(),
            message.from()
        );

        match message.message_type() {
            MessageType::TpresignAbort(TpresignAbortMessageType::ReadyDelta) => {
                let res = self.gen_round_one_delta_msgs(rng, self.sid());
                if let Err(e) = res {
                    error!("Failed to generate round one delta messages: {:?}", e);
                    return Err(e);
                } else {
                    let msg = res.unwrap();
                    info!(
                        "TPRESIGN_ABORT: Player {}: generated round one delta message {:?}",
                        self.id(),
                        msg
                    );
                    return Ok(ProcessOutcome::Continue(msg));
                }
            }
            MessageType::TpresignAbort(TpresignAbortMessageType::ReadyS) => {
                let res = self.gen_round_one_s_msgs(rng, self.sid());
                if let Err(e) = res {
                    error!("Failed to generate round one s messages: {:?}", e);
                    return Err(e);
                } else {
                    let msg = res.unwrap();
                    info!(
                        "TPRESIGN_ABORT: Player {}: generated round one s message {:?}",
                        self.id(),
                        msg
                    );
                    return Ok(ProcessOutcome::Continue(msg));
                }
            }
            MessageType::TpresignAbort(TpresignAbortMessageType::RoundOneDelta) => {
                self.handle_round_one_delta_msg(rng, message.clone())?;
                let is_r1_done = self.is_r1_done();

                if is_r1_done {
                    info!("TPRESIGN_ABORT: Player {}: round one delta done", self.id());
                    let res = self.gen_output();
                    if let Err(e) = res {
                        error!("Failed to generate output messages: {:?}", e);
                        return Err(e);
                    } else {
                        let msg = res.unwrap();
                        info!(
                            "TPRESIGN_ABORT: Player {}: generated output message {:?}",
                            self.id(),
                            msg
                        );
                        return Ok(ProcessOutcome::Done(msg));
                    }
                } else {
                    info!(
                        "TPRESIGN_ABORT: Player {}: still waiting for round one messages",
                        self.id()
                    );
                    return Ok(ProcessOutcome::Continue(vec![]));
                }
            }
            MessageType::TpresignAbort(TpresignAbortMessageType::RoundOneS) => {
                self.handle_round_one_s_msg(rng, message.clone())?;
                let is_r1_done = self.is_r1_done();

                if is_r1_done {
                    info!("TPRESIGN_ABORT: Player {}: round one s done", self.id());
                    let res = self.gen_output();
                    if let Err(e) = res {
                        error!("Failed to generate output messages: {:?}", e);
                        return Err(e);
                    } else {
                        let msg = res.unwrap();
                        info!(
                            "TPRESIGN_ABORT: Player {}: generated output message {:?}",
                            self.id(),
                            msg
                        );
                        return Ok(ProcessOutcome::Done(msg));
                    }
                } else {
                    info!(
                        "TPRESIGN_ABORT: Player {}: still waiting for round one messages",
                        self.id()
                    );
                    return Ok(ProcessOutcome::Continue(vec![]));
                }
            }
            _ => {
                error!(
                    "TPRESIGN_ABORT: Player {}: received unexpected message type {:?}",
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
        // 음...
        panic!("PresignAbortParticipant does not have a single ready type.");
    }
}

impl<C: CurveTrait> InnerProtocolParticipant for TpresignAbortParticipant<C> {
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

impl<C: CurveTrait> TpresignAbortParticipant<C> {
    fn gen_round_one_delta_msgs<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        sid: Identifier,
    ) -> Result<Vec<Message>> {
        info!("Generating round one 'delta' tpresign abort messages.");
        let pids = self.other_participant_ids.clone();
        let paillier_key = self.auxinfo_output.private_auxinfo().decryption_key();
        let nn = paillier_key.encryption_key().0.nn().clone();
        let mut D: BigNumber = BigNumber::from(1);
        let Gamma_i = self
            .local_storage
            .retrieve::<tpresign_storage::RoundTwoPublicISent<C>>(pids[0])?
            .Gamma
            .clone();

        let Gamma_i = Gamma_i.normalize();

        pids.iter()
            .map(|pid| {
                let presign_r2_public = self
                    .local_storage
                    .retrieve::<tpresign_storage::RoundTwoPublic<C>>(pid.clone())?;
                let presign_r2_public_i_sent =
                    self.local_storage
                        .retrieve::<tpresign_storage::RoundTwoPublicISent<C>>(pid.clone())?;
                D = D.modmul(&presign_r2_public.D.0, &nn);
                D = D.modmul(&presign_r2_public_i_sent.F.0, &nn);
                Ok(())
            })
            .collect::<Result<Vec<()>>>()?;
        let presign_r1_private = self
            .local_storage
            .retrieve::<tpresign_storage::RoundOnePrivate>(self.id)?;

        let presign_r3_private = self
            .local_storage
            .retrieve::<tpresign_storage::RoundThreePrivate<C>>(self.id)?;

        let D_mul_K = paillier_key
            .encryption_key()
            .multiply_and_add(
                &presign_r1_private.gamma,
                &presign_r1_private.K,
                &Ciphertext(D.clone()),
            )
            .map_err(|_| {
                error!("Failed to compute D * K for decryption key.");
                InternalError::InternalInvariantFailed
            })?;

        let rho = paillier_key.get_rho(D_mul_K).map_err(|_| {
            error!("Failed to generate rho for decryption key.");
            InternalError::InternalInvariantFailed
        })?;
        let rho = Nonce(rho);
        let delta = &presign_r3_private.delta;
        let mut dec_transcript = Transcript::new(b"PiDecProof");
        let dec_secret = PiDecSecret::new(&presign_r1_private.gamma, &delta, &rho);
        let S = C::GENERATOR.multiply_by_bignum(&delta)?;
        let dec_proof = PiDecProof::prove(
            PiDecInput::new(
                &paillier_key.encryption_key(),
                &presign_r1_private.K,
                &Gamma_i,
                &Ciphertext(D.clone()),
                &S,
                &C::GENERATOR,
            ),
            dec_secret,
            &self.retrieve_context(),
            &mut dec_transcript,
            rng,
        )?;

        let affg_star_proofs = pids
            .iter()
            .map(|pid| {
                let mut affg_star_transcript = Transcript::new(b"PiAffgStarProof");
                let presign_r1_public_broad =
                    self.local_storage
                        .retrieve::<tpresign_storage::RoundOnePublicBroadcast>(pid.clone())?;
                let presign_r2_private = self
                    .local_storage
                    .retrieve::<tpresign_storage::RoundTwoPrivate>(pid.clone())?;
                let presign_r2_public_i_sent =
                    self.local_storage
                        .retrieve::<tpresign_storage::RoundTwoPublicISent<C>>(pid.clone())?;

                let affg_star_secret = PiAffgStarSecret::new(
                    &presign_r1_private.gamma,
                    &presign_r2_private.beta,
                    &presign_r2_private.s,
                    &presign_r2_private.r,
                );

                let affg_star_proof = PiAffgStarProof::prove(
                    PiAffgStarInput::new(
                        self.find_auxinfo_public(pid.clone())?.pk(),
                        &paillier_key.encryption_key(),
                        &presign_r1_public_broad.K,
                        &presign_r2_public_i_sent.D,
                        &presign_r2_public_i_sent.F,
                        &Gamma_i,
                        pid.clone(),
                    ),
                    affg_star_secret,
                    &self.retrieve_context(),
                    &mut affg_star_transcript,
                    rng,
                )?;
                Ok(affg_star_proof)
            })
            .collect::<Result<Vec<PiAffgStarProof<C>>>>()?;

        let public_message = PublicMessage {
            dec_proof,
            affg_star_proofs,
        };

        let broadcast_messages = Message::new(
            MessageType::TpresignAbort(TpresignAbortMessageType::RoundOneDelta),
            sid,
            self.id,
            None,
            true,
            &public_message,
        )?;

        Ok(vec![broadcast_messages])
    }

    fn gen_round_one_s_msgs<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        sid: Identifier,
    ) -> Result<Vec<Message>> {
        info!("Generating round one 's' presign abort messages.");
        let pids = self.other_participant_ids.clone();
        let paillier_key = self.auxinfo_output.private_auxinfo().decryption_key();
        let nn = paillier_key.encryption_key().0.nn().clone();
        let mut D_hat: BigNumber = BigNumber::from(1);

        let lagrange = C::scalar_to_bn(&ToutofTHelper::<C>::lagrange_coefficient_at_zero(
            &self.id, &pids,
        ));
        let x = C::scalar_to_bn(self.tshare_output.private_key_share());
        let x = x.modmul(&lagrange, &k256_order());
        let X = self.find_tshare_output_public(self.id)?.as_ref();
        let X = X.mul_by_bn(&lagrange)?;

        pids.iter()
            .map(|pid| {
                let presign_r2_public = self
                    .local_storage
                    .retrieve::<tpresign_storage::RoundTwoPublic<C>>(pid.clone())?;
                let presign_r2_public_i_sent =
                    self.local_storage
                        .retrieve::<tpresign_storage::RoundTwoPublicISent<C>>(pid.clone())?;
                D_hat = D_hat.modmul(&presign_r2_public.D_hat.0, &nn);
                D_hat = D_hat.modmul(&presign_r2_public_i_sent.F_hat.0, &nn);
                Ok(())
            })
            .collect::<Result<Vec<()>>>()?;

        let presign_r1_private = self
            .local_storage
            .retrieve::<tpresign_storage::RoundOnePrivate>(self.id)?;
        let presign_r3_private = self
            .local_storage
            .retrieve::<tpresign_storage::RoundThreePrivate<C>>(self.id)?;

        let D_hat_mul_K = paillier_key
            .encryption_key()
            .multiply_and_add(&x, &presign_r1_private.K, &Ciphertext(D_hat.clone()))
            .map_err(|_| {
                error!("Failed to compute D * K for decryption key.");
                InternalError::InternalInvariantFailed
            })?;

        let rho = paillier_key.get_rho(D_hat_mul_K).map_err(|_| {
            error!("Failed to generate rho for decryption key.");
            InternalError::InternalInvariantFailed
        })?;
        let rho = Nonce(rho);
        let chi = &presign_r3_private.chi;
        let mut dec_transcript = Transcript::new(b"PiDecProof");
        let dec_secret = PiDecSecret::new(&x, &chi, &rho);
        let S = presign_r3_private.S.clone();
        let dec_proof = PiDecProof::prove(
            PiDecInput::new(
                &paillier_key.encryption_key(),
                &presign_r1_private.K,
                &X,
                &Ciphertext(D_hat.clone()),
                &S,
                presign_r3_private.Gamma.as_ref(),
            ),
            dec_secret,
            &self.retrieve_context(),
            &mut dec_transcript,
            rng,
        )?;

        let affg_star_proofs = pids
            .iter()
            .map(|pid| {
                let mut affg_star_transcript = Transcript::new(b"PiAffgStarProof");

                let presign_r1_public_broad =
                    self.local_storage
                        .retrieve::<tpresign_storage::RoundOnePublicBroadcast>(pid.clone())?;
                let presign_r2_private = self
                    .local_storage
                    .retrieve::<tpresign_storage::RoundTwoPrivate>(pid.clone())?;
                let presign_r2_public_i_sent =
                    self.local_storage
                        .retrieve::<tpresign_storage::RoundTwoPublicISent<C>>(pid.clone())?;

                let affg_star_secret = PiAffgStarSecret::new(
                    &x,
                    &presign_r2_private.beta_hat,
                    &presign_r2_private.s_hat,
                    &presign_r2_private.r_hat,
                );

                let affg_star_proof = PiAffgStarProof::prove(
                    PiAffgStarInput::new(
                        self.find_auxinfo_public(pid.clone())?.pk(),
                        &paillier_key.encryption_key(),
                        &presign_r1_public_broad.K,
                        &presign_r2_public_i_sent.D_hat,
                        &presign_r2_public_i_sent.F_hat,
                        &X,
                        pid.clone(),
                    ),
                    affg_star_secret,
                    &self.retrieve_context(),
                    &mut affg_star_transcript,
                    rng,
                )?;
                Ok(affg_star_proof)
            })
            .collect::<Result<Vec<PiAffgStarProof<C>>>>()?;

        let public_message = PublicMessage {
            dec_proof,
            affg_star_proofs,
        };

        let broadcast_messages = Message::new(
            MessageType::TpresignAbort(TpresignAbortMessageType::RoundOneS),
            sid,
            self.id,
            None,
            true,
            &public_message,
        )?;

        Ok(vec![broadcast_messages])
    }

    fn handle_round_one_delta_msg<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        broadcast_msg: Message,
    ) -> Result<()> {
        info!("Handling round one delta presign abort message.");
        broadcast_msg.check_broadcast_message()?;
        let public = PublicMessage::<C>::try_from(&broadcast_msg)?;
        let pid = broadcast_msg.from();

        let paillier_enc_key = self.find_auxinfo_public(pid)?.pk().clone();
        let presign_r1_public = self
            .local_storage
            .retrieve::<tpresign_storage::RoundOnePublicBroadcast>(pid)?;
        let presign_r2_public = self
            .local_storage
            .retrieve::<tpresign_storage::RoundTwoPublic<C>>(pid)?;
        let presign_r3_public = self
            .local_storage
            .retrieve::<tpresign_storage::RoundThreePublic<C>>(pid)?;
        let presign_r2_broadcast = self
            .local_storage
            .retrieve::<tpresign_storage::RoundTwoPublicBroadcast>(pid)?;

        let delta = &presign_r3_public.delta;
        let S = C::GENERATOR.multiply_by_bignum(&delta)?;

        let mut D = self
            .local_storage
            .retrieve::<tpresign_storage::RoundTwoPublicISent<C>>(pid)?
            .D
            .0
            .clone();
        self.other_participant_ids
            .iter()
            .map(|other_pid| {
                let m = self
                    .local_storage
                    .retrieve::<tpresign_storage::RoundTwoPublicBroadcast>(*other_pid)?;
                m.iter().filter(|m| m.verifier_pid == pid).for_each(|m| {
                    D = D.modmul(&m.D.0, paillier_enc_key.0.nn());
                });
                Ok(())
            })
            .collect::<Result<Vec<_>>>()?;

        presign_r2_broadcast.iter().for_each(|m| {
            D = D.modmul(&m.F.0, paillier_enc_key.0.nn());
        });

        let mut dec_transcript = Transcript::new(b"PiDecProof");

        let res = public.dec_proof.clone().verify(
            PiDecInput::new(
                &paillier_enc_key,
                &presign_r1_public.K,
                &presign_r2_public.Gamma,
                &Ciphertext(D),
                &S,
                &C::GENERATOR,
            ),
            &self.retrieve_context(),
            &mut dec_transcript,
        );

        if let Err(e) = res {
            error!("Failed to verify PiDecProof: {:?}", e);
            self.local_storage.store_once::<storage::VerifyResult<C>>(
                pid,
                FailedProof::PiDec(public.dec_proof),
            )?;
            return Ok(());
        }

        let mut verifier_pid_counter: HashSet<u128> = HashSet::new();

        for proof in public.affg_star_proofs {
            let verifier_pid = proof.verifier_pid();
            if !verifier_pid_counter.insert(verifier_pid.as_u128()) {
                error!("Duplicate verifier pid found: {}", verifier_pid);
                self.local_storage.store_once::<storage::VerifyResult<C>>(
                    pid,
                    FailedProof::PiAffgStar(proof.clone()),
                )?;
                return Ok(());
            }
            if !self.other_participant_ids.contains(&verifier_pid) && verifier_pid != self.id {
                error!("Verifier pid {} not in other participant ids", verifier_pid);
                self.local_storage.store_once::<storage::VerifyResult<C>>(
                    pid,
                    FailedProof::PiAffgStar(proof.clone()),
                )?;
                return Ok(());
            }
            let mut affg_star_transcript = Transcript::new(b"PiAffgStarProof");

            let presign_r1_public = self
                .local_storage
                .retrieve::<tpresign_storage::RoundOnePublicBroadcast>(verifier_pid)?;
            let presign_r2_public = self
                .local_storage
                .retrieve::<tpresign_storage::RoundTwoPublic<C>>(pid)?;
            let presign_r2_broadcast =
                self.local_storage
                    .retrieve::<tpresign_storage::RoundTwoPublicBroadcast>(pid)?;

            let public_broadcast_to_verifier = presign_r2_broadcast
                .iter()
                .find(|m| m.verifier_pid == verifier_pid);

            if let None = public_broadcast_to_verifier {
                error!("Failed to find D for participant {}", verifier_pid);
                self.local_storage.store_once::<storage::VerifyResult<C>>(
                    pid,
                    FailedProof::PiAffgStar(proof.clone()),
                )?;
                return Ok(());
            }

            let public_broadcast_to_verifier = public_broadcast_to_verifier.unwrap();

            let verifier_pk = self.find_auxinfo_public(verifier_pid)?.pk().clone();

            let Gamma = &presign_r2_public.Gamma;
            let K = &presign_r1_public.K;
            let D = &public_broadcast_to_verifier.D;
            let F = &public_broadcast_to_verifier.F;

            let res = proof.clone().verify(
                PiAffgStarInput::new(
                    &verifier_pk,
                    &paillier_enc_key,
                    K,
                    D,
                    F,
                    &Gamma,
                    verifier_pid,
                ),
                &self.retrieve_context(),
                &mut affg_star_transcript,
            );

            if let Err(e) = res {
                error!("Failed to verify PiAffgStarProof: {:?}", e);
                self.local_storage.store_once::<storage::VerifyResult<C>>(
                    pid,
                    FailedProof::PiAffgStar(proof.clone()),
                )?;
                return Ok(());
            }
        }

        self.local_storage
            .store_once::<storage::VerifyResult<C>>(pid, FailedProof::None)?;

        Ok(())
    }

    fn handle_round_one_s_msg<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        broadcast_msg: Message,
    ) -> Result<()> {
        info!("Handling round one delta presign abort message.");
        broadcast_msg.check_broadcast_message()?;
        let public = PublicMessage::<C>::try_from(&broadcast_msg)?;
        let pid = broadcast_msg.from();
        let mut lagrange_participants = self.other_participant_ids.clone();
        lagrange_participants.retain(|_pid| _pid.clone() != pid);
        lagrange_participants.push(self.id);
        let lagrange = C::scalar_to_bn(&ToutofTHelper::<C>::lagrange_coefficient_at_zero(
            &pid,
            &lagrange_participants,
        ));
        let X = self.find_tshare_output_public(pid)?.as_ref();
        let X = X.mul_by_bn(&lagrange)?;

        let paillier_enc_key = self.find_auxinfo_public(pid)?.pk().clone();
        let presign_r1_public = self
            .local_storage
            .retrieve::<tpresign_storage::RoundOnePublicBroadcast>(pid)?;
        let presign_r3_public = self
            .local_storage
            .retrieve::<tpresign_storage::RoundThreePublic<C>>(pid)?;
        let presign_r2_broadcast = self
            .local_storage
            .retrieve::<tpresign_storage::RoundTwoPublicBroadcast>(pid)?;

        let mut D_hat = self
            .local_storage
            .retrieve::<tpresign_storage::RoundTwoPublicISent<C>>(pid)?
            .D_hat
            .0
            .clone();
        self.other_participant_ids
            .iter()
            .map(|other_pid| {
                let m = self
                    .local_storage
                    .retrieve::<tpresign_storage::RoundTwoPublicBroadcast>(*other_pid)?;
                m.iter().filter(|m| m.verifier_pid == pid).for_each(|m| {
                    D_hat = D_hat.modmul(&m.D_hat.0, paillier_enc_key.0.nn());
                });
                Ok(())
            })
            .collect::<Result<Vec<_>>>()?;

        presign_r2_broadcast.iter().for_each(|m| {
            D_hat = D_hat.modmul(&m.F_hat.0, paillier_enc_key.0.nn());
        });
        let S = presign_r3_public.S.clone();

        let mut dec_transcript = Transcript::new(b"PiDecProof");

        let res = public.dec_proof.clone().verify(
            PiDecInput::new(
                &paillier_enc_key,
                &presign_r1_public.K,
                &X,
                &Ciphertext(D_hat),
                &S,
                presign_r3_public.Gamma.as_ref(),
            ),
            &self.retrieve_context(),
            &mut dec_transcript,
        );

        if let Err(e) = res {
            error!("Failed to verify PiDecProof: {:?}", e);
            self.local_storage.store_once::<storage::VerifyResult<C>>(
                pid,
                FailedProof::PiDec(public.dec_proof),
            )?;
            return Ok(());
        }

        let mut verifier_pid_counter: HashSet<u128> = HashSet::new();

        for proof in public.affg_star_proofs {
            let verifier_pid = proof.verifier_pid();
            if !verifier_pid_counter.insert(verifier_pid.as_u128()) {
                error!("Duplicate verifier pid found: {}", verifier_pid);
                self.local_storage.store_once::<storage::VerifyResult<C>>(
                    pid,
                    FailedProof::PiAffgStar(proof.clone()),
                )?;
                return Ok(());
            }
            if !self.other_participant_ids.contains(&verifier_pid) && verifier_pid != self.id {
                error!("Verifier pid {} not in other participant ids", verifier_pid);
                self.local_storage.store_once::<storage::VerifyResult<C>>(
                    pid,
                    FailedProof::PiAffgStar(proof.clone()),
                )?;
                return Ok(());
            }
            let mut affg_star_transcript = Transcript::new(b"PiAffgStarProof");

            let presign_r1_public = self
                .local_storage
                .retrieve::<tpresign_storage::RoundOnePublicBroadcast>(verifier_pid)?;
            let presign_r2_broadcast =
                self.local_storage
                    .retrieve::<tpresign_storage::RoundTwoPublicBroadcast>(pid)?;

            let public_broadcast_to_verifier = presign_r2_broadcast
                .iter()
                .find(|m| m.verifier_pid == verifier_pid);

            if let None = public_broadcast_to_verifier {
                error!("Failed to find D for participant {}", verifier_pid);
                self.local_storage.store_once::<storage::VerifyResult<C>>(
                    pid,
                    FailedProof::PiAffgStar(proof.clone()),
                )?;
                return Ok(());
            }

            let public_broadcast_to_verifier = public_broadcast_to_verifier.unwrap();

            let verifier_pk = self.find_auxinfo_public(verifier_pid)?.pk().clone();

            let K = &presign_r1_public.K;
            let D_hat = &public_broadcast_to_verifier.D_hat;
            let F_hat = &public_broadcast_to_verifier.F_hat;

            let res = proof.clone().verify(
                PiAffgStarInput::new(
                    &verifier_pk,
                    &paillier_enc_key,
                    K,
                    D_hat,
                    F_hat,
                    &X,
                    verifier_pid,
                ),
                &self.retrieve_context(),
                &mut affg_star_transcript,
            );

            if let Err(e) = res {
                error!("Failed to verify PiAffgStarProof: {:?}", e);
                self.local_storage.store_once::<storage::VerifyResult<C>>(
                    pid,
                    FailedProof::PiAffgStar(proof.clone()),
                )?;
                return Ok(());
            }
        }

        self.local_storage
            .store_once::<storage::VerifyResult<C>>(pid, FailedProof::None)?;

        Ok(())
    }

    fn is_r1_done(&self) -> bool {
        self.local_storage
            .contains_for_all_ids::<storage::VerifyResult<C>>(&self.other_participant_ids)
    }

    fn gen_output(&mut self) -> Result<Vec<ParticipantIdentifier>> {
        info!("Generating presign abort output.");
        if !self.is_r1_done() {
            error!("Cannot generate output before round one is done.");
            return Err(InternalError::InternalInvariantFailed);
        }

        let mut faulty_participants: Vec<ParticipantIdentifier> = vec![];
        self.other_participant_ids.iter().for_each(|pid| {
            let res = self
                .local_storage
                .retrieve::<storage::VerifyResult<C>>(*pid);
            if let Ok(FailedProof::None) = res {
            } else {
                faulty_participants.push(*pid);
            }
        });
        Ok(faulty_participants)
    }
}
