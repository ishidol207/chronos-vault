#[macro_use]
pub mod errors;
pub mod auxinfo;
pub mod curve;
pub mod k256;
pub mod keygen;
pub mod keyrefresh;
mod local_storage;
pub mod messages;
pub mod p256;
mod paillier;
mod parameters;
mod participant;
pub mod presign;
mod protocol;
mod ring_pedersen;
pub mod sign;
#[cfg(test)]
pub mod test;
pub mod threshold;
pub mod tpresign;
pub mod trecover;
pub mod trefresh;
pub mod tshare;
mod utils;
mod zkp;
mod zkstar;

use crate::presign::*;
use lazy_static::lazy_static;
pub use participant::{ProcessOutcome, ProtocolParticipant};
pub use protocol::{
    participant_config::ParticipantConfig, Identifier, Participant, ParticipantIdentifier,
};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use wasm_bindgen::prelude::*;

use crate::auxinfo::AuxInfoParticipant;
use crate::curve::{CurveTrait, ScalarTrait, SignatureTrait};
use crate::k256::K256;
use crate::messages::{
    AuxinfoMessageType, Message, MessageType, SignMessageType, TpresignAbortMessageType,
    TpresignMessageType, TrecoverMessageType, TrefreshMessageType, TshareMessageType,
};
use crate::sign::non_interactive_sign::participant::SignParticipant;
use crate::sign::non_interactive_sign::share::SignatureShare;
use crate::threshold::ToutofTHelper;
use crate::tpresign::tpresign_abort::TpresignAbortParticipant;
use crate::tpresign::TpresignParticipant;
use crate::trecover::participant::{TrecoverHelperParticipant, TrecoverTargetParticipant};
use crate::trefresh::participant::TrefreshParticipant;
use crate::tshare::TshareParticipant;
use serde::Serialize;
use sha3::{Digest, Keccak256};

#[cfg(test)]
mod safe_primes_1024;
#[cfg(test)]
mod safe_primes_512;

type C = K256;

// 세션 키: sid 만으로 세션을 구분합니다. (같은 sid 로 두 번 참가하는 경우 없음)
pub(crate) type SessionKey = u64;


const INITIAL_SESSION_CAPACITY: usize = 64;

lazy_static! {
    pub(crate) static ref TSHAREPARTICIPANT: Arc<RwLock<HashMap<SessionKey, Mutex<TshareParticipant<C>>>>> =
        Arc::new(RwLock::new(HashMap::with_capacity(INITIAL_SESSION_CAPACITY)));
    pub(crate) static ref AUXINFOPARTICIPANT: Arc<RwLock<HashMap<SessionKey, Mutex<AuxInfoParticipant<C>>>>> =
        Arc::new(RwLock::new(HashMap::with_capacity(INITIAL_SESSION_CAPACITY)));
    pub(crate) static ref TREFRESHPARTICIPANT: Arc<RwLock<HashMap<SessionKey, Mutex<TrefreshParticipant<C>>>>> =
        Arc::new(RwLock::new(HashMap::with_capacity(INITIAL_SESSION_CAPACITY)));
    pub(crate) static ref TPRESIGNPARTICIPANT: Arc<RwLock<HashMap<SessionKey, Mutex<TpresignParticipant<C>>>>> =
        Arc::new(RwLock::new(HashMap::with_capacity(INITIAL_SESSION_CAPACITY)));
    pub(crate) static ref SIGNPARTICIPANT: Arc<RwLock<HashMap<SessionKey, Mutex<SignParticipant<C>>>>> =
        Arc::new(RwLock::new(HashMap::with_capacity(INITIAL_SESSION_CAPACITY)));
    pub(crate) static ref TPRESIGNABORTPARTICIPANT: Arc<RwLock<HashMap<SessionKey, Mutex<TpresignAbortParticipant<C>>>>> =
        Arc::new(RwLock::new(HashMap::with_capacity(INITIAL_SESSION_CAPACITY)));
    pub(crate) static ref TRECOVERTARGETPARTICIPANT: Arc<RwLock<HashMap<SessionKey, Mutex<TrecoverTargetParticipant<C>>>>> =
        Arc::new(RwLock::new(HashMap::with_capacity(INITIAL_SESSION_CAPACITY)));
    pub(crate) static ref TRECOVERHELPERPARTICIPANT: Arc<RwLock<HashMap<SessionKey, Mutex<TrecoverHelperParticipant<C>>>>> =
        Arc::new(RwLock::new(HashMap::with_capacity(INITIAL_SESSION_CAPACITY)));
}

pub fn participant_factory(
    participant_type: &str,
    sid: u64,
    id: u64,
    other_participant_ids: &[u64],
    input: &str,
) {
    let session_key: SessionKey = sid;

    match participant_type {
        "AuxInfo" => {
            let participant = AuxInfoParticipant::<C>::new(
                Identifier::from(sid),
                ParticipantIdentifier::from_u64(id),
                ParticipantIdentifier::from_u64_slice(other_participant_ids),
                (),
            )
            .expect("Failed to create AuxInfoParticipant");
            // write 락은 insert 하는 순간만 점유, 이후 즉시 해제
            AUXINFOPARTICIPANT.write().unwrap().insert(session_key, Mutex::new(participant));
        }
        "TShare" => {
            let input: <TshareParticipant<C> as participant::ProtocolParticipant>::Input =
                serde_json::from_str(input).expect("Failed to parse input JSON");
            let participant = TshareParticipant::<C>::new(
                Identifier::from(sid),
                ParticipantIdentifier::from_u64(id),
                ParticipantIdentifier::from_u64_slice(other_participant_ids),
                input,
            )
            .expect("Failed to create TshareParticipant");
            TSHAREPARTICIPANT.write().unwrap().insert(session_key, Mutex::new(participant));
        }
        "TRefresh" => {
            let input: <TrefreshParticipant<C> as participant::ProtocolParticipant>::Input =
                serde_json::from_str(input).expect("Failed to parse input JSON");
            let participant = TrefreshParticipant::<C>::new(
                Identifier::from(sid),
                ParticipantIdentifier::from_u64(id),
                ParticipantIdentifier::from_u64_slice(other_participant_ids),
                input,
            )
            .expect("Failed to create TrefreshParticipant");
            TREFRESHPARTICIPANT.write().unwrap().insert(session_key, Mutex::new(participant));
        }
        "TPreSign" => {
            let input: <TpresignParticipant<C> as participant::ProtocolParticipant>::Input =
                serde_json::from_str(input).expect("Failed to parse input JSON");
            let participant = TpresignParticipant::<C>::new(
                Identifier::from(sid),
                ParticipantIdentifier::from_u64(id),
                ParticipantIdentifier::from_u64_slice(other_participant_ids),
                input,
            )
            .expect("Failed to create TpresignParticipant");
            TPRESIGNPARTICIPANT.write().unwrap().insert(session_key, Mutex::new(participant));
        }
        "TPreSignAbort" => {
            let tpresign_input: <TpresignParticipant<C> as participant::ProtocolParticipant>::Input =
                serde_json::from_str(input).expect("Failed to parse input JSON");

            // read 락으로 HashMap 조회 → 세션 Mutex 로 개별 락
            let local_storage = {
                let map = TPRESIGNPARTICIPANT.read().unwrap();
                let mut participant = map
                    .get(&session_key)
                    .expect("TpresignParticipant not found for session key")
                    .lock().unwrap();
                participant
                    .get_localstorage()
                    .expect("Failed to get local storage from TpresignParticipant")
            };

            let input =
                <TpresignAbortParticipant<C> as participant::ProtocolParticipant>::Input::new(
                    local_storage,
                    tpresign_input.auxinfo_output,
                    tpresign_input.tshare_output,
                );
            let participant = TpresignAbortParticipant::<C>::new(
                Identifier::from(sid),
                ParticipantIdentifier::from_u64(id),
                ParticipantIdentifier::from_u64_slice(other_participant_ids),
                input,
            )
            .expect("Failed to create TpresignAbortParticipant");
            TPRESIGNABORTPARTICIPANT.write().unwrap().insert(session_key, Mutex::new(participant));
        }
        "Sign" => {
            let input: <SignParticipant<C> as participant::ProtocolParticipant>::Input =
                serde_json::from_str(input).expect("Failed to parse input JSON");
            let participant = SignParticipant::<C>::new(
                Identifier::from(sid),
                ParticipantIdentifier::from_u64(id),
                ParticipantIdentifier::from_u64_slice(other_participant_ids),
                input,
            )
            .expect("Failed to create SignParticipant");
            SIGNPARTICIPANT.write().unwrap().insert(session_key, Mutex::new(participant));
        }
        "TRecoverTarget" => {
            let input: <TrecoverTargetParticipant<C> as participant::ProtocolParticipant>::Input =
                serde_json::from_str(input).expect("Failed to parse input JSON");
            let participant = TrecoverTargetParticipant::<C>::new(
                Identifier::from(sid),
                ParticipantIdentifier::from_u64(id),
                ParticipantIdentifier::from_u64_slice(other_participant_ids),
                input,
            )
            .expect("Failed to create TrecoverTargetParticipant");
            TRECOVERTARGETPARTICIPANT.write().unwrap().insert(session_key, Mutex::new(participant));
        }
        "TRecoverHelper" => {
            let input: <TrecoverHelperParticipant<C> as participant::ProtocolParticipant>::Input =
                serde_json::from_str(input).expect("Failed to parse input JSON");
            let participant = TrecoverHelperParticipant::<C>::new(
                Identifier::from(sid),
                ParticipantIdentifier::from_u64(id),
                ParticipantIdentifier::from_u64_slice(other_participant_ids),
                input,
            )
            .expect("Failed to create TrecoverHelperParticipant");
            TRECOVERHELPERPARTICIPANT.write().unwrap().insert(session_key, Mutex::new(participant));
        }
        _ => panic!("Unknown participant type"),
    }
}

pub fn ready_message_factory(participant_type: &str, sid: u64, my_id: u64) -> String {
    match participant_type {
        "AuxInfo" => {
            let message = Message::new(
                MessageType::Auxinfo(AuxinfoMessageType::Ready),
                Identifier::from(sid),
                ParticipantIdentifier::from_u64(my_id),
                Some(ParticipantIdentifier::from_u64(my_id)),
                false,
                b"init",
            )
            .expect("Failed to create ready message for AuxInfoParticipant");

            let message_json =
                serde_json::to_string(&message).expect("Failed to serialize message to JSON");
            return message_json;
        }
        "TShare" => {
            let message = Message::new(
                MessageType::Tshare(TshareMessageType::Ready),
                Identifier::from(sid),
                ParticipantIdentifier::from_u64(my_id),
                Some(ParticipantIdentifier::from_u64(my_id)),
                false,
                b"init",
            )
            .expect("Failed to create ready message for TshareParticipant");

            let message_json =
                serde_json::to_string(&message).expect("Failed to serialize message to JSON");
            return message_json;
        }
        "TRefresh" => {
            let message = Message::new(
                MessageType::Trefresh(TrefreshMessageType::Ready),
                Identifier::from(sid),
                ParticipantIdentifier::from_u64(my_id),
                Some(ParticipantIdentifier::from_u64(my_id)),
                false,
                b"init",
            )
            .expect("Failed to create ready message for TrefreshParticipant");

            let message_json =
                serde_json::to_string(&message).expect("Failed to serialize message to JSON");
            return message_json;
        }
        "TPreSign" => {
            let message = Message::new(
                MessageType::Tpresign(TpresignMessageType::Ready),
                Identifier::from(sid),
                ParticipantIdentifier::from_u64(my_id),
                Some(ParticipantIdentifier::from_u64(my_id)),
                false,
                b"init",
            )
            .expect("Failed to create ready message for TpresignParticipant");

            let message_json =
                serde_json::to_string(&message).expect("Failed to serialize message to JSON");
            return message_json;
        }
        "TPresignAbortDelta" => {
            let message = Message::new(
                MessageType::TpresignAbort(TpresignAbortMessageType::ReadyDelta),
                Identifier::from(sid),
                ParticipantIdentifier::from_u64(my_id),
                Some(ParticipantIdentifier::from_u64(my_id)),
                false,
                b"init",
            )
            .expect("Failed to create ready message for TpresignAbortParticipant");

            let message_json =
                serde_json::to_string(&message).expect("Failed to serialize message to JSON");
            return message_json;
        }
        "TPresignAbortS" => {
            let message = Message::new(
                MessageType::TpresignAbort(TpresignAbortMessageType::ReadyS),
                Identifier::from(sid),
                ParticipantIdentifier::from_u64(my_id),
                Some(ParticipantIdentifier::from_u64(my_id)),
                false,
                b"init",
            )
            .expect("Failed to create ready message for TpresignAbortParticipant");

            let message_json =
                serde_json::to_string(&message).expect("Failed to serialize message to JSON");
            return message_json;
        }
        "Sign" => {
            let message = Message::new(
                MessageType::Sign(SignMessageType::Ready),
                Identifier::from(sid),
                ParticipantIdentifier::from_u64(my_id),
                Some(ParticipantIdentifier::from_u64(my_id)),
                false,
                b"init",
            )
            .expect("Failed to create ready message for SignParticipant");

            let message_json =
                serde_json::to_string(&message).expect("Failed to serialize message to JSON");
            return message_json;
        }
        "TRecoverHelper" => {
            let message = Message::new(
                MessageType::Trecover(TrecoverMessageType::Ready),
                Identifier::from(sid),
                ParticipantIdentifier::from_u64(my_id),
                Some(ParticipantIdentifier::from_u64(my_id)),
                false,
                b"init",
            )
            .expect("Failed to create ready message for TrecoverHelperParticipant");

            let message_json =
                serde_json::to_string(&message).expect("Failed to serialize message to JSON");
            return message_json;
        }
        _ => panic!("Unknown participant type"),
    };
}

pub fn delegate_process_message(participant_type: &str, sid: u64, message: &str) -> String {
    let message: Message = serde_json::from_str(message).expect("Failed to parse message JSON");
    let mut rng = rand::thread_rng();

    let session_key: SessionKey = sid;

    match participant_type {
        "AuxInfo" => {
            let map = AUXINFOPARTICIPANT.read().unwrap();
            let mut participant = map
                .get(&session_key)
                .expect("AuxInfoParticipant not found for session key")
                .lock().unwrap();
            let res = participant
                .process_message(&mut rng, &message)
                .expect("Failed to process message in AuxInfoParticipant");
            serde_json::to_string(&res).expect("Failed to serialize response to JSON")
        }
        "TShare" => {
            let map = TSHAREPARTICIPANT.read().unwrap();
            let mut participant = map
                .get(&session_key)
                .expect("TshareParticipant not found for session key")
                .lock().unwrap();
            let res = participant
                .process_message(&mut rng, &message)
                .expect("Failed to process message in TshareParticipant");
            serde_json::to_string(&res).expect("Failed to serialize response to JSON")
        }
        "TRefresh" => {
            let map = TREFRESHPARTICIPANT.read().unwrap();
            let mut participant = map
                .get(&session_key)
                .expect("TrefreshParticipant not found for session key")
                .lock().unwrap();
            let res = participant
                .process_message(&mut rng, &message)
                .expect("Failed to process message in TrefreshParticipant");
            serde_json::to_string(&res).expect("Failed to serialize response to JSON")
        }
        "TPreSign" => {
            let map = TPRESIGNPARTICIPANT.read().unwrap();
            let mut participant = map
                .get(&session_key)
                .expect("TpresignParticipant not found for session key")
                .lock().unwrap();
            let res = participant
                .process_message(&mut rng, &message)
                .expect("Failed to process message in TpresignParticipant");
            serde_json::to_string(&res).expect("Failed to serialize response to JSON")
        }
        "TPresignAbort" => {
            let map = TPRESIGNABORTPARTICIPANT.read().unwrap();
            let mut participant = map
                .get(&session_key)
                .expect("TpresignAbortParticipant not found for session key")
                .lock().unwrap();
            let res = participant
                .process_message(&mut rng, &message)
                .expect("Failed to process message in TpresignAbortParticipant");
            serde_json::to_string(&res).expect("Failed to serialize response to JSON")
        }
        "Sign" => {
            let map = SIGNPARTICIPANT.read().unwrap();
            let mut participant = map
                .get(&session_key)
                .expect("SignParticipant not found for session key")
                .lock().unwrap();
            let res = participant
                .process_message(&mut rng, &message)
                .expect("Failed to process message in SignParticipant");
            serde_json::to_string(&res).expect("Failed to serialize response to JSON")
        }
        "TRecoverTarget" => {
            let map = TRECOVERTARGETPARTICIPANT.read().unwrap();
            let mut participant = map
                .get(&session_key)
                .expect("TrecoverTargetParticipant not found for session key")
                .lock().unwrap();
            let res = participant
                .process_message(&mut rng, &message)
                .expect("Failed to process message in TrecoverTargetParticipant");
            serde_json::to_string(&res).expect("Failed to serialize response to JSON")
        }
        "TRecoverHelper" => {
            let map = TRECOVERHELPERPARTICIPANT.read().unwrap();
            let mut participant = map
                .get(&session_key)
                .expect("TrecoverHelperParticipant not found for session key")
                .lock().unwrap();
            let res = participant
                .process_message(&mut rng, &message)
                .expect("Failed to process message in TrecoverHelperParticipant");
            serde_json::to_string(&res).expect("Failed to serialize response to JSON")
        }
        _ => panic!("Unknown participant type"),
    }
}

/// 세션 완료 후 메모리에서 참여자 객체를 제거합니다.
/// 해당 세션의 프로토콜 라운드를 모두 마친 뒤 호출합니다.
pub fn remove_session(participant_type: &str, sid: u64) {
    let session_key: SessionKey = sid;
    match participant_type {
        "AuxInfo"         => { AUXINFOPARTICIPANT.write().unwrap().remove(&session_key); }
        "TShare"          => { TSHAREPARTICIPANT.write().unwrap().remove(&session_key); }
        "TRefresh"        => { TREFRESHPARTICIPANT.write().unwrap().remove(&session_key); }
        "TPreSign"        => { TPRESIGNPARTICIPANT.write().unwrap().remove(&session_key); }
        "TPreSignAbort"   => { TPRESIGNABORTPARTICIPANT.write().unwrap().remove(&session_key); }
        "Sign"            => { SIGNPARTICIPANT.write().unwrap().remove(&session_key); }
        "TRecoverTarget"  => { TRECOVERTARGETPARTICIPANT.write().unwrap().remove(&session_key); }
        "TRecoverHelper"  => { TRECOVERHELPERPARTICIPANT.write().unwrap().remove(&session_key); }
        _ => panic!("Unknown participant type"),
    }
}

pub fn generate_tshare_input(auxinfo_output: &str, threshold: usize) -> String {
    let auxinfo_output: auxinfo::Output =
        serde_json::from_str(auxinfo_output).expect("Failed to parse auxinfo output JSON");

    let input: tshare::Input<C> =
        tshare::Input::new(auxinfo_output, None, threshold).expect("Failed to create tshare input");
    let input_json =
        serde_json::to_string(&input).expect("Failed to serialize tshare input to JSON");
    input_json
}

pub fn generate_trefresh_input(
    tshare_output: &str,
    auxinfo_output: &str,
    threshold: usize,
) -> String {
    let tshare_output: tshare::Output<C> =
        serde_json::from_str(tshare_output).expect("Failed to parse tshare output JSON");
    let auxinfo_output: auxinfo::Output =
        serde_json::from_str(auxinfo_output).expect("Failed to parse auxinfo output JSON");

    let input = trefresh::input::Input::new(auxinfo_output, tshare_output, threshold)
        .expect("Failed to create trefresh input");
    let input_json =
        serde_json::to_string(&input).expect("Failed to serialize trefresh input to JSON");
    input_json
}

pub fn generate_tpresign_input(
    signer_participant_ids: &[u64],
    auxinfo_output: &str,
    tshare_output: &str,
) -> String {
    let auxinfo_output: auxinfo::Output =
        serde_json::from_str(auxinfo_output).expect("Failed to parse auxinfo output JSON");
    let tshare_output: tshare::Output<C> =
        serde_json::from_str(tshare_output).expect("Failed to parse trefresh output JSON");

    let signer_auxinfo_output = {
        let signer_public_auxinfo: Vec<_> = auxinfo_output
            .public_auxinfo()
            .iter()
            .filter(|info| signer_participant_ids.contains(&(info.participant().as_u128() as u64)))
            .cloned()
            .collect();

        auxinfo::Output::from_parts(
            signer_public_auxinfo,
            auxinfo_output.private_auxinfo().clone(),
        )
        .expect("Failed to create signer auxinfo output")
    };

    let signer_tshare_output = {
        let signer_public_key_shares: Vec<_> = tshare_output
            .public_key_shares()
            .iter()
            .filter(|share| {
                signer_participant_ids.contains(&(share.participant().as_u128() as u64))
            })
            .cloned()
            .collect();

        tshare::Output::new(
            signer_public_key_shares,
            tshare_output.private_key_share().clone(),
            *tshare_output.rid(),
            tshare_output.threshold(),
        )
    };

    let input = tpresign::input::Input::new(signer_auxinfo_output, signer_tshare_output)
        .expect("Failed to create tpresign input");
    let input_json =
        serde_json::to_string(&input).expect("Failed to serialize tpresign input to JSON");
    input_json
}

/// signer_participant_ids 는 my_id 를 포함합니다
pub fn generate_sign_input(
    my_id: u64,
    signer_participant_ids: &[u64],
    tpresign_output: &str,
    tshare_output: &str,
    message_bytes: &[u8],
    threshold: usize,
) -> String {
    let tpresign_output: tpresign::TpresignRecord<C> =
        serde_json::from_str(tpresign_output).expect("Failed to parse presign output JSON");
    let tshare_output: tshare::Output<C> =
        serde_json::from_str(tshare_output).expect("Failed to parse trefresh output JSON");

    let signer_tshare_output = {
        let signer_public_key_shares: Vec<_> = tshare_output
            .public_key_shares()
            .iter()
            .filter(|share| {
                signer_participant_ids.contains(&(share.participant().as_u128() as u64))
            })
            .cloned()
            .collect();
        tshare::Output::new(
            signer_public_key_shares,
            tshare_output.private_key_share().clone(),
            *tshare_output.rid(),
            tshare_output.threshold(),
        )
    };

    let tshare = ToutofTHelper::<C>::convert_to_t_out_of_t_share(
        &ParticipantIdentifier::from_u64(my_id),
        &ParticipantIdentifier::from_u64_slice(signer_participant_ids),
        &signer_tshare_output,
        *tshare_output.rid(),
    )
    .expect("Failed to convert t-of-n share to t-of-t share");

    let input = sign::non_interactive_sign::participant::Input::new(
        message_bytes,
        tpresign_output.into(),
        tshare.public_key_shares().to_vec(),
        threshold,
    );
    let input_json = serde_json::to_string(&input).expect("Failed to serialize sign input to JSON");
    input_json
}

pub fn generate_trecover_helper_input(
    helper_participant_ids: &[u64],
    my_participant_id: u64,
    target_participant_id: u64,
    tshare_output: &str,
    auxinfo_output: &str,
    threshold: usize,
) -> String {
    let tshare_output: tshare::Output<C> =
        serde_json::from_str(tshare_output).expect("Failed to parse tshare output JSON");
    let auxinfo_output: auxinfo::Output =
        serde_json::from_str(auxinfo_output).expect("Failed to parse auxinfo output JSON");

    let helper_tshare_output = {
        let helper_public_key_shares: Vec<_> = tshare_output
            .public_key_shares()
            .iter()
            .filter(|share| {
                helper_participant_ids.contains(&(share.participant().as_u128() as u64))
            })
            .cloned()
            .collect();
        tshare::Output::new(
            helper_public_key_shares,
            tshare_output.private_key_share().clone(),
            *tshare_output.rid(),
            tshare_output.threshold(),
        )
    };

    let helper_auxinfo_output = {
        let helper_public_auxinfo: Vec<_> = auxinfo_output
            .public_auxinfo()
            .iter()
            .filter(|info| helper_participant_ids.contains(&(info.participant().as_u128() as u64)))
            .cloned()
            .collect();

        auxinfo::Output::from_parts(
            helper_public_auxinfo,
            auxinfo_output.private_auxinfo().clone(),
        )
        .expect("Failed to create helper auxinfo output")
    };

    let other_participant_ids: Vec<u64> = helper_participant_ids
        .iter()
        .cloned()
        .filter(|&id| id != my_participant_id)
        .collect();

    let input = trecover::input::HelperInput::new(
        threshold,
        ParticipantIdentifier::from_u64_slice(&other_participant_ids),
        ParticipantIdentifier::from_u64(target_participant_id),
        helper_tshare_output,
        helper_auxinfo_output,
    );
    let input_json =
        serde_json::to_string(&input).expect("Failed to serialize trecover input to JSON");
    input_json
}

pub fn generate_trecover_target_input(
    helper_participant_ids: &[u64],
    auxinfo_output: &str,
    threshold: usize,
) -> String {
    let auxinfo_output: auxinfo::Output =
        serde_json::from_str(auxinfo_output).expect("Failed to parse auxinfo output JSON");
    let helper_auxinfo_output = {
        let helper_public_auxinfo: Vec<_> = auxinfo_output
            .public_auxinfo()
            .iter()
            .filter(|info| helper_participant_ids.contains(&(info.participant().as_u128() as u64)))
            .cloned()
            .collect();

        auxinfo::Output::from_parts(
            helper_public_auxinfo,
            auxinfo_output.private_auxinfo().clone(),
        )
        .expect("Failed to create helper auxinfo output")
    };

    let input = trecover::input::TargetInput::new(
        threshold,
        ParticipantIdentifier::from_u64_slice(helper_participant_ids),
        helper_auxinfo_output,
    );
    let input_json =
        serde_json::to_string(&input).expect("Failed to serialize trecover input to JSON");
    input_json
}

pub fn get_master_pk(tshare_output: &str) -> String {
    let tshare_output: tshare::Output<C> =
        serde_json::from_str(tshare_output).expect("Failed to parse tshare output JSON");

    let master_pk = tshare_output
        .public_key()
        .expect("Failed to compute master key");
    let master_pk_json =
        serde_json::to_string(&master_pk).expect("Failed to serialize master pk to JSON");
    master_pk_json
}

#[derive(Serialize)]
pub struct EthereumSignatureJson {
    pub r: String,
    pub s: String,
    pub v: u64,
}
