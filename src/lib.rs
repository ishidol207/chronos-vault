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
use jni::objects::{JByteArray, JClass, JObject, JObjectArray, JString};
use jni::sys::{jint, jstring};
use jni::JNIEnv;
use lazy_static::lazy_static;
pub use participant::ProtocolParticipant;
pub use protocol::{
    participant_config::ParticipantConfig, Identifier, Participant, ParticipantIdentifier,
};
use std::collections::HashMap;
use std::panic::{self, AssertUnwindSafe};
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
/// Java 서버에서 프로토콜 라운드가 모두 끝난 뒤 반드시 호출해야 메모리 누수를 방지합니다.
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

// --- JNI 타입 변환을 위한 유틸리티 모듈 ---
mod jni_utils {
    use jni::objects::{JObject, JObjectArray, JString};
    use jni::sys::jsize;
    use jni::JNIEnv;

    pub fn convert_jstring_array_to_vec_u64(env: &mut JNIEnv, arr: JObjectArray) -> Vec<u64> {
        let len = env
            .get_array_length(&arr)
            .expect("Failed to get array length");
        if len == 0 {
            return Vec::new();
        }

        let mut rust_vec: Vec<u64> = Vec::with_capacity(len as usize);

        for i in 0..len {
            let element_obj = env
                .get_object_array_element(&arr, i as jsize)
                .expect("Failed to get element at index");

            let element_jstring = JString::from(element_obj);

            rust_vec.push(convert_jstring_to_u64(env, element_jstring));
        }

        rust_vec
    }

    pub fn convert_jstring_to_u64(env: &mut JNIEnv, str: JString) -> u64 {
        // 1. JString을 Rust의 String으로 변환합니다.
        let rust_str: String = env
            .get_string(&str)
            .expect("Failed to get Java string")
            .into();

        // 2. 변환된 String을 u64로 파싱합니다.
        rust_str
            .parse::<u64>()
            .expect("Failed to parse string as u64")
    }
}

// --- JNI Exported Functions ---

/// Java: com.zkrypto.cryptolib.TssBridge.participantFactory
#[no_mangle]
pub extern "C" fn Java_com_zkrypto_cryptolib_TssBridge_participantFactory<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    participant_type: JString<'local>,
    sid: JString<'local>,
    id: JString<'local>,
    other_participant_ids: JObjectArray<'local>,
    input: JString<'local>,
) {
    let result = panic::catch_unwind(AssertUnwindSafe(|| {
        let participant_type_str: String = env
            .get_string(&participant_type)
            .expect("Couldn't get string")
            .into();
        let other_ids_vec: Vec<u64> =
            jni_utils::convert_jstring_array_to_vec_u64(&mut env, other_participant_ids);
        let input_str: String = env.get_string(&input).expect("Couldn't get string").into();

        // 원본 함수의 로직을 그대로 사용
        participant_factory(
            &participant_type_str,
            jni_utils::convert_jstring_to_u64(&mut env, sid),
            jni_utils::convert_jstring_to_u64(&mut env, id),
            &other_ids_vec,
            &input_str,
        );
    }));

    if result.is_err() {
        env.throw_new(
            "java/lang/RuntimeException",
            "Rust panic occurred in participantFactory",
        )
        .unwrap();
    }
}

/// Java: com.zkrypto.cryptolib.TssBridge.readyMessageFactory
#[no_mangle]
pub extern "C" fn Java_com_zkrypto_cryptolib_TssBridge_readyMessageFactory<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    participant_type: JString<'local>,
    sid: JString<'local>,
    my_id: JString<'local>,
) -> jstring {
    let result = panic::catch_unwind(AssertUnwindSafe(|| {
        let participant_type_str: String = env
            .get_string(&participant_type)
            .expect("Couldn't get string")
            .into();
        let message_json = ready_message_factory(
            &participant_type_str,
            jni_utils::convert_jstring_to_u64(&mut env, sid),
            jni_utils::convert_jstring_to_u64(&mut env, my_id),
        );
        env.new_string(message_json)
            .expect("Couldn't create java string!")
            .into_raw()
    }));

    match result {
        Ok(jstr) => jstr,
        Err(_) => {
            env.throw_new(
                "java/lang/RuntimeException",
                "Rust panic in readyMessageFactory",
            )
            .unwrap();
            JObject::null().into_raw()
        }
    }
}

/// Java: com.zkrypto.cryptolib.TssBridge.delegateProcessMessage
/// 시그니처 변경: sid 파라미터 추가 (세션 구분을 위해 Java에서 넘겨야 합니다)
#[no_mangle]
pub extern "C" fn Java_com_zkrypto_cryptolib_TssBridge_delegateProcessMessage<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    participant_type: JString<'local>,
    sid: JString<'local>,
    message: JString<'local>,
) -> jstring {
    let result = panic::catch_unwind(AssertUnwindSafe(|| {
        let participant_type_str: String = env
            .get_string(&participant_type)
            .expect("Couldn't get string")
            .into();
        let message_str: String = env
            .get_string(&message)
            .expect("Couldn't get string")
            .into();
        let res_json = delegate_process_message(
            &participant_type_str,
            jni_utils::convert_jstring_to_u64(&mut env, sid),
            &message_str,
        );
        env.new_string(res_json)
            .expect("Couldn't create java string!")
            .into_raw()
    }));

    match result {
        Ok(jstr) => jstr,
        Err(_) => {
            env.throw_new(
                "java/lang/RuntimeException",
                "Rust panic in delegateProcessMessage",
            )
            .unwrap();
            JObject::null().into_raw()
        }
    }
}

/// Java: com.zkrypto.cryptolib.TssBridge.generateTshareInput
#[no_mangle]
pub extern "C" fn Java_com_zkrypto_cryptolib_TssBridge_generateTshareInput<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    auxinfo_output: JString<'local>,
    threshold: jint,
) -> jstring {
    let result = panic::catch_unwind(AssertUnwindSafe(|| {
        let auxinfo_output_str: String = env
            .get_string(&auxinfo_output)
            .expect("Couldn't get string")
            .into();
        let input_json = generate_tshare_input(&auxinfo_output_str, threshold as usize);
        env.new_string(input_json)
            .expect("Couldn't create java string!")
            .into_raw()
    }));

    match result {
        Ok(jstr) => jstr,
        Err(_) => {
            env.throw_new(
                "java/lang/RuntimeException",
                "Rust panic in generateTshareInput",
            )
            .unwrap();
            JObject::null().into_raw()
        }
    }
}

/// Java: com.zkrypto.cryptolib.TssBridge.generateTrefreshInput
#[no_mangle]
pub extern "C" fn Java_com_zkrypto_cryptolib_TssBridge_generateTrefreshInput<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    tshare_output: JString<'local>,
    auxinfo_output: JString<'local>,
    threshold: jint,
) -> jstring {
    let result = panic::catch_unwind(AssertUnwindSafe(|| {
        let tshare_output_str: String = env
            .get_string(&tshare_output)
            .expect("Couldn't get string")
            .into();
        let auxinfo_output_str: String = env
            .get_string(&auxinfo_output)
            .expect("Couldn't get string")
            .into();
        let input_json =
            generate_trefresh_input(&tshare_output_str, &auxinfo_output_str, threshold as usize);
        env.new_string(input_json)
            .expect("Couldn't create java string!")
            .into_raw()
    }));

    match result {
        Ok(jstr) => jstr,
        Err(_) => {
            env.throw_new(
                "java/lang/RuntimeException",
                "Rust panic in generateTrefreshInput",
            )
            .unwrap();
            JObject::null().into_raw()
        }
    }
}

/// Java: com.zkrypto.cryptolib.TssBridge.generateTpresignInput
#[no_mangle]
pub extern "C" fn Java_com_zkrypto_cryptolib_TssBridge_generateTpresignInput<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    signer_participant_ids: JObjectArray<'local>,
    auxinfo_output: JString<'local>,
    tshare_output: JString<'local>,
) -> jstring {
    let result = panic::catch_unwind(AssertUnwindSafe(|| {
        let signer_ids_vec =
            jni_utils::convert_jstring_array_to_vec_u64(&mut env, signer_participant_ids);
        let auxinfo_output_str: String = env
            .get_string(&auxinfo_output)
            .expect("Couldn't get string")
            .into();
        let tshare_output_str: String = env
            .get_string(&tshare_output)
            .expect("Couldn't get string")
            .into();
        let input_json =
            generate_tpresign_input(&signer_ids_vec, &auxinfo_output_str, &tshare_output_str);
        env.new_string(input_json)
            .expect("Couldn't create java string!")
            .into_raw()
    }));

    match result {
        Ok(jstr) => jstr,
        Err(_) => {
            env.throw_new(
                "java/lang/RuntimeException",
                "Rust panic in generateTpresignInput",
            )
            .unwrap();
            JObject::null().into_raw()
        }
    }
}

/// Java: com.zkrypto.cryptolib.TssBridge.generateSignInput
#[no_mangle]
pub extern "C" fn Java_com_zkrypto_cryptolib_TssBridge_generateSignInput<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    my_id: JString<'local>,
    signer_participant_ids: JObjectArray<'local>,
    tpresign_output: JString<'local>,
    tshare_output: JString<'local>,
    message_bytes: JByteArray,
    threshold: jint,
) -> jstring {
    let result = panic::catch_unwind(AssertUnwindSafe(|| {
        let signer_ids_vec =
            jni_utils::convert_jstring_array_to_vec_u64(&mut env, signer_participant_ids);
        let tpresign_output_str: String = env
            .get_string(&tpresign_output)
            .expect("Couldn't get string")
            .into();
        let tshare_output_str: String = env
            .get_string(&tshare_output)
            .expect("Couldn't get string")
            .into();
        let message_vec: Vec<u8> = env
            .convert_byte_array(message_bytes)
            .expect("Couldn't convert byte array");

        let input_json = generate_sign_input(
            jni_utils::convert_jstring_to_u64(&mut env, my_id),
            &signer_ids_vec,
            &tpresign_output_str,
            &tshare_output_str,
            &message_vec,
            threshold as usize,
        );
        env.new_string(input_json)
            .expect("Couldn't create java string!")
            .into_raw()
    }));

    match result {
        Ok(jstr) => jstr,
        Err(_) => {
            env.throw_new(
                "java/lang/RuntimeException",
                "Rust panic in generateSignInput",
            )
            .unwrap();
            JObject::null().into_raw()
        }
    }
}

/// Java: com.zkrypto.cryptolib.TssBridge.generateTrecoverHelperInput
#[no_mangle]
pub extern "C" fn Java_com_zkrypto_cryptolib_TssBridge_generateTrecoverHelperInput<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    helper_participant_ids: JObjectArray<'local>,
    my_participant_id: JString<'local>,
    target_participant_id: JString<'local>,
    tshare_output: JString<'local>,
    auxinfo_output: JString<'local>,
    threshold: jint,
) -> jstring {
    let result = panic::catch_unwind(AssertUnwindSafe(|| {
        let helper_ids_vec =
            jni_utils::convert_jstring_array_to_vec_u64(&mut env, helper_participant_ids);
        let tshare_output_str: String = env
            .get_string(&tshare_output)
            .expect("Couldn't get string")
            .into();
        let auxinfo_output_str: String = env
            .get_string(&auxinfo_output)
            .expect("Couldn't get string")
            .into();

        let input_json = generate_trecover_helper_input(
            &helper_ids_vec,
            jni_utils::convert_jstring_to_u64(&mut env, my_participant_id),
            jni_utils::convert_jstring_to_u64(&mut env, target_participant_id),
            &tshare_output_str,
            &auxinfo_output_str,
            threshold as usize,
        );
        env.new_string(input_json)
            .expect("Couldn't create java string!")
            .into_raw()
    }));

    match result {
        Ok(jstr) => jstr,
        Err(_) => {
            env.throw_new(
                "java/lang/RuntimeException",
                "Rust panic in generateTrecoverHelperInput",
            )
            .unwrap();
            JObject::null().into_raw()
        }
    }
}

/// Java: com.zkrypto.cryptolib.TssBridge.generateTrecoverTargetInput
#[no_mangle]
pub extern "C" fn Java_com_zkrypto_cryptolib_TssBridge_generateTrecoverTargetInput<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    helper_participant_ids: JObjectArray,
    auxinfo_output: JString<'local>,
    threshold: jint,
) -> jstring {
    let result = panic::catch_unwind(AssertUnwindSafe(|| {
        let helper_ids_vec =
            jni_utils::convert_jstring_array_to_vec_u64(&mut env, helper_participant_ids);
        let auxinfo_output_str: String = env
            .get_string(&auxinfo_output)
            .expect("Couldn't get string")
            .into();

        let input_json = generate_trecover_target_input(
            &helper_ids_vec,
            &auxinfo_output_str,
            threshold as usize,
        );
        env.new_string(input_json)
            .expect("Couldn't create java string!")
            .into_raw()
    }));

    match result {
        Ok(jstr) => jstr,
        Err(_) => {
            env.throw_new(
                "java/lang/RuntimeException",
                "Rust panic in generateTrecoverTargetInput",
            )
            .unwrap();
            JObject::null().into_raw()
        }
    }
}

/// Java: com.zkrypto.cryptolib.TssBridge.removeSession
/// 프로토콜 완료 후 세션 메모리를 해제합니다. Java 서버에서 반드시 호출하세요.
#[no_mangle]
pub extern "C" fn Java_com_zkrypto_cryptolib_TssBridge_removeSession<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    participant_type: JString<'local>,
    sid: JString<'local>,
) {
    let result = panic::catch_unwind(AssertUnwindSafe(|| {
        let participant_type_str: String = env
            .get_string(&participant_type)
            .expect("Couldn't get string")
            .into();
        remove_session(
            &participant_type_str,
            jni_utils::convert_jstring_to_u64(&mut env, sid),
        );
    }));

    if result.is_err() {
        env.throw_new(
            "java/lang/RuntimeException",
            "Rust panic occurred in removeSession",
        )
        .unwrap();
    }
}

/// Java: com.zkrypto.cryptolib.TssBridge.getMasterKey
#[no_mangle]
pub extern "C" fn Java_com_zkrypto_cryptolib_TssBridge_getMasterKey<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    tshare_output: JString<'local>,
) -> jstring {
    let result = panic::catch_unwind(AssertUnwindSafe(|| {
        let tshare_output_str: String = env
            .get_string(&tshare_output)
            .expect("Couldn't get string")
            .into();

        let master_pk_json = get_master_pk(&tshare_output_str);

        env.new_string(master_pk_json)
            .expect("Couldn't create java string!")
            .into_raw()
    }));

    match result {
        Ok(jstr) => jstr,
        Err(_) => {
            env.throw_new(
                "java/lang/RuntimeException",
                "Rust panic in getMasterKey",
            )
            .unwrap();
            JObject::null().into_raw()
        }
    }
}