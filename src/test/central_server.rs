use core::panic;
use std::collections::HashMap;

use crate::messages::TpresignAbortMessageType;
use crate::{
    errors::{InternalError, Result},
    messages::{
        AuxinfoMessageType, KeygenMessageType, KeyrefreshMessageType, Message, MessageType,
        PresignMessageType, SignMessageType, TpresignMessageType, TrecoverMessageType,
        TrefreshMessageType, TshareMessageType,
    },
    ParticipantIdentifier,
};

#[derive(PartialEq, Eq, Hash, Clone, Copy, Debug)]
pub enum Protocol {
    Keygen,
    Auxinfo,
    Keyrefresh,
    Presign,
    Sign,
    Tshare,
    Trefresh,
    Tpresign,
    TPresignAbort,
    Trecover,
}

impl MessageType {
    pub fn protocol(&self) -> Protocol {
        match self {
            MessageType::Keygen(_) => Protocol::Keygen,
            MessageType::Auxinfo(_) => Protocol::Auxinfo,
            MessageType::Keyrefresh(_) => Protocol::Keyrefresh,
            MessageType::Presign(_) => Protocol::Presign,
            MessageType::Sign(_) => Protocol::Sign,
            MessageType::Tshare(_) => Protocol::Tshare,
            MessageType::Trefresh(_) => Protocol::Trefresh,
            MessageType::Tpresign(_) => Protocol::Tpresign,
            MessageType::TpresignAbort(_) => Protocol::TPresignAbort,
            MessageType::Trecover(_) => Protocol::Trecover,
        }
    }
}

/// 중앙 서버가 관리할 메시지 저장소
/// 각 프로토콜에 대해 라운드별로 메시지를 저장
pub trait MessageStore {
    /// P_i가 보낸 메시지를 알맞는 inbox에 저장
    fn store(&mut self, msg: Message) -> Result<()>;

    /// P_i가 요청하는 모든 메시지를 가져오고 inbox에서 삭제
    fn fetch(
        &mut self,
        participant_id: &ParticipantIdentifier,
        msg_type: MessageType,
    ) -> Vec<Message>;
}

pub struct CentralServer {
    stores: HashMap<Protocol, Box<dyn MessageStore>>,
    participants: Vec<ParticipantIdentifier>,
}

impl CentralServer {
    pub fn new(participants: Vec<ParticipantIdentifier>) -> Self {
        let mut stores: HashMap<Protocol, Box<dyn MessageStore>> = HashMap::new();

        stores.insert(Protocol::Keygen, Box::new(KeygenInbox::new()));
        stores.insert(Protocol::Auxinfo, Box::new(AuxinfoInbox::new()));
        stores.insert(Protocol::Keyrefresh, Box::new(KeyrefreshInbox::new()));
        stores.insert(Protocol::Presign, Box::new(PresignInbox::new()));
        stores.insert(Protocol::Sign, Box::new(SignInbox::new()));
        stores.insert(Protocol::Tshare, Box::new(TshareInbox::new()));
        stores.insert(Protocol::Trefresh, Box::new(TrefreshInbox::new()));
        stores.insert(Protocol::Tpresign, Box::new(TpresignInbox::new()));
        stores.insert(Protocol::TPresignAbort, Box::new(TpresignAbortInbox::new()));
        stores.insert(Protocol::Trecover, Box::new(TrecoverInbox::new()));

        Self {
            stores,
            participants,
        }
    }

    /// [참여자 API] 참여자가 중앙 서버로 메시지 전송
    pub fn send_message(&mut self, message: Message) -> Result<()> {
        if message.check_is_broadcast() {
            let personal_msgs = self.fill_broadcast_to(message)?;
            for msg in personal_msgs {
                self.route_message(msg)?;
            }
        } else {
            self.route_message(message)?;
        }
        Ok(())
    }

    /// [참여자 API] 참여자가 특정 프로토콜에 대해 자신에게 온 모든 메시지를 fetch
    pub fn fetch_messages(
        &mut self,
        msg_type: MessageType,
        participant_id: &ParticipantIdentifier,
    ) -> Vec<Message> {
        if let Some(store) = self.stores.get_mut(&msg_type.protocol()) {
            store.fetch(participant_id, msg_type)
        } else {
            panic!("No store found for message type: {:?}", msg_type);
        }
    }

    /// 메시지 타입에 따라 올바른 inbox 저장소로 메시지를 전달
    fn route_message(&mut self, message: Message) -> Result<()> {
        let msg_type = message.message_type();
        if let Some(store) = self.stores.get_mut(&msg_type.protocol()) {
            store.store(message)
        } else {
            Err(InternalError::InternalInvariantFailed)
        }
    }

    /// 브로드캐스트 메시지 하나를 모든 다른 참여자에게 보내는 개인 메시지 여러 개로 변환
    fn fill_broadcast_to(&self, msg: Message) -> Result<Vec<Message>> {
        let mut personal_msgs = Vec::new();
        let sender_id = msg.from();

        for pid in &self.participants {
            if *pid != sender_id {
                let mut new_msg = msg.clone();
                new_msg.set_to(Some(*pid));
                personal_msgs.push(new_msg);
            }
        }
        Ok(personal_msgs)
    }

    pub fn clear(&mut self) {
        self.stores.clear();
    }
}

pub struct KeygenInbox {
    r1: HashMap<ParticipantIdentifier, Vec<Message>>,
    r2: HashMap<ParticipantIdentifier, Vec<Message>>,
    r3: HashMap<ParticipantIdentifier, Vec<Message>>,
}

impl KeygenInbox {
    pub fn new() -> Self {
        Self {
            r1: HashMap::new(),
            r2: HashMap::new(),
            r3: HashMap::new(),
        }
    }
}

impl MessageStore for KeygenInbox {
    fn store(&mut self, msg: Message) -> Result<()> {
        match msg.message_type() {
            MessageType::Keygen(KeygenMessageType::R1CommitHash) => {
                self.r1
                    .entry(msg.to().unwrap())
                    .or_insert_with(Vec::new)
                    .push(msg);
            }
            MessageType::Keygen(KeygenMessageType::R2Decommit) => {
                self.r2
                    .entry(msg.to().unwrap())
                    .or_insert_with(Vec::new)
                    .push(msg);
            }
            MessageType::Keygen(KeygenMessageType::R3Proof) => {
                self.r3
                    .entry(msg.to().unwrap())
                    .or_insert_with(Vec::new)
                    .push(msg);
            }
            _ => panic!("Invalid message type for KeygenInbox"),
        }
        Ok(())
    }

    fn fetch(
        &mut self,
        participant_id: &ParticipantIdentifier,
        msg_type: MessageType,
    ) -> Vec<Message> {
        match msg_type {
            MessageType::Keygen(KeygenMessageType::R1CommitHash) => {
                self.r1.remove(participant_id).unwrap()
            }
            MessageType::Keygen(KeygenMessageType::R2Decommit) => {
                self.r2.remove(participant_id).unwrap()
            }
            MessageType::Keygen(KeygenMessageType::R3Proof) => {
                self.r3.remove(participant_id).unwrap()
            }
            _ => panic!("Invalid message type for KeygenInbox"),
        }
    }
}

pub struct AuxinfoInbox {
    r1: HashMap<ParticipantIdentifier, Vec<Message>>,
    r2: HashMap<ParticipantIdentifier, Vec<Message>>,
    r3: HashMap<ParticipantIdentifier, Vec<Message>>,
}
impl AuxinfoInbox {
    pub fn new() -> Self {
        Self {
            r1: HashMap::new(),
            r2: HashMap::new(),
            r3: HashMap::new(),
        }
    }
}

impl MessageStore for AuxinfoInbox {
    fn store(&mut self, msg: Message) -> Result<()> {
        match msg.message_type() {
            MessageType::Auxinfo(AuxinfoMessageType::R1CommitHash) => {
                self.r1
                    .entry(msg.to().unwrap())
                    .or_insert_with(Vec::new)
                    .push(msg);
            }
            MessageType::Auxinfo(AuxinfoMessageType::R2Decommit) => {
                self.r2
                    .entry(msg.to().unwrap())
                    .or_insert_with(Vec::new)
                    .push(msg);
            }
            MessageType::Auxinfo(AuxinfoMessageType::R3Proof) => {
                self.r3
                    .entry(msg.to().unwrap())
                    .or_insert_with(Vec::new)
                    .push(msg);
            }
            _ => panic!("Invalid message type for AuxinfoInbox"),
        }
        Ok(())
    }

    fn fetch(
        &mut self,
        participant_id: &ParticipantIdentifier,
        msg_type: MessageType,
    ) -> Vec<Message> {
        match msg_type {
            MessageType::Auxinfo(AuxinfoMessageType::R1CommitHash) => {
                self.r1.remove(participant_id).unwrap()
            }
            MessageType::Auxinfo(AuxinfoMessageType::R2Decommit) => {
                self.r2.remove(participant_id).unwrap()
            }
            MessageType::Auxinfo(AuxinfoMessageType::R3Proof) => {
                self.r3.remove(participant_id).unwrap()
            }
            _ => panic!("Invalid message type for AuxinfoInbox"),
        }
    }
}

pub struct KeyrefreshInbox {
    r1: HashMap<ParticipantIdentifier, Vec<Message>>,
    r2: HashMap<ParticipantIdentifier, Vec<Message>>,
    r3_pub: HashMap<ParticipantIdentifier, Vec<Message>>,
    r3_priv: HashMap<ParticipantIdentifier, Vec<Message>>,
}
impl KeyrefreshInbox {
    pub fn new() -> Self {
        Self {
            r1: HashMap::new(),
            r2: HashMap::new(),
            r3_pub: HashMap::new(),
            r3_priv: HashMap::new(),
        }
    }
}
impl MessageStore for KeyrefreshInbox {
    fn store(&mut self, msg: Message) -> Result<()> {
        match msg.message_type() {
            MessageType::Keyrefresh(KeyrefreshMessageType::R1CommitHash) => {
                self.r1
                    .entry(msg.to().unwrap())
                    .or_insert_with(Vec::new)
                    .push(msg);
            }
            MessageType::Keyrefresh(KeyrefreshMessageType::R2Decommit) => {
                self.r2
                    .entry(msg.to().unwrap())
                    .or_insert_with(Vec::new)
                    .push(msg);
            }
            MessageType::Keyrefresh(KeyrefreshMessageType::R3Proofs) => {
                self.r3_pub
                    .entry(msg.to().unwrap())
                    .or_insert_with(Vec::new)
                    .push(msg);
            }

            MessageType::Keyrefresh(KeyrefreshMessageType::R3PrivateUpdate) => {
                self.r3_priv
                    .entry(msg.to().unwrap())
                    .or_insert_with(Vec::new)
                    .push(msg);
            }
            _ => panic!("Invalid message type for KeyrefreshInbox"),
        }
        Ok(())
    }

    fn fetch(
        &mut self,
        participant_id: &ParticipantIdentifier,
        msg_type: MessageType,
    ) -> Vec<Message> {
        match msg_type {
            MessageType::Keyrefresh(KeyrefreshMessageType::R1CommitHash) => {
                self.r1.remove(participant_id).unwrap()
            }
            MessageType::Keyrefresh(KeyrefreshMessageType::R2Decommit) => {
                self.r2.remove(participant_id).unwrap()
            }
            MessageType::Keyrefresh(KeyrefreshMessageType::R3Proofs) => {
                self.r3_pub.remove(participant_id).unwrap()
            }
            MessageType::Keyrefresh(KeyrefreshMessageType::R3PrivateUpdate) => {
                self.r3_priv.remove(participant_id).unwrap()
            }
            _ => panic!("Invalid message type for KeyrefreshInbox"),
        }
    }
}

pub struct PresignInbox {
    r1_priv: HashMap<ParticipantIdentifier, Vec<Message>>,
    r1_pub: HashMap<ParticipantIdentifier, Vec<Message>>,
    r2: HashMap<ParticipantIdentifier, Vec<Message>>,
    r3: HashMap<ParticipantIdentifier, Vec<Message>>,
}
impl PresignInbox {
    pub fn new() -> Self {
        Self {
            r1_priv: HashMap::new(),
            r1_pub: HashMap::new(),
            r2: HashMap::new(),
            r3: HashMap::new(),
        }
    }
}

impl MessageStore for PresignInbox {
    fn store(&mut self, msg: Message) -> Result<()> {
        match msg.message_type() {
            MessageType::Presign(PresignMessageType::RoundOne) => {
                self.r1_priv
                    .entry(msg.to().unwrap())
                    .or_insert_with(Vec::new)
                    .push(msg);
            }
            MessageType::Presign(PresignMessageType::RoundOneBroadcast) => {
                self.r1_pub
                    .entry(msg.to().unwrap())
                    .or_insert_with(Vec::new)
                    .push(msg);
            }
            MessageType::Presign(PresignMessageType::RoundTwo) => {
                self.r2
                    .entry(msg.to().unwrap())
                    .or_insert_with(Vec::new)
                    .push(msg);
            }
            MessageType::Presign(PresignMessageType::RoundThree) => {
                self.r3
                    .entry(msg.to().unwrap())
                    .or_insert_with(Vec::new)
                    .push(msg);
            }
            _ => panic!("Invalid message type for PresignInbox"),
        }
        Ok(())
    }

    fn fetch(
        &mut self,
        participant_id: &ParticipantIdentifier,
        msg_type: MessageType,
    ) -> Vec<Message> {
        match msg_type {
            MessageType::Presign(PresignMessageType::RoundOne) => {
                self.r1_priv.remove(participant_id).unwrap()
            }
            MessageType::Presign(PresignMessageType::RoundOneBroadcast) => {
                self.r1_pub.remove(participant_id).unwrap()
            }
            MessageType::Presign(PresignMessageType::RoundTwo) => {
                self.r2.remove(participant_id).unwrap()
            }
            MessageType::Presign(PresignMessageType::RoundThree) => {
                self.r3.remove(participant_id).unwrap()
            }
            _ => panic!("Invalid message type for PresignInbox"),
        }
    }
}

pub struct SignInbox {
    r1: HashMap<ParticipantIdentifier, Vec<Message>>,
}

impl SignInbox {
    pub fn new() -> Self {
        Self { r1: HashMap::new() }
    }
}

impl MessageStore for SignInbox {
    fn store(&mut self, msg: Message) -> Result<()> {
        match msg.message_type() {
            MessageType::Sign(SignMessageType::RoundOneShare) => {
                self.r1
                    .entry(msg.to().unwrap())
                    .or_insert_with(Vec::new)
                    .push(msg);
            }
            _ => panic!("Invalid message type for SignInbox"),
        }
        Ok(())
    }

    fn fetch(
        &mut self,
        participant_id: &ParticipantIdentifier,
        msg_type: MessageType,
    ) -> Vec<Message> {
        match msg_type {
            MessageType::Sign(SignMessageType::RoundOneShare) => {
                self.r1.remove(participant_id).unwrap()
            }
            _ => panic!("Invalid message type for SignInbox"),
        }
    }
}

pub struct TshareInbox {
    r1: HashMap<ParticipantIdentifier, Vec<Message>>,
    r2_priv: HashMap<ParticipantIdentifier, Vec<Message>>,
    r2_pub: HashMap<ParticipantIdentifier, Vec<Message>>,
    r3: HashMap<ParticipantIdentifier, Vec<Message>>,
    pk: HashMap<ParticipantIdentifier, Vec<Message>>,
}

impl TshareInbox {
    pub fn new() -> Self {
        Self {
            r1: HashMap::new(),
            r2_priv: HashMap::new(),
            r2_pub: HashMap::new(),
            r3: HashMap::new(),
            pk: HashMap::new(),
        }
    }
}

impl MessageStore for TshareInbox {
    fn store(&mut self, msg: Message) -> Result<()> {
        match msg.message_type() {
            MessageType::Tshare(TshareMessageType::R1CommitHash) => {
                self.r1
                    .entry(msg.to().unwrap())
                    .or_insert_with(Vec::new)
                    .push(msg);
            }
            MessageType::Tshare(TshareMessageType::R2Decommit) => {
                self.r2_pub
                    .entry(msg.to().unwrap())
                    .or_insert_with(Vec::new)
                    .push(msg);
            }
            MessageType::Tshare(TshareMessageType::R2PrivateShare) => {
                self.r2_priv
                    .entry(msg.to().unwrap())
                    .or_insert_with(Vec::new)
                    .push(msg);
            }
            MessageType::Tshare(TshareMessageType::R3Proof) => {
                self.r3
                    .entry(msg.to().unwrap())
                    .or_insert_with(Vec::new)
                    .push(msg);
            }
            MessageType::Tshare(TshareMessageType::Pk) => {
                self.pk
                    .entry(msg.to().unwrap())
                    .or_insert_with(Vec::new)
                    .push(msg);
            }
            _ => panic!("Invalid message type for TshareInbox"),
        }
        Ok(())
    }

    fn fetch(
        &mut self,
        participant_id: &ParticipantIdentifier,
        msg_type: MessageType,
    ) -> Vec<Message> {
        match msg_type {
            MessageType::Tshare(TshareMessageType::R1CommitHash) => {
                self.r1.remove(participant_id).unwrap()
            }
            MessageType::Tshare(TshareMessageType::R2Decommit) => {
                self.r2_pub.remove(participant_id).unwrap()
            }
            MessageType::Tshare(TshareMessageType::R2PrivateShare) => {
                self.r2_priv.remove(participant_id).unwrap()
            }
            MessageType::Tshare(TshareMessageType::R3Proof) => {
                self.r3.remove(participant_id).unwrap()
            }
            MessageType::Tshare(TshareMessageType::Pk) => self.pk.remove(participant_id).unwrap(),
            _ => panic!("Invalid message type for TshareInbox"),
        }
    }
}

pub struct TrefreshInbox {
    r1: HashMap<ParticipantIdentifier, Vec<Message>>,
    r2_priv: HashMap<ParticipantIdentifier, Vec<Message>>,
    r2_pub: HashMap<ParticipantIdentifier, Vec<Message>>,
    r3: HashMap<ParticipantIdentifier, Vec<Message>>,
}

impl TrefreshInbox {
    pub fn new() -> Self {
        Self {
            r1: HashMap::new(),
            r2_priv: HashMap::new(),
            r2_pub: HashMap::new(),
            r3: HashMap::new(),
        }
    }
}

impl MessageStore for TrefreshInbox {
    fn store(&mut self, msg: Message) -> Result<()> {
        match msg.message_type() {
            MessageType::Trefresh(TrefreshMessageType::R1CommitHash) => {
                self.r1
                    .entry(msg.to().unwrap())
                    .or_insert_with(Vec::new)
                    .push(msg);
            }
            MessageType::Trefresh(TrefreshMessageType::R2Decommit) => {
                self.r2_pub
                    .entry(msg.to().unwrap())
                    .or_insert_with(Vec::new)
                    .push(msg);
            }
            MessageType::Trefresh(TrefreshMessageType::R2PrivateShare) => {
                self.r2_priv
                    .entry(msg.to().unwrap())
                    .or_insert_with(Vec::new)
                    .push(msg);
            }
            MessageType::Trefresh(TrefreshMessageType::R3Proof) => {
                self.r3
                    .entry(msg.to().unwrap())
                    .or_insert_with(Vec::new)
                    .push(msg);
            }
            _ => panic!("Invalid message type for TshareInbox"),
        }
        Ok(())
    }

    fn fetch(
        &mut self,
        participant_id: &ParticipantIdentifier,
        msg_type: MessageType,
    ) -> Vec<Message> {
        match msg_type {
            MessageType::Trefresh(TrefreshMessageType::R1CommitHash) => {
                self.r1.remove(participant_id).unwrap()
            }
            MessageType::Trefresh(TrefreshMessageType::R2Decommit) => {
                self.r2_pub.remove(participant_id).unwrap()
            }
            MessageType::Trefresh(TrefreshMessageType::R2PrivateShare) => {
                self.r2_priv.remove(participant_id).unwrap()
            }
            MessageType::Trefresh(TrefreshMessageType::R3Proof) => {
                self.r3.remove(participant_id).unwrap()
            }
            _ => panic!("Invalid message type for TshareInbox"),
        }
    }
}

pub struct TpresignInbox {
    r1_priv: HashMap<ParticipantIdentifier, Vec<Message>>,
    r1_pub: HashMap<ParticipantIdentifier, Vec<Message>>,
    r2: HashMap<ParticipantIdentifier, Vec<Message>>,
    r2_broadcast: HashMap<ParticipantIdentifier, Vec<Message>>,
    r3: HashMap<ParticipantIdentifier, Vec<Message>>,
}
impl TpresignInbox {
    pub fn new() -> Self {
        Self {
            r1_priv: HashMap::new(),
            r1_pub: HashMap::new(),
            r2: HashMap::new(),
            r2_broadcast: HashMap::new(),
            r3: HashMap::new(),
        }
    }
}

impl MessageStore for TpresignInbox {
    fn store(&mut self, msg: Message) -> Result<()> {
        match msg.message_type() {
            MessageType::Tpresign(TpresignMessageType::RoundOne) => {
                self.r1_priv
                    .entry(msg.to().unwrap())
                    .or_insert_with(Vec::new)
                    .push(msg);
            }
            MessageType::Tpresign(TpresignMessageType::RoundOneBroadcast) => {
                self.r1_pub
                    .entry(msg.to().unwrap())
                    .or_insert_with(Vec::new)
                    .push(msg);
            }
            MessageType::Tpresign(TpresignMessageType::RoundTwo) => {
                self.r2
                    .entry(msg.to().unwrap())
                    .or_insert_with(Vec::new)
                    .push(msg);
            }
            MessageType::Tpresign(TpresignMessageType::RoundTwoBroadcast) => {
                self.r2_broadcast
                    .entry(msg.to().unwrap())
                    .or_insert_with(Vec::new)
                    .push(msg);
            }
            MessageType::Tpresign(TpresignMessageType::RoundThree) => {
                self.r3
                    .entry(msg.to().unwrap())
                    .or_insert_with(Vec::new)
                    .push(msg);
            }
            _ => panic!("Invalid message type for PresignInbox"),
        }
        Ok(())
    }

    fn fetch(
        &mut self,
        participant_id: &ParticipantIdentifier,
        msg_type: MessageType,
    ) -> Vec<Message> {
        match msg_type {
            MessageType::Tpresign(TpresignMessageType::RoundOne) => {
                self.r1_priv.remove(participant_id).unwrap()
            }
            MessageType::Tpresign(TpresignMessageType::RoundOneBroadcast) => {
                self.r1_pub.remove(participant_id).unwrap()
            }
            MessageType::Tpresign(TpresignMessageType::RoundTwo) => {
                self.r2.remove(participant_id).unwrap()
            }
            MessageType::Tpresign(TpresignMessageType::RoundTwoBroadcast) => {
                self.r2_broadcast.remove(participant_id).unwrap()
            }
            MessageType::Tpresign(TpresignMessageType::RoundThree) => {
                self.r3.remove(participant_id).unwrap()
            }
            _ => panic!("Invalid message type for PresignInbox"),
        }
    }
}

pub struct TpresignAbortInbox {
    r1_delta: HashMap<ParticipantIdentifier, Vec<Message>>,
    r1_s: HashMap<ParticipantIdentifier, Vec<Message>>,
}
impl TpresignAbortInbox {
    pub fn new() -> Self {
        Self {
            r1_delta: HashMap::new(),
            r1_s: HashMap::new(),
        }
    }
}

impl MessageStore for TpresignAbortInbox {
    fn store(&mut self, msg: Message) -> Result<()> {
        match msg.message_type() {
            MessageType::TpresignAbort(TpresignAbortMessageType::RoundOneDelta) => {
                self.r1_delta
                    .entry(msg.to().unwrap())
                    .or_insert_with(Vec::new)
                    .push(msg);
            }
            MessageType::TpresignAbort(TpresignAbortMessageType::RoundOneS) => {
                self.r1_s
                    .entry(msg.to().unwrap())
                    .or_insert_with(Vec::new)
                    .push(msg);
            }
            _ => panic!("Invalid message type for TpresignAbortInbox"),
        }
        Ok(())
    }

    fn fetch(
        &mut self,
        participant_id: &ParticipantIdentifier,
        msg_type: MessageType,
    ) -> Vec<Message> {
        match msg_type {
            MessageType::TpresignAbort(TpresignAbortMessageType::RoundOneDelta) => {
                self.r1_delta.remove(participant_id).unwrap()
            }
            MessageType::TpresignAbort(TpresignAbortMessageType::RoundOneS) => {
                self.r1_s.remove(participant_id).unwrap()
            }
            _ => panic!("Invalid message type for TpresignAbortInbox"),
        }
    }
}

pub struct TrecoverInbox {
    r1: HashMap<ParticipantIdentifier, Vec<Message>>,
    r2: HashMap<ParticipantIdentifier, Vec<Message>>,
    r3: HashMap<ParticipantIdentifier, Vec<Message>>,
}
impl TrecoverInbox {
    pub fn new() -> Self {
        Self {
            r1: HashMap::new(),
            r2: HashMap::new(),
            r3: HashMap::new(),
        }
    }
}

impl MessageStore for TrecoverInbox {
    fn store(&mut self, msg: Message) -> Result<()> {
        match msg.message_type() {
            MessageType::Trecover(TrecoverMessageType::R1CommitHash) => {
                self.r1
                    .entry(msg.to().unwrap())
                    .or_insert_with(Vec::new)
                    .push(msg);
            }
            MessageType::Trecover(TrecoverMessageType::R2Decommit) => {
                self.r2
                    .entry(msg.to().unwrap())
                    .or_insert_with(Vec::new)
                    .push(msg);
            }
            MessageType::Trecover(TrecoverMessageType::R3EncryptedShare) => {
                self.r3
                    .entry(msg.to().unwrap())
                    .or_insert_with(Vec::new)
                    .push(msg);
            }
            _ => panic!("Invalid message type for TrecoverInbox"),
        }
        Ok(())
    }

    fn fetch(
        &mut self,
        participant_id: &ParticipantIdentifier,
        msg_type: MessageType,
    ) -> Vec<Message> {
        match msg_type {
            MessageType::Trecover(TrecoverMessageType::R1CommitHash) => {
                self.r1.remove(participant_id).unwrap()
            }
            MessageType::Trecover(TrecoverMessageType::R2Decommit) => {
                self.r2.remove(participant_id).unwrap()
            }
            MessageType::Trecover(TrecoverMessageType::R3EncryptedShare) => {
                self.r3.remove(participant_id).unwrap()
            }
            _ => panic!("Invalid message type for TrecoverInbox"),
        }
    }
}
