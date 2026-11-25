//! Live two-party presigning state for one local participant.
use crate::{PresignRecord, SignerIdentity, SigningPackage, parse_master_key};
use rand::rngs::OsRng;
use threshold_ecdsa::{
    Identifier, ParticipantIdentifier, ProcessOutcome, ProtocolParticipant,
    generate_tpresign_input, get_master_pk,
    k256::K256,
    messages::{Message, MessageType, TpresignMessageType as Kind},
    ready_message_factory,
    tpresign::{Input, TpresignParticipant},
};
use zeroize::Zeroizing;
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub enum RoundOutput {
    Messages(Vec<String>),
    Done(Vec<PresignRecord>),
}

pub struct Presigner {
    identity: SignerIdentity,
    input: Input<K256>,
    ids: Vec<u64>,
    records: Vec<PresignRecord>,
    party: TpresignParticipant<K256>,
    round: u8,
}

fn outgoing(messages: Vec<Message>) -> Result<RoundOutput> {
    let messages = messages
        .iter()
        .map(serde_json::to_string)
        .collect::<std::result::Result<_, _>>()?;
    Ok(RoundOutput::Messages(messages))
}

impl Presigner {
    pub fn start(
        identity: SignerIdentity,
        package: &SigningPackage,
        ids: Vec<u64>,
        aux: &str,
        share: &str,
    ) -> Result<(Self, Vec<String>)> {
        if ids.is_empty()
            || ids.len() != package.review()?.input_sighashes.len()
            || ids.iter().collect::<std::collections::HashSet<_>>().len() != ids.len()
        {
            return Err("incorrect or duplicated session IDs".into());
        }
        identity.check_quorum(package)?;
        if parse_master_key(&get_master_pk(share))? != package.public_key {
            return Err("local share does not match package".into());
        }
        let serialized = Zeroizing::new(generate_tpresign_input(&package.signers, aux, share));
        let input = serde_json::from_str(&serialized)?;
        let (party, first) = Self::begin_input(&identity, &input, ids[0])?;
        let RoundOutput::Messages(messages) = first else {
            return Err("expected first round".into());
        };
        Ok((
            Self {
                identity,
                input,
                ids,
                records: Vec::new(),
                party,
                round: 1,
            },
            messages,
        ))
    }
    fn begin_input(
        identity: &SignerIdentity,
        input: &Input<K256>,
        sid: u64,
    ) -> Result<(TpresignParticipant<K256>, RoundOutput)> {
        let mut party = TpresignParticipant::new(
            Identifier::from(sid),
            ParticipantIdentifier::from_u64(identity.party_id),
            vec![ParticipantIdentifier::from_u64(identity.peer_id)],
            input.clone(),
        )?;
        let ready =
            serde_json::from_str(&ready_message_factory("TPreSign", sid, identity.party_id))?;
        let ProcessOutcome::Continue(messages) = party.process_message(&mut OsRng, &ready)? else {
            return Err("unexpected initial outcome".into());
        };
        Ok((party, outgoing(messages)?))
    }

    pub fn advance(&mut self, wire: &[String]) -> Result<RoundOutput> {
        let expected: &[Kind] = match self.round {
            1 => &[Kind::RoundOneBroadcast, Kind::RoundOne],
            2 => &[Kind::RoundTwoBroadcast, Kind::RoundTwo],
            3 => &[Kind::RoundThree],
            _ => return Err("session finished".into()),
        };
        if wire.len() != expected.len() {
            return Err("wrong round message count".into());
        }
        let mut messages = wire
            .iter()
            .map(|s| serde_json::from_str::<Message>(s))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let me = ParticipantIdentifier::from_u64(self.identity.party_id);
        let peer = ParticipantIdentifier::from_u64(self.identity.peer_id);
        let mut out = Vec::new();
        // The engine needs the broadcast companion before its recipient-specific message.
        for kind in expected {
            let index = messages
                .iter()
                .position(|m| m.message_type() == MessageType::Tpresign(*kind))
                .ok_or("wrong round message type")?;
            let mut msg = messages.swap_remove(index);
            let broadcast = matches!(kind, Kind::RoundOneBroadcast | Kind::RoundTwoBroadcast);
            if msg.from() != peer
                || msg.id() != self.party.sid()
                || msg.to() != if broadcast { None } else { Some(me) }
            {
                return Err("wrong protocol message address or session".into());
            }
            msg.set_to(Some(me));
            match self.party.process_message(&mut OsRng, &msg)? {
                ProcessOutcome::Continue(batch) => out.extend(batch),
                ProcessOutcome::Done(record) if self.round == 3 => {
                    let bytes = Zeroizing::new(serde_json::to_vec(&record)?);
                    self.records.push(serde_json::from_slice(&bytes)?);
                    if let Some(sid) = self.ids.get(self.records.len()) {
                        let (party, first) = Self::begin_input(&self.identity, &self.input, *sid)?;
                        self.party = party;
                        self.round = 1;
                        return Ok(first);
                    }
                    self.round = 4;
                    return Ok(RoundOutput::Done(std::mem::take(&mut self.records)));
                }
                _ => return Err("early protocol completion".into()),
            }
        }
        if out.is_empty() {
            return Err("incomplete protocol round".into());
        }
        self.round += 1;
        outgoing(out)
    }
}
