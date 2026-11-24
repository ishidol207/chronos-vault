use super::{Job, Operation, Result, party_dir, party_store, write_new};
use chronos_vault::{PresignRecord, SignerIdentity, parse_master_key};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;
use std::io::{self, BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Child, ChildStdout, Command, Stdio};
use threshold_ecdsa::messages::{Message, MessageType, TpresignMessageType, TshareMessageType};
use threshold_ecdsa::{
    ParticipantIdentifier, ProcessOutcome, delegate_process_message, generate_tpresign_input,
    generate_tshare_input, get_master_pk, participant_factory, ready_message_factory,
    remove_session,
};
use zeroize::Zeroizing;

#[derive(Serialize, Deserialize)]
enum Reply {
    Messages(Vec<Message>),
    Finished,
}

fn receive<T: DeserializeOwned>(reader: &mut impl BufRead) -> Result<T> {
    let mut line = String::new();
    if reader.read_line(&mut line)? == 0 {
        return Err("protocol pipe closed before completion".into());
    }
    Ok(serde_json::from_str(&line)?)
}

fn send(writer: &mut impl Write, value: &impl Serialize) -> Result<()> {
    serde_json::to_writer(&mut *writer, value)?;
    writer.write_all(b"\n")?;
    writer.flush()?;
    Ok(())
}

struct Peer {
    id: ParticipantIdentifier,
    child: Child,
    reader: BufReader<ChildStdout>,
}

impl Drop for Peer {
    fn drop(&mut self) {
        // On a failed round, siblings can still be blocked on either end of a pipe.
        if !matches!(self.child.try_wait(), Ok(Some(_))) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

pub(super) fn relay(wallet: &Path, job: &Job) -> Result<()> {
    let exe = std::env::current_exe()?;
    let mut peers = Vec::new();
    for &id in &job.parties {
        let mut child = Command::new(&exe)
            .arg("worker")
            .arg(party_dir(wallet, id))
            .arg(id.to_string())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()?;
        let reader = BufReader::new(child.stdout.take().ok_or("missing worker output")?);
        peers.push(Peer {
            id: ParticipantIdentifier::from_u64(id),
            child,
            reader,
        });
    }
    for peer in &mut peers {
        send(
            peer.child.stdin.as_mut().ok_or("missing worker input")?,
            job,
        )?;
    }

    loop {
        let mut outbox = Vec::new();
        let mut done = 0;
        for peer in &mut peers {
            match receive(&mut peer.reader)? {
                Reply::Finished => done += 1,
                Reply::Messages(messages) => {
                    if messages.iter().any(|m| m.from() != peer.id) {
                        return Err("unexpected sender in protocol message".into());
                    }
                    outbox.extend(messages);
                }
            }
        }
        if done == peers.len() {
            for peer in &mut peers {
                if !peer.child.wait()?.success() {
                    return Err("protocol worker exited unsuccessfully".into());
                }
            }
            return Ok(());
        }
        if done != 0 {
            return Err("participants disagreed on the final round".into());
        }
        // The local protocol processes these companion messages first within a round.
        outbox.sort_by_key(|m| {
            !matches!(
                m.message_type(),
                MessageType::Tshare(TshareMessageType::R2PrivateShare)
                    | MessageType::Tpresign(
                        TpresignMessageType::RoundOneBroadcast
                            | TpresignMessageType::RoundTwoBroadcast
                    )
            )
        });
        for peer in &mut peers {
            let mut inbox = Vec::new();
            for m in &outbox {
                if m.from() != peer.id && m.to().is_none_or(|to| to == peer.id) {
                    let mut addressed = m.clone();
                    addressed.set_to(Some(peer.id));
                    inbox.push(addressed);
                }
            }
            if inbox.is_empty() {
                return Err("participant received no messages in an unfinished round".into());
            }
            send(
                peer.child.stdin.as_mut().ok_or("missing worker input")?,
                &inbox,
            )?;
        }
    }
}

// Only protocol messages go to the relay. Done values stay in the worker.
struct Party<'a> {
    id: u64,
    others: Vec<u64>,
    reader: io::StdinLock<'a>,
    writer: io::StdoutLock<'a>,
}

impl Party<'_> {
    fn execute(&mut self, kind: &str, sid: u64, input: &str) -> Result<Zeroizing<String>> {
        participant_factory(kind, sid, self.id, &self.others, input);
        let ready = ready_message_factory(kind, sid, self.id);
        let mut inbox: Vec<Message> = vec![serde_json::from_str(&ready)?];
        loop {
            let mut outgoing = Vec::new();
            for message in inbox {
                let result = Zeroizing::new(delegate_process_message(
                    kind,
                    sid,
                    &serde_json::to_string(&message)?,
                ));
                match serde_json::from_str::<ProcessOutcome<Value>>(&result)? {
                    ProcessOutcome::Continue(messages) => outgoing.extend(messages),
                    ProcessOutcome::Done(value) => {
                        remove_session(kind, sid);
                        return Ok(Zeroizing::new(serde_json::to_string(&value)?));
                    }
                }
            }
            send(&mut self.writer, &Reply::Messages(outgoing))?;
            inbox = receive(&mut self.reader)?;
        }
    }
}

pub(super) fn worker(dir: &Path, id: u64) -> Result<()> {
    let mut reader = io::stdin().lock();
    let job: Job = receive(&mut reader)?;
    let mut party = Party {
        id,
        others: job
            .parties
            .iter()
            .copied()
            .filter(|other| *other != id)
            .collect(),
        reader,
        writer: io::stdout().lock(),
    };
    match job.operation {
        Operation::Keygen { aux_sid, share_sid } => {
            let aux = party.execute("AuxInfo", aux_sid, "")?;
            let input = Zeroizing::new(generate_tshare_input(&aux, 2));
            let share = party.execute("TShare", share_sid, &input)?;
            let pk = get_master_pk(&share);
            let key = parse_master_key(&pk)?;
            party_store::seal(dir, id, &key, &aux, &share)?;
            write_new(&dir.join("public-key.json"), pk.as_bytes())?;
            for &peer_id in &party.others {
                let identity = SignerIdentity {
                    party_id: id,
                    peer_id,
                    public_key: key,
                };
                write_new(
                    &dir.join(format!("peer-{peer_id}.json")),
                    &serde_json::to_vec(&identity)?,
                )?;
            }
        }
        Operation::Presign {
            sessions,
            public_key,
            output,
        } => {
            let (aux, share) = party_store::open(dir, id, &public_key)?;
            if parse_master_key(&get_master_pk(&share))? != public_key {
                return Err("local key share does not match the requested public key".into());
            }
            let input = Zeroizing::new(generate_tpresign_input(&job.parties, &aux, &share));
            let mut records = Vec::new();
            for sid in sessions {
                let record = party.execute("TPreSign", sid, &input)?;
                records.push(serde_json::from_str::<PresignRecord>(&record)?);
            }
            let serialized = Zeroizing::new(serde_json::to_vec(&records)?);
            write_new(&output.join(format!("party-{id}.json")), &serialized)?;
        }
    }
    send(&mut party.writer, &Reply::Finished)
}
