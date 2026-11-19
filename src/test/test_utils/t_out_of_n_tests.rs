use crate::{
    messages::TrecoverMessageType,
    trecover::participant::{TrecoverHelperParticipant, TrecoverTargetParticipant},
};

use super::test_imports::*;
use crate::curve::ScalarTrait;
use crate::messages::TpresignAbortMessageType;
use crate::protocol::ProtocolType::TpresignAbort;
use crate::tpresign::round_three;
use crate::tpresign::tpresign_abort::TpresignAbortParticipant;

// tshare는 모든 참여자가 참여해야 함 -> all_participants 사용
pub(crate) fn test_tshare(
    all_participants: &mut Vec<TshareParticipant<C>>,
    mut rng: &mut (impl rand::RngCore + rand::CryptoRng),
    sid: Identifier,
    central_server: &mut central_server::CentralServer,
    participant_inbox: &mut HashMap<ParticipantIdentifier, Vec<Message>>,
) -> Result<(
    HashMap<ParticipantIdentifier, tshare::Output<C>>,
    <C as CurveTrait>::VerifyingKey,
)> {
    let all_participants_size = all_participants.len();

    let mut tshare_outputs: HashMap<ParticipantIdentifier, tshare::Output<C>> = HashMap::new();

    // 중앙 서버 -> 각 P_i: keygen 시작 메시지
    for p in all_participants.iter_mut() {
        participant_inbox
            .entry(p.id())
            .or_insert_with(Vec::new)
            .push(
                Message::new(
                    MessageType::Tshare(TshareMessageType::Ready),
                    sid,
                    p.id(),
                    Some(p.id()),
                    false,
                    b"init",
                )
                .unwrap(),
            );
    }

    // 각 P_i: handle 메시지 (Ready) 후 R1CommitHash를 중앙 서버로 전송
    for p in all_participants.iter_mut() {
        let current_pid = p.id();
        if let Some(messages_for_p) = participant_inbox.remove(&current_pid) {
            for msg in messages_for_p {
                let res = p.process_message(&mut rng, &msg)?;
                let res = res.into_messages().unwrap();
                // P_i -> 중앙 서버: keygen R1CommitHash
                for m in res {
                    central_server.send_message(m)?;
                }
            }
        }
    }

    // 각 P_i: 중앙서버로부터 keygen R1CommitHash 메시지를 받고 이를 처리하여 R2Decommit 및 R2PrivateShare 메시지를 생성
    // R2Decommit 메시지를 중앙 서버로 전송
    for p in all_participants.iter_mut() {
        let current_pid = p.id();
        let msgs = central_server.fetch_messages(
            MessageType::Tshare(TshareMessageType::R1CommitHash),
            &current_pid,
        );
        for msg in msgs {
            let res = p.process_message(&mut rng, &msg)?;
            let res = res.into_messages().unwrap();
            for m in res {
                central_server.send_message(m)?;
            }
        }
    }

    // Check if all participants have completed round one
    assert!(all_participants.iter().all(|p| p.is_r1_done()));

    // 각 P_i: 중앙 서버로부터 keygen R2Decommit 및 R2PrivateShare 메시지를 받고 이를 처리하여 R3Proof 메시지를 생성
    // R3Proof 메시지를 중앙 서버로 전송
    for p in all_participants.iter_mut() {
        let current_pid = p.id();

        let priv_msgs = central_server.fetch_messages(
            MessageType::Tshare(TshareMessageType::R2PrivateShare),
            &current_pid,
        );

        let msgs = central_server.fetch_messages(
            MessageType::Tshare(TshareMessageType::R2Decommit),
            &current_pid,
        );

        for msg in priv_msgs {
            let res = p.process_message(&mut rng, &msg)?;
            let res = res.into_messages().unwrap();
            for m in res {
                central_server.send_message(m)?;
            }
        }
        for msg in msgs {
            let res = p.process_message(&mut rng, &msg)?;
            let res = res.into_messages().unwrap();
            for m in res {
                central_server.send_message(m)?;
            }
        }
    }

    // Check if all participants have completed round two
    assert!(all_participants.iter().all(|p| p.is_r2_done()));

    // 각 P_i: 중앙 서버로부터 keygen R3Proof 메시지를 받고 이를 처리하여 최종 출력 생성
    for p in all_participants.iter_mut() {
        let current_pid = p.id();
        let msgs = central_server.fetch_messages(
            MessageType::Tshare(TshareMessageType::R3Proof),
            &current_pid,
        );
        for msg in msgs {
            let res = p.process_message(&mut rng, &msg)?;
            if let ProcessOutcome::Done(output) = res {
                tshare_outputs.insert(current_pid, output);
            }
        }
    }

    // 각 P_i: 중앙 서버에게 master pk 전송
    for p in all_participants.iter_mut() {
        let master_pk = p.retrieve_master_pk()?;
        let msg = Message::new(
            MessageType::Tshare(TshareMessageType::Pk),
            sid,
            p.id(),
            Some(p.id()),
            false,
            &master_pk,
        )?;
        central_server.send_message(msg)?;
    }

    // 중앙 서버: 모든 P_i로부터 수신한 master pk가 동일한지 확인
    let mut master_pks = Vec::new();
    for p in all_participants.iter() {
        let msgs =
            central_server.fetch_messages(MessageType::Tshare(TshareMessageType::Pk), &p.id());
        for msg in msgs {
            let master_pk: <C as CurveTrait>::VerifyingKey =
                bincode::deserialize(&msg.unverified_bytes)
                    .expect("Failed to deserialize master public key.");
            master_pks.push(master_pk);
        }
    }
    assert!(
        master_pks.windows(2).all(|x| x[0] == x[1]),
        "All participants should have the same master public key."
    );

    let master_pk = master_pks[0].clone();

    // Make sure every player got an output
    assert_eq!(tshare_outputs.len(), all_participants_size);
    let tshare_outputs_vec = tshare_outputs.values().cloned().collect::<Vec<_>>();

    // Make sure everybody agrees on the public parts.
    assert!(tshare_outputs_vec
        .windows(2)
        .all(|o| o[0].public_key_shares() == o[1].public_key_shares()));
    assert!(tshare_outputs_vec.windows(2).all(|o| {
        let first_pks = o[0].public_key_shares();
        let second_pks = o[1].public_key_shares();
        // for each element in first_pks, there must be a corresponding element in
        // second_pks
        first_pks.iter().all(|x| second_pks.iter().any(|y| x == y))
    }));

    // Check that each participant's own `CoeffPublic` corresponds to their
    // `CoeffPrivate`
    for (pid, output) in &tshare_outputs {
        let stored_public_share = output
            .public_key_shares()
            .iter()
            .find(|x| x.participant() == *pid)
            .expect("Public key share for the participant not found in the output list.");

        let expected_public_share = C::GENERATOR.mul(output.private_key_share());

        assert_eq!(expected_public_share, *stored_public_share.as_ref());
    }

    // validate the final public key, which is given by the sum of the public keys
    // of all participants
    let mut sum_public_keys_first = C::IDENTITY;
    for public_key in tshare_outputs_vec.first().unwrap().public_key_shares() {
        sum_public_keys_first = sum_public_keys_first + *public_key.as_ref();
    }
    for output in tshare_outputs_vec.iter().skip(1) {
        let mut sum_public_keys = C::IDENTITY;
        for public_key in output.public_key_shares() {
            sum_public_keys = sum_public_keys + *public_key.as_ref();
        }
        assert_eq!(sum_public_keys, sum_public_keys_first);
    }

    Ok((tshare_outputs.clone(), master_pk))
}

// trefresh는 모든 참여자가 참여해야 함 -> all_participants 사용
pub(crate) fn test_trefresh(
    all_participants: &mut Vec<TrefreshParticipant<C>>,
    mut rng: &mut (impl rand::RngCore + rand::CryptoRng),
    sid: Identifier,
    central_server: &mut central_server::CentralServer,
    participant_inbox: &mut HashMap<ParticipantIdentifier, Vec<Message>>,
    QUORUM_SIZE: usize,
    orig_pk: <C as CurveTrait>::VerifyingKey,
) -> Result<(HashMap<ParticipantIdentifier, tshare::Output<C>>)> {
    let mut trefresh_outputs: HashMap<ParticipantIdentifier, tshare::Output<C>> = HashMap::new();

    // 중앙 서버 -> 각 P_i: trefresh 시작 메시지
    for p in all_participants.iter_mut() {
        participant_inbox
            .entry(p.id())
            .or_insert_with(Vec::new)
            .push(
                Message::new(
                    MessageType::Trefresh(TrefreshMessageType::Ready),
                    sid,
                    p.id(),
                    Some(p.id()),
                    false,
                    b"init",
                )
                .unwrap(),
            );
    }

    // 각 P_i: handle 메시지 (Ready) 후 R1CommitHash를 중앙 서버로 전송
    for p in all_participants.iter_mut() {
        let current_pid = p.id();
        if let Some(messages_for_p) = participant_inbox.remove(&current_pid) {
            for msg in messages_for_p {
                let res = p.process_message(&mut rng, &msg)?;
                let res = res.into_messages().unwrap();
                // P_i -> 중앙 서버: trefresh R1CommitHash
                for m in res {
                    central_server.send_message(m)?;
                }
            }
        }
    }

    // 각 P_i: 중앙서버로부터 trefresh R1CommitHash 메시지를 받고 이를 처리하여 R2Decommit 및 R2PrivateShare 메시지를 생성
    // R2Decommit 메시지를 중앙 서버로 전송
    for p in all_participants.iter_mut() {
        let current_pid = p.id();
        let msgs = central_server.fetch_messages(
            MessageType::Trefresh(TrefreshMessageType::R1CommitHash),
            &current_pid,
        );
        for msg in msgs {
            let res = p.process_message(&mut rng, &msg)?;
            let res = res.into_messages().unwrap();
            for m in res {
                central_server.send_message(m)?;
            }
        }
    }

    // Check if all participants have completed round one
    assert!(all_participants.iter().all(|p| p.is_r1_done()));

    // 각 P_i: 중앙 서버로부터 trefresh R2Decommit 및 R2PrivateShare 메시지를 받고 이를 처리하여 R3Proof 메시지를 생성
    // R3Proof 메시지를 중앙 서버로 전송
    for p in all_participants.iter_mut() {
        let current_pid = p.id();

        let priv_msgs = central_server.fetch_messages(
            MessageType::Trefresh(TrefreshMessageType::R2PrivateShare),
            &current_pid,
        );

        let msgs = central_server.fetch_messages(
            MessageType::Trefresh(TrefreshMessageType::R2Decommit),
            &current_pid,
        );

        for msg in priv_msgs {
            let res = p.process_message(&mut rng, &msg)?;
            let res = res.into_messages().unwrap();
            for m in res {
                central_server.send_message(m)?;
            }
        }
        for msg in msgs {
            let res = p.process_message(&mut rng, &msg)?;
            let res = res.into_messages().unwrap();
            for m in res {
                central_server.send_message(m)?;
            }
        }
    }

    // Check if all participants have completed round two
    assert!(all_participants.iter().all(|p| p.is_r2_done()));

    // 각 P_i: 중앙 서버로부터 trefresh R3Proof 메시지를 받고 이를 처리하여 최종 출력 생성
    for p in all_participants.iter_mut() {
        let current_pid = p.id();
        let msgs = central_server.fetch_messages(
            MessageType::Trefresh(TrefreshMessageType::R3Proof),
            &current_pid,
        );
        for msg in msgs {
            let res = p.process_message(&mut rng, &msg)?;
            if let ProcessOutcome::Done(output) = res {
                trefresh_outputs.insert(current_pid, output);
            }
        }
    }

    // Make sure every player got an output
    assert_eq!(trefresh_outputs.len(), QUORUM_SIZE);
    let trefresh_outputs_vec = trefresh_outputs.values().cloned().collect::<Vec<_>>();

    // Make sure everybody agrees on the public parts.
    assert!(trefresh_outputs_vec
        .windows(2)
        .all(|o| o[0].public_key_shares() == o[1].public_key_shares()));
    assert!(trefresh_outputs_vec.windows(2).all(|o| {
        let first_pks = o[0].public_key_shares();
        let second_pks = o[1].public_key_shares();
        // for each element in first_pks, there must be a corresponding element in
        // second_pks
        first_pks.iter().all(|x| second_pks.iter().any(|y| x == y))
    }));

    // Check that each participant's own `CoeffPublic` corresponds to their
    // `CoeffPrivate`
    for (pid, output) in &trefresh_outputs {
        let expected_public_share = C::GENERATOR.mul(output.private_key_share());

        let stored_public_share = output
            .public_key_shares()
            .iter()
            .find(|x| x.participant() == *pid)
            .expect("Public key share for the participant not found in the output list.");

        assert_eq!(expected_public_share, *stored_public_share.as_ref());
    }

    // validate the final public key, which is given by the sum of the public keys
    // of all participants
    let mut sum_public_keys_first = C::IDENTITY;
    for public_key in trefresh_outputs_vec.first().unwrap().public_key_shares() {
        sum_public_keys_first = sum_public_keys_first + *public_key.as_ref();
    }
    for output in trefresh_outputs_vec.iter().skip(1) {
        let mut sum_public_keys = C::IDENTITY;
        for public_key in output.public_key_shares() {
            sum_public_keys = sum_public_keys + *public_key.as_ref();
        }
        assert_eq!(sum_public_keys, sum_public_keys_first);
    }

    // todo: sk도 복구되는지 테스트...?

    // trefresh 전후로 공개키가 동일한지 확인
    {
        // trefresh 후 공개키
        let refreshed_pk = trefresh_outputs.values().next().unwrap().public_key()?;

        assert_eq!(
            orig_pk, refreshed_pk,
            "The overall public key should not change after a key refresh."
        );
    }

    Ok(trefresh_outputs.clone())
}

// tpresign은 t명의 참여자만 참여 -> active_participants만 사용
pub(crate) fn test_tpresign(
    mut active_participants: Vec<TpresignParticipant<C>>,
    mut rng: &mut (impl rand::RngCore + rand::CryptoRng),
    sid: Identifier,
    central_server: &mut central_server::CentralServer,
    participant_inbox: &mut HashMap<ParticipantIdentifier, Vec<Message>>,
) -> Result<HashMap<ParticipantIdentifier, TpresignRecord<C>>> {
    let mut presign_outputs: HashMap<ParticipantIdentifier, TpresignRecord<C>> = HashMap::new();
    let active_participants_size = active_participants.len();

    for p in active_participants.iter_mut() {
        participant_inbox
            .entry(p.id())
            .or_insert_with(Vec::new)
            .push(
                Message::new(
                    MessageType::Tpresign(TpresignMessageType::Ready),
                    sid,
                    p.id(),
                    Some(p.id()),
                    false,
                    b"init",
                )
                .unwrap(),
            );
    }

    // 각 P_i: handle 메시지 (Ready) 후 RoundOne 및 RoundOneBroadcast 중앙 서버로 전송
    for p in active_participants.iter_mut() {
        let current_pid = p.id();
        if let Some(messages_for_p) = participant_inbox.remove(&current_pid) {
            for msg in messages_for_p {
                let res = p.process_message(&mut rng, &msg)?;
                let res = res.into_messages().unwrap();
                // P_i -> 중앙 서버: presign RoundOne 및 RoundOneBroadcast
                for m in res {
                    central_server.send_message(m)?;
                }
            }
        }
    }

    // 각 P_i: 중앙서버로부터 presign RoundOne 및 RoundOneBroadcast 메시지를 받고 이를 처리하여 RoundTwo 메시지를 생성
    // RoundTwo 메시지를 중앙 서버로 전송
    for p in active_participants.iter_mut() {
        let current_pid = p.id();
        let mut msgs = central_server.fetch_messages(
            MessageType::Tpresign(TpresignMessageType::RoundOneBroadcast),
            &current_pid,
        );
        let msgs_priv = central_server.fetch_messages(
            MessageType::Tpresign(TpresignMessageType::RoundOne),
            &current_pid,
        );
        msgs.extend(msgs_priv);

        for msg in msgs {
            let res = p.process_message(&mut rng, &msg)?;
            let res = res.into_messages().unwrap();
            for m in res {
                central_server.send_message(m)?;
            }
        }
    }

    // Check if all participants have completed round one
    assert!(active_participants.iter().all(|p| p.is_r1_done()));

    // 각 P_i: 중앙 서버로부터 presign RoundTwo 메시지를 받고 이를 처리하여 RoundThree 메시지를 생성
    // RoundThree 메시지를 중앙 서버로 전송
    for p in active_participants.iter_mut() {
        let current_pid = p.id();
        let msgs_broadcast = central_server.fetch_messages(
            MessageType::Tpresign(TpresignMessageType::RoundTwoBroadcast),
            &current_pid,
        );
        let msgs = central_server.fetch_messages(
            MessageType::Tpresign(TpresignMessageType::RoundTwo),
            &current_pid,
        );
        for msg in msgs_broadcast {
            let res = p.process_message(&mut rng, &msg)?;
            let res = res.into_messages().unwrap();
        }
        for msg in msgs {
            let res = p.process_message(&mut rng, &msg)?;
            let res = res.into_messages().unwrap();
            for m in res {
                central_server.send_message(m)?;
            }
        }
    }

    // Check if all participants have completed round two
    assert!(active_participants.iter().all(|p| p.is_r2_done()));

    // 각 P_i: 중앙 서버로부터 keygen RoundThree 메시지를 받고 이를 처리하여 최종 출력 생성
    for p in active_participants.iter_mut() {
        let current_pid = p.id();
        let msgs = central_server.fetch_messages(
            MessageType::Tpresign(TpresignMessageType::RoundThree),
            &current_pid,
        );
        for msg in msgs {
            let res = p.process_message(&mut rng, &msg)?;
            if let ProcessOutcome::Done(output) = res {
                presign_outputs.insert(current_pid, output);
            }
        }
    }

    // Check if all participants have completed round three
    assert!(active_participants.iter().all(|p| p.is_r3_done()));

    let outputs: Vec<_> = presign_outputs.values().collect();

    // Make sure every player got an output
    assert_eq!(outputs.len(), active_participants_size);

    let records: Vec<_> = outputs.into_iter().cloned().collect();

    let signers: Vec<_> = active_participants
        .iter()
        .map(|p| p.id())
        .collect::<Vec<_>>();

    let t_out_of_t_shares: Vec<_> = active_participants
        .iter()
        .map(|participant| {
            let tshare_output = participant.input().tshare_output().clone();
            let rid = tshare_output.rid();
            let t_out_of_t_share = ToutofTHelper::<C>::convert_to_t_out_of_t_share(
                &participant.id(),
                &signers.as_slice(),
                participant.input().tshare_output(),
                *rid,
            )
            .unwrap();
            t_out_of_t_share
        })
        .collect();

    // Check validity of set; this will panic if anything is wrong
    tpresign_record_set_is_valid(records, t_out_of_t_shares);

    Ok(presign_outputs.clone())
}

pub(crate) fn test_trecover(
    mut target_participant: TrecoverTargetParticipant<C>,
    mut helper_participants: Vec<TrecoverHelperParticipant<C>>,
    mut rng: &mut (impl rand::RngCore + rand::CryptoRng),
    sid: Identifier,
    central_server: &mut central_server::CentralServer,
    participant_inbox: &mut HashMap<ParticipantIdentifier, Vec<Message>>,
) -> Result<tshare::Output<C>> {
    let mut target_tshare: tshare::Output<C> = tshare::Output::default();

    // 중앙 서버 -> Helpers: Key recovery 시작 메시지
    for p in helper_participants.iter_mut() {
        participant_inbox
            .entry(p.id())
            .or_insert_with(Vec::new)
            .push(
                Message::new(
                    MessageType::Trecover(crate::messages::TrecoverMessageType::Ready),
                    sid,
                    p.id(),
                    Some(p.id()),
                    false,
                    b"init",
                )
                .unwrap(),
            );
    }

    // Helpers: handle 메시지 (Ready) 후 R1Commit를 중앙서버로 전송
    for p in helper_participants.iter_mut() {
        let current_pid = p.id();
        if let Some(messages_for_p) = participant_inbox.remove(&current_pid) {
            for msg in messages_for_p {
                let res = p.process_message(&mut rng, &msg)?;
                let res = res.into_messages().unwrap();
                // P_i -> 중앙 서버: keygen R1CommitHash
                for m in res {
                    central_server.send_message(m)?;
                }
            }
        }
    }

    // Helpers: 중앙서버로부터 kgen R1CommitHash 메시지를 받고 이를 처리하여 R2Decommit메시지를 생성
    // R2Decommit 메시지를 중앙 서버로 전송
    for p in helper_participants.iter_mut() {
        let current_pid = p.id();
        let msgs = central_server.fetch_messages(
            MessageType::Trecover(TrecoverMessageType::R1CommitHash),
            &current_pid,
        );
        for msg in msgs {
            let res = p.process_message(&mut rng, &msg)?;
            let res = res.into_messages().unwrap();
            for m in res {
                central_server.send_message(m)?;
            }
        }
    }

    // Check if all participants have completed round one
    assert!(helper_participants.iter().all(|p| p.is_r1_done()));

    // Helpers: 중앙 서버로부터 R2Decommit 메시지를 받고 이를 처리하여 R3 메시지를 생성
    // R3Proof 메시지를 중앙 서버로 전송
    for p in helper_participants.iter_mut() {
        let current_pid = p.id();
        let msgs = central_server.fetch_messages(
            MessageType::Trecover(TrecoverMessageType::R2Decommit),
            &current_pid,
        );

        for msg in msgs {
            let res = p.process_message(&mut rng, &msg)?;
            let res = res.into_messages().unwrap();
            for m in res {
                central_server.send_message(m)?;
            }
        }
    }

    // target participant: key 복구
    let target_pid = target_participant.id();
    let msgs_for_target = central_server.fetch_messages(
        MessageType::Trecover(TrecoverMessageType::R3EncryptedShare),
        &target_pid,
    );
    participant_inbox
        .entry(target_pid)
        .or_default()
        .extend(msgs_for_target);

    if let Some(messages_for_p) = participant_inbox.remove(&target_participant.id()) {
        for msg in messages_for_p {
            let res = target_participant.process_message(&mut rng, &msg)?;
            if let ProcessOutcome::Done(output) = res {
                target_tshare = output;
            }
        }
    }

    Ok(target_tshare)
}

pub(crate) fn test_tpresign_abort(
    mut active_participants: Vec<TpresignAbortParticipant<C>>,
    mut rng: &mut (impl rand::RngCore + rand::CryptoRng),
    sid: Identifier,
    is_delta_error: bool,
    central_server: &mut central_server::CentralServer,
    participant_inbox: &mut HashMap<ParticipantIdentifier, Vec<Message>>,
) -> Result<HashMap<ParticipantIdentifier, Vec<ParticipantIdentifier>>> {
    let mut presign_abort_outputs: HashMap<ParticipantIdentifier, Vec<ParticipantIdentifier>> =
        HashMap::new();

    // 각 P_i: tpresign_abort 시작 메시지
    for p in active_participants.iter_mut() {
        participant_inbox
            .entry(p.id())
            .or_insert_with(Vec::new)
            .push(if is_delta_error {
                Message::new(
                    MessageType::TpresignAbort(TpresignAbortMessageType::ReadyDelta),
                    sid,
                    p.id(),
                    Some(p.id()),
                    false,
                    b"init",
                )
                .unwrap()
            } else {
                Message::new(
                    MessageType::TpresignAbort(TpresignAbortMessageType::ReadyS),
                    sid,
                    p.id(),
                    Some(p.id()),
                    false,
                    b"init",
                )
                .unwrap()
            });
    }

    // 각 P_i: handle 메시지 (Ready) 후 RoundOne{} 중앙 서버로 전송
    for p in active_participants.iter_mut() {
        let current_pid = p.id();
        if let Some(messages_for_p) = participant_inbox.remove(&current_pid) {
            for msg in messages_for_p {
                let res = p.process_message(&mut rng, &msg)?;
                let res = res.into_messages().unwrap();
                for m in res {
                    central_server.send_message(m)?;
                }
            }
        }
    }

    // 각 P_i: 중앙서버로부터 RoundOne{} 메시지를 받고 이를 처리하여 output 을 생성
    for p in active_participants.iter_mut() {
        let current_pid = p.id();
        let mut msgs = if is_delta_error {
            central_server.fetch_messages(
                MessageType::TpresignAbort(TpresignAbortMessageType::RoundOneDelta),
                &current_pid,
            )
        } else {
            central_server.fetch_messages(
                MessageType::TpresignAbort(TpresignAbortMessageType::RoundOneS),
                &current_pid,
            )
        };
        for msg in msgs {
            let res = p.process_message(&mut rng, &msg)?;
            if let ProcessOutcome::Done(output) = res {
                println!("Participant {:?} completed tpresign_abort.", current_pid);
                println!("Aborting participants: {:?}", output);
                presign_abort_outputs.insert(current_pid, output);
            }
        }
    }

    Ok(presign_abort_outputs.clone())
}
