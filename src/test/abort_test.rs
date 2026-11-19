use crate::auxinfo::AuxInfoParticipant;
use crate::curve::{CurveTrait, ScalarTrait};
use crate::errors::InternalError;
use crate::local_storage::LocalStorage;
use crate::messages::{Message, MessageType, TpresignMessageType};
use crate::participant::ProcessOutcome;
use crate::presign::PresignRecord;
use crate::sign::non_interactive_sign::participant::SignParticipant;
use crate::test::central_server;
use crate::test::test_utils::n_out_of_n_tests::{test_auxinfo, test_sign};
use crate::test::test_utils::t_out_of_n_tests::{test_tpresign, test_tpresign_abort, test_tshare};
use crate::test::test_utils::test_imports::{
    compute_non_distributed_ecdsa, tpresign_record_set_is_valid, C,
};
use crate::threshold::ToutofTHelper;
use crate::tpresign::tpresign_abort::TpresignAbortParticipant;
use crate::tpresign::{round_three, TpresignParticipant, TpresignRecord};
use crate::tshare::TshareParticipant;
use crate::utils::testing::init_testing;
use crate::{
    auxinfo, curve, keygen, tpresign, tshare, Identifier, ParticipantConfig, ParticipantIdentifier,
    ProtocolParticipant,
};
use libpaillier::unknown_order::BigNumber;
use sha3::Keccak256;
use std::collections::HashMap;

#[test]
fn tshare_abort_test() -> crate::errors::Result<()> {
    // error 로그를 보고 싶다면 아래 주석 해제
    // tracing_subscriber::fmt()
    //     .with_max_level(tracing::Level::ERROR)
    //     .init();

    // Total number of participants
    const NUM_ALL_PARTICIPANTS: usize = 4;
    // How many parties are needed to sign
    const THRESHOLD: usize = 3;
    let mut rng = init_testing();
    let sid = Identifier::random(&mut rng);

    let participant_configs = ParticipantConfig::random_quorum(NUM_ALL_PARTICIPANTS, &mut rng)?;
    let all_pids: Vec<_> = participant_configs.iter().map(|c| c.id()).collect();
    println!("All participant IDs: {:?}", all_pids);
    let mut participant_inbox: HashMap<ParticipantIdentifier, Vec<Message>> =
        all_pids.iter().map(|pid| (*pid, Vec::new())).collect();

    // ---------------------------------------- Auxinfo ----------------------------------------
    // Auxinfo 를 시뮬레이션 합니다.
    let auxinfo_outputs = auxinfo::Output::simulate_set(participant_configs.as_slice(), &mut rng);
    let auxinfo_outputs: HashMap<ParticipantIdentifier, auxinfo::Output> = participant_configs
        .iter()
        .zip(auxinfo_outputs.into_iter())
        .map(|(config, output)| (config.id(), output))
        .collect();

    let mut central_server = central_server::CentralServer::new(all_pids.clone());

    // ---------------------------------------- Threshold Keygen ----------------------------------------
    let mut tshare_participants: Vec<TshareParticipant<C>> = participant_configs
        .iter()
        .map(|config| {
            let tshare_input: tshare::Input<C> = crate::tshare::Input::new(
                auxinfo_outputs.get(&config.id()).unwrap().clone(),
                None, // None -> 새로운 랜덤값 사용
                THRESHOLD,
            )
            .expect("Failed to create tshare input");
            TshareParticipant::new(sid, config.id(), config.other_ids().to_vec(), tshare_input)
                .unwrap()
        })
        .collect::<Vec<_>>();

    let (tshare_outputs, master_pk): (
        HashMap<ParticipantIdentifier, tshare::Output<C>>,
        <C as CurveTrait>::VerifyingKey,
    ) = test_tshare(
        &mut tshare_participants,
        &mut rng,
        sid,
        &mut central_server,
        &mut participant_inbox,
    )?;
    central_server.clear();
    let mut central_server = central_server::CentralServer::new(all_pids.clone());

    assert!(participant_inbox.is_empty());

    // master pk 저장
    let master_pk = master_pk;

    // ---------------------------------------- Threshold Presign ----------------------------------------
    // 프로토콜에 참여할 THRESHOLD 명의 active participants
    let signers_configs = &participant_configs[..THRESHOLD];
    let malicious_id = all_pids[1];

    // is_delta_error: true -> delta 값에 오류 삽입
    // is_delta_error: false -> S 값에 오류 삽입
    let tpresign_error_result = malicious_tpresign(
        &tshare_outputs,
        &auxinfo_outputs,
        signers_configs,
        sid,
        false,
        malicious_id,
        &mut rng,
        &mut central_server,
        &mut participant_inbox,
    )?;

    central_server.clear();

    let mut central_server = central_server::CentralServer::new(all_pids.clone());

    assert!(participant_inbox.is_empty());

    // ---------------------------------------- Threshold Presign Abort ----------------------------------------

    let abort_result = tpresign_abort(
        &tshare_outputs,
        &auxinfo_outputs,
        tpresign_error_result.1,
        tpresign_error_result.0,
        signers_configs,
        sid,
        &mut rng,
        &mut central_server,
        &mut participant_inbox,
    );

    abort_result.into_iter().for_each(|(pid, accused)| {
        if pid != malicious_id {
            assert_eq!(accused, vec![malicious_id]);
        } else {
            assert!(accused.is_empty());
        }
    });

    Ok(())
}

fn malicious_tpresign(
    tshare_outputs: &HashMap<ParticipantIdentifier, tshare::Output<C>>,
    auxinfo_outputs: &HashMap<ParticipantIdentifier, auxinfo::Output>,
    signers_configs: &[ParticipantConfig],
    sid: Identifier,
    is_delta_error: bool,
    malicious_id: ParticipantIdentifier,
    mut rng: &mut (impl rand::RngCore + rand::CryptoRng),
    mut central_server: &mut central_server::CentralServer,
    mut participant_inbox: &mut HashMap<ParticipantIdentifier, Vec<Message>>,
) -> crate::errors::Result<(InternalError, Vec<LocalStorage>)> {
    let signer_ids: Vec<_> = signers_configs.iter().map(|c| c.id()).collect();
    let signer_ids_set: std::collections::HashSet<_> = signer_ids.iter().collect();

    // Tpresign 프로토콜에 참여할 THRESHOLD 명의 participants
    // tshare_output, auxinfo_output에서 서명 참여자의 public key share만 필터링하여 사용
    let tpresign_participants: Vec<TpresignParticipant<C>> = signers_configs
        .iter()
        .map(|config| {
            let orig_tshare_output = tshare_outputs.get(&config.id()).unwrap();
            let orig_auxinfo_output = auxinfo_outputs.get(&config.id()).unwrap();

            // active signer들의 tshare_output만 필터링
            let signer_tshare_output = {
                let signer_public_key_shares: Vec<_> = orig_tshare_output
                    .public_key_shares()
                    .iter()
                    .filter(|share| signer_ids_set.contains(&share.participant()))
                    .cloned()
                    .collect();

                tshare::Output::new(
                    signer_public_key_shares,
                    orig_tshare_output.private_key_share().clone(),
                    *orig_tshare_output.rid(),
                    orig_tshare_output.threshold(),
                )
            };

            // active signer들의 auxinfo_output만 필터링
            let signer_auxinfo_output = {
                let signer_public_auxinfo: Vec<_> = orig_auxinfo_output
                    .public_auxinfo()
                    .iter()
                    .filter(|info| signer_ids_set.contains(&info.participant()))
                    .cloned()
                    .collect();

                auxinfo::Output::from_parts(
                    signer_public_auxinfo,
                    orig_auxinfo_output.private_auxinfo().clone(),
                )
                .unwrap()
            };

            let tpresign_input =
                crate::tpresign::Input::new(signer_auxinfo_output, signer_tshare_output)
                    .expect("Failed to create presign input with filtered shares");

            // "active signer" 중 다른 signer들의 id
            let other_ids: Vec<_> = signer_ids
                .iter()
                .copied()
                .filter(|id| *id != config.id())
                .collect();

            TpresignParticipant::new(sid, config.id(), other_ids, tpresign_input)
                .expect("Failed to create PresignParticipant")
        })
        .collect::<Vec<_>>();

    // Tpresign 프로토콜 실행
    let tpresign_outputs = malicious_tpresign_internal(
        tpresign_participants,
        &mut rng,
        sid,
        is_delta_error,
        malicious_id,
        &mut central_server,
        &mut participant_inbox,
    )?;
    assert!(participant_inbox.is_empty());

    Ok(tpresign_outputs)
}

pub(crate) fn malicious_tpresign_internal(
    mut active_participants: Vec<TpresignParticipant<C>>,
    mut rng: &mut (impl rand::RngCore + rand::CryptoRng),
    sid: Identifier,
    is_delta_error: bool,
    malicious_id: ParticipantIdentifier,
    central_server: &mut central_server::CentralServer,
    participant_inbox: &mut HashMap<ParticipantIdentifier, Vec<Message>>,
) -> crate::errors::Result<(InternalError, Vec<LocalStorage>)> {
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
            // malicious things...
            let res = res.into_messages().unwrap();
            let mal_res = if p.id() == malicious_id && is_delta_error {
                res.iter()
                    .map(|m| {
                        let mut r3_public = round_three::Public::<C>::try_from(m).unwrap();
                        r3_public.delta = r3_public.delta + BigNumber::one();
                        let bad_m = Message::new(
                            MessageType::Tpresign(TpresignMessageType::RoundThree),
                            m.id(),
                            m.from(),
                            m.to(),
                            false,
                            &r3_public,
                        )
                        .unwrap();
                        bad_m
                    })
                    .collect::<Vec<_>>()
            } else if p.id() == malicious_id && !is_delta_error {
                res.iter()
                    .map(|m| {
                        let mut r3_public = round_three::Public::<C>::try_from(m).unwrap();
                        r3_public.S = r3_public.S + C::GENERATOR;
                        let bad_m = Message::new(
                            MessageType::Tpresign(TpresignMessageType::RoundThree),
                            m.id(),
                            m.from(),
                            m.to(),
                            false,
                            &r3_public,
                        )
                        .unwrap();
                        bad_m
                    })
                    .collect::<Vec<_>>()
            } else {
                res
            };

            for m in mal_res {
                central_server.send_message(m)?;
            }
        }
    }

    // Check if all participants have completed round two
    assert!(active_participants.iter().all(|p| p.is_r2_done()));

    let mut error = InternalError::SError;
    let mut local_storage_vec: Vec<LocalStorage> = Vec::new();

    // 각 P_i: 중앙 서버로부터 keygen RoundThree 메시지를 받고 이를 처리하여 최종 출력 생성
    for p in active_participants.iter_mut() {
        let current_pid = p.id();
        let msgs = central_server.fetch_messages(
            MessageType::Tpresign(TpresignMessageType::RoundThree),
            &current_pid,
        );
        for msg in msgs {
            let res = p.process_message(&mut rng, &msg);
            match res {
                Err(e) => {
                    println!(
                        "Participant {} failed as expected with error: {:?}",
                        current_pid, e
                    );
                    error = e;
                }
                Ok(outcome) => {}
            }
        }
        local_storage_vec.push(p.get_localstorage().unwrap());
    }

    return Ok((error, local_storage_vec));
}

fn tpresign_abort(
    tshare_outputs: &HashMap<ParticipantIdentifier, tshare::Output<C>>,
    auxinfo_outputs: &HashMap<ParticipantIdentifier, auxinfo::Output>,
    presign_localstorages: Vec<LocalStorage>,
    error: InternalError,
    signers_configs: &[ParticipantConfig],
    sid: Identifier,
    mut rng: &mut (impl rand::RngCore + rand::CryptoRng),
    mut central_server: &mut central_server::CentralServer,
    mut participant_inbox: &mut HashMap<ParticipantIdentifier, Vec<Message>>,
) -> HashMap<ParticipantIdentifier, Vec<ParticipantIdentifier>> {
    let signer_ids: Vec<_> = signers_configs.iter().map(|c| c.id()).collect();
    let signer_ids_set: std::collections::HashSet<_> = signer_ids.iter().collect();

    // -------------------------------------------- Tpresign Abort ----------------------------------------

    let tpresign_abort_participants: Vec<TpresignAbortParticipant<C>> = signers_configs
        .into_iter()
        .zip(presign_localstorages.into_iter())
        .map(|(config, local_storage)| {
            let orig_tshare_output = tshare_outputs.get(&config.id()).unwrap();
            let orig_auxinfo_output = auxinfo_outputs.get(&config.id()).unwrap();

            // active signer들의 tshare_output만 필터링
            let signer_tshare_output = {
                let signer_public_key_shares: Vec<_> = orig_tshare_output
                    .public_key_shares()
                    .iter()
                    .filter(|share| signer_ids_set.contains(&share.participant()))
                    .cloned()
                    .collect();

                tshare::Output::new(
                    signer_public_key_shares,
                    orig_tshare_output.private_key_share().clone(),
                    *orig_tshare_output.rid(),
                    orig_tshare_output.threshold(),
                )
            };

            // active signer들의 auxinfo_output만 필터링
            let signer_auxinfo_output = {
                let signer_public_auxinfo: Vec<_> = orig_auxinfo_output
                    .public_auxinfo()
                    .iter()
                    .filter(|info| signer_ids_set.contains(&info.participant()))
                    .cloned()
                    .collect();

                auxinfo::Output::from_parts(
                    signer_public_auxinfo,
                    orig_auxinfo_output.private_auxinfo().clone(),
                )
                .unwrap()
            };

            let tpresign_abort_input = tpresign::tpresign_abort::Input::new(
                local_storage,
                signer_auxinfo_output,
                signer_tshare_output,
            );

            // "active signer" 중 다른 signer들의 id
            let other_ids: Vec<_> = signer_ids
                .iter()
                .copied()
                .filter(|id| *id != config.id())
                .collect();

            TpresignAbortParticipant::new(sid, config.id(), other_ids, tpresign_abort_input)
                .expect("Failed to create PresignParticipant")
        })
        .collect::<Vec<_>>();

    let is_delta_error = if let InternalError::DeltaError = error {
        true
    } else if let InternalError::SError = error {
        false
    } else {
        panic!("Unexpected error type for tpresign abort test");
    };

    let res: HashMap<ParticipantIdentifier, Vec<ParticipantIdentifier>> = test_tpresign_abort(
        tpresign_abort_participants,
        &mut rng,
        sid,
        is_delta_error,
        &mut central_server,
        &mut participant_inbox,
    )
    .unwrap();

    assert!(participant_inbox.is_empty());

    res
}
