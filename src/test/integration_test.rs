use crate::{
    test::test_utils::{n_out_of_n_tests::*, t_out_of_n_tests::*, test_imports::*},
    trecover::{
        self,
        input::{HelperInput, TargetInput},
    },
};

#[test]
fn integration_test() -> Result<()> {
    let QUORUM_SIZE = 3;
    let mut rng = init_testing();
    let sid = Identifier::random(&mut rng);

    let participant_configs = ParticipantConfig::random_quorum(QUORUM_SIZE, &mut rng)?;
    let all_pids: Vec<_> = participant_configs.iter().map(|c| c.id()).collect();
    let mut central_server = central_server::CentralServer::new(all_pids.clone());
    let mut participant_inbox: HashMap<ParticipantIdentifier, Vec<Message>> =
        all_pids.iter().map(|pid| (*pid, Vec::new())).collect();

    // ---------------------------------------- Keygen----------------------------------------
    let participants = participant_configs
        .iter()
        .map(|config| KeygenParticipant::new(sid, config.id(), config.other_ids().to_vec(), ()))
        .collect::<Result<Vec<_>>>()?;

    // keygen 프로토콜 실행
    let keygen_outputs = test_keygen(
        participants,
        &mut rng,
        sid,
        &mut central_server,
        &mut participant_inbox,
        all_pids.clone(),
        QUORUM_SIZE,
    )?;
    assert!(participant_inbox.is_empty());

    // ---------------------------------------- Auxinfo ----------------------------------------
    let mut participants: Vec<auxinfo::participant::AuxInfoParticipant<C>> = participant_configs
        .iter()
        .map(|config| AuxInfoParticipant::new(sid, config.id(), config.other_ids().to_vec(), ()))
        .collect::<Result<Vec<_>>>()?;

    // Auxinfo 프로토콜 실행
    let auxinfo_outputs = test_auxinfo(
        participants,
        &mut rng,
        sid,
        &mut central_server,
        &mut participant_inbox,
        all_pids.clone(),
        QUORUM_SIZE,
    )?;
    assert!(participant_inbox.is_empty());

    // ---------------------------------------- Keyrefresh ----------------------------------------
    let mut participants: Vec<KeyrefreshParticipant<C>> = participant_configs
        .iter()
        .map(|config| {
            let keygen_output = keygen_outputs.get(&config.id()).unwrap();
            let auxinfo_output = auxinfo_outputs.get(&config.id()).unwrap();
            let keyrefresh_input =
                crate::keyrefresh::input::Input::new(auxinfo_output.clone(), keygen_output.clone())
                    .expect("Failed to create keyrefresh input");
            let participant = KeyrefreshParticipant::new(
                sid,
                config.id(),
                config.other_ids().to_vec(),
                keyrefresh_input,
            )
            .expect("Failed to create KeyrefreshParticipant");
            participant
        })
        .collect::<Vec<KeyrefreshParticipant<C>>>();

    let keyrefresh_outputs = test_keyrefresh(
        participants,
        &mut rng,
        sid,
        &mut central_server,
        &mut participant_inbox,
        all_pids.clone(),
        QUORUM_SIZE,
    )?;
    assert!(participant_inbox.is_empty());

    // ---------------------------------------- Presign ----------------------------------------

    let mut participants: Vec<PresignParticipant<C>> = participant_configs
        .iter()
        .map(|config| {
            let keygen_output = keyrefresh_outputs.get(&config.id()).unwrap();
            let auxinfo_output = auxinfo_outputs.get(&config.id()).unwrap();
            let presign_input =
                crate::presign::Input::new(auxinfo_output.clone(), keygen_output.clone())
                    .expect("Failed to create keyrefresh input");
            let participant = PresignParticipant::new(
                sid,
                config.id(),
                config.other_ids().to_vec(),
                presign_input,
            )
            .expect("Failed to create KeyrefreshParticipant");
            participant
        })
        .collect::<Vec<PresignParticipant<C>>>();

    let presign_outputs = test_presign(
        participants,
        &mut rng,
        sid,
        &mut central_server,
        &mut participant_inbox,
        all_pids.clone(),
        QUORUM_SIZE,
        keygen_outputs.values().cloned().collect::<Vec<_>>(),
    )?;
    assert!(participant_inbox.is_empty());

    // ---------------------------------------- Sign ----------------------------------------
    let message = b"the quick brown fox jumped over the lazy dog";

    let mut sign_participants: Vec<_> = participant_configs
        .iter()
        .map(|config| {
            let keygen_output = keygen_outputs
                .get(&config.id())
                .expect("Should have keygen output");
            let presign_output = presign_outputs
                .get(&config.id())
                .expect("Should have presign output");

            let mut sign_input = crate::sign::non_interactive_sign::participant::Input::new(
                message,
                presign_output.clone(),
                keygen_output.public_key_shares().to_vec(),
                QUORUM_SIZE,
            );

            let participant = crate::sign::non_interactive_sign::participant::SignParticipant::new(
                sid,
                config.id(),
                config.other_ids().to_vec(),
                sign_input,
            )
            .expect("Failed to create SignParticipant");

            participant
        })
        .collect::<Vec<SignParticipant<C>>>();

    let presign_outputs_vec = presign_outputs.values().cloned().collect::<Vec<_>>();
    let keygen_outputs_vec = keygen_outputs.values().cloned().collect::<Vec<_>>();

    // Save some things for later -- a signature constructucted from the records and
    // the public key
    let non_distributed_sig =
        compute_non_distributed_ecdsa(message, &presign_outputs_vec, &keygen_outputs_vec);
    let public_key = &keygen_outputs_vec[0].public_key().unwrap();
    let digest = Keccak256::new_with_prefix(message);

    let sign_outputs = test_sign(
        &mut sign_participants,
        &mut rng,
        sid,
        &mut central_server,
        &mut participant_inbox,
        all_pids.clone(),
        QUORUM_SIZE,
        non_distributed_sig, // 여기 아래로는 테스트용 데이터
        public_key,
        digest,
    );

    Ok(())
}
fn tpresign_and_tsign(
    tshare_outputs: &HashMap<ParticipantIdentifier, tshare::Output<C>>,
    auxinfo_outputs: &HashMap<ParticipantIdentifier, auxinfo::Output>,
    signers_configs: &[ParticipantConfig],
    sid: Identifier,
    mut rng: &mut (impl rand::RngCore + rand::CryptoRng),
    mut central_server: &mut central_server::CentralServer,
    mut participant_inbox: &mut HashMap<ParticipantIdentifier, Vec<Message>>,
    message: &[u8],
    THRESHOLD: usize,
) -> Result<HashMap<ParticipantIdentifier, <C as curve::CurveTrait>::ECDSASignature>> {
    let signer_ids: Vec<_> = signers_configs.iter().map(|c| c.id()).collect();
    let signer_ids_set: std::collections::HashSet<_> = signer_ids.iter().collect();

    // -------------------------------------------- Tpresign ----------------------------------------

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
    let tpresign_outputs = test_tpresign(
        tpresign_participants,
        &mut rng,
        sid,
        &mut central_server,
        &mut participant_inbox,
    )?;
    assert!(participant_inbox.is_empty());

    // -------------------------------------------- Tsign ----------------------------------------

    // t-out-of-n share를 t-out-of-t share로 변환하여 sign_participants 생성
    let mut sign_participants: Vec<_> = signers_configs
        .iter()
        .map(|config| {
            let keygen_output = {
                let tshare_output = tshare_outputs.get(&config.id()).unwrap();

                // "active signer"들의 public key share만 필터링한 tshare::Output 생성
                let signer_tshare_output = {
                    let signer_public_key_shares: Vec<_> = tshare_output
                        .public_key_shares()
                        .iter()
                        .filter(|share| signer_ids_set.contains(&share.participant()))
                        .cloned()
                        .collect();
                    tshare::Output::new(
                        signer_public_key_shares,
                        tshare_output.private_key_share().clone(),
                        *tshare_output.rid(),
                        tshare_output.threshold(),
                    )
                };

                // t-out-of-n share를 t-out-of-t share로 변환
                ToutofTHelper::<C>::convert_to_t_out_of_t_share(
                    &config.id(),
                    &signer_ids,
                    &signer_tshare_output,
                    *tshare_output.rid(),
                )
                .expect("Failed to convert t-of-n share to t-of-t share")
            };

            let t_out_of_t_public_shares = keygen_output.public_key_shares().to_vec();

            let sign_input = {
                let tpresign_output = tpresign_outputs
                    .get(&config.id())
                    .expect("Should have presign output");
                let presign_output: PresignRecord<C> = tpresign_output.clone().into();

                crate::sign::non_interactive_sign::participant::Input::new(
                    message,
                    presign_output.clone(),
                    t_out_of_t_public_shares.clone(),
                    THRESHOLD,
                )
            };

            let participant = crate::sign::non_interactive_sign::participant::SignParticipant::new(
                sid,
                config.id(),
                signer_ids
                    .iter()
                    .copied()
                    .filter(|&id| id != config.id())
                    .collect(),
                sign_input,
            )
            .expect("Failed to create SignParticipant");

            participant
        })
        .collect::<Vec<SignParticipant<C>>>();

    let presign_outputs_vec: Vec<PresignRecord<C>> = signer_ids
        .iter()
        .map(|id| {
            let tpresign_record = tpresign_outputs
                .get(id)
                .expect("Presign output not found for signer");
            tpresign_record.clone().into()
        })
        .collect();

    // tshare_outputs에서 active signer들의 public key share만 필터링
    let signer_public_key_shares: Vec<_> = tshare_outputs
        .get(&signer_ids[0])
        .unwrap()
        .public_key_shares()
        .iter()
        .filter(|share| signer_ids_set.contains(&share.participant()))
        .cloned()
        .collect();

    // 서명 참여자들의 public key share만 필터링하여 새로운 tshare::Output 생성
    let keygen_outputs_vec: Vec<keygen::Output<C>> = signer_ids
        .iter()
        .map(|id| {
            let orig_tshare_output = tshare_outputs.get(id).unwrap();

            // active signer의 public key share만 필터링
            let signer_public_key_shares: Vec<_> = orig_tshare_output
                .public_key_shares()
                .iter()
                .filter(|share| signer_ids_set.contains(&share.participant()))
                .cloned()
                .collect();

            // 필터링된 정보로 새로운 tshare::Output 객체 생성
            let signer_tshare_output = tshare::Output::new(
                signer_public_key_shares,
                orig_tshare_output.private_key_share().clone(),
                *orig_tshare_output.rid(),
                orig_tshare_output.threshold(),
            );

            // t-out-of-n share를 t-out-of-t share로 변환
            ToutofTHelper::<C>::convert_to_t_out_of_t_share(
                id,
                &signer_ids,
                &signer_tshare_output,
                *orig_tshare_output.rid(),
            )
            .expect("Failed to convert t-of-n share to t-of-t share")
        })
        .collect();

    // only for debugging
    let non_distributed_sig =
        compute_non_distributed_ecdsa(message, &presign_outputs_vec, &keygen_outputs_vec);
    let public_key = &keygen_outputs_vec[0].public_key().unwrap();
    let digest = Keccak256::new_with_prefix(message);

    let sign_outputs = test_sign(
        &mut sign_participants,
        &mut rng,
        sid,
        &mut central_server,
        &mut participant_inbox,
        signer_ids.clone(),
        THRESHOLD,
        non_distributed_sig, // 여기 아래로는 테스트용 데이터
        public_key,
        digest,
    )?;

    Ok(sign_outputs)
}

// auxinfo -> tshare -> tpresign & sign (P_0, P_1)
// -> trefresh -> tpresign & sign (P_1, P_2)
#[test]
fn tshare_integration_test() -> Result<()> {
    // Total number of participants
    const NUM_ALL_PARTICIPANTS: usize = 3;
    // How many parties are needed to sign
    const THRESHOLD: usize = 2;
    let mut rng = init_testing();
    let sid = Identifier::random(&mut rng);

    let participant_configs = ParticipantConfig::random_quorum(NUM_ALL_PARTICIPANTS, &mut rng)?;
    let all_pids: Vec<_> = participant_configs.iter().map(|c| c.id()).collect();
    let mut central_server = central_server::CentralServer::new(all_pids.clone());
    let mut participant_inbox: HashMap<ParticipantIdentifier, Vec<Message>> =
        all_pids.iter().map(|pid| (*pid, Vec::new())).collect();

    // ---------------------------------------- Auxinfo ----------------------------------------
    let auxinfo_participants: Vec<auxinfo::participant::AuxInfoParticipant<C>> =
        participant_configs
            .iter()
            .map(|config| {
                AuxInfoParticipant::new(sid, config.id(), config.other_ids().to_vec(), ())
            })
            .collect::<Result<Vec<_>>>()?;

    // Auxinfo 프로토콜 실행
    let auxinfo_outputs = test_auxinfo(
        auxinfo_participants,
        &mut rng,
        sid,
        &mut central_server,
        &mut participant_inbox,
        all_pids.clone(),
        NUM_ALL_PARTICIPANTS,
    )?;
    central_server.clear();
    let mut central_server = central_server::CentralServer::new(all_pids.clone());

    assert!(participant_inbox.is_empty());

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

    // ---------------------------------------- Threshold Presign and Sign ----------------------------------------
    // 프로토콜에 참여할 THRESHOLD 명의 active participants
    let signers_configs = &participant_configs[..THRESHOLD];

    let message = b"the quick brown fox jumped over the lazy dog";

    let signatures_before_refresh = tpresign_and_tsign(
        &tshare_outputs,
        &auxinfo_outputs,
        signers_configs,
        sid,
        &mut rng,
        &mut central_server,
        &mut participant_inbox,
        message,
        THRESHOLD,
    )?;
    central_server.clear();
    let mut central_server = central_server::CentralServer::new(all_pids.clone());

    assert!(participant_inbox.is_empty());

    // ---------------------------------------- Threshold Key refresh ----------------------------------------
    let mut trefresh_participants: Vec<TrefreshParticipant<C>> = participant_configs
        .iter()
        .map(|config| {
            let tshare = tshare_outputs.get(&config.id()).unwrap();
            let trefresh_input: crate::trefresh::input::Input<C> =
                crate::trefresh::input::Input::new(
                    auxinfo_outputs.get(&config.id()).unwrap().clone(),
                    tshare.clone(),
                    THRESHOLD,
                )
                .expect("Failed to create tshare input for keyrefresh");

            TrefreshParticipant::new(
                sid,
                config.id(),
                config.other_ids().to_vec(),
                trefresh_input,
            )
            .unwrap()
        })
        .collect::<Vec<_>>();

    let refreshed_tshare_outputs = test_trefresh(
        &mut trefresh_participants,
        &mut rng,
        sid,
        &mut central_server,
        &mut participant_inbox,
        NUM_ALL_PARTICIPANTS,
        master_pk,
    )?;
    central_server.clear();
    let mut central_server = central_server::CentralServer::new(all_pids.clone());

    assert!(participant_inbox.is_empty());

    // ---------------------------------------- Threshold Presign and sign after refresh ----------------------------------------

    // 프로토콜에 참여할 THRESHOLD 명의 active participants
    // refresh 전의 signers와 다르게 설정
    let new_signers_configs = &participant_configs[1..THRESHOLD + 1];

    let signatures_after_refresh = tpresign_and_tsign(
        &refreshed_tshare_outputs,
        &auxinfo_outputs,
        new_signers_configs,
        sid,
        &mut rng,
        &mut central_server,
        &mut participant_inbox,
        message,
        THRESHOLD,
    )?;

    // key refresh 전후로 같은 Pk로 검증되는지 확인
    <C as CurveTrait>::VerifyingKey::verify_signature(
        &master_pk,
        Keccak256::new_with_prefix(message),
        signatures_before_refresh[&participant_configs[0].id()],
    )?;
    <C as CurveTrait>::VerifyingKey::verify_signature(
        &master_pk,
        Keccak256::new_with_prefix(message),
        signatures_after_refresh[&participant_configs[1].id()],
    )?;

    assert!(participant_inbox.is_empty());

    Ok(())
}

#[test]
fn test_run_trecover() -> Result<()> {
    // Total number of participants
    const NUM_ALL_PARTICIPANTS: usize = 3;
    // How many parties are needed to sign
    const THRESHOLD: usize = 2;
    let mut rng = init_testing();
    let sid = Identifier::random(&mut rng);

    let participant_configs = ParticipantConfig::random_quorum(NUM_ALL_PARTICIPANTS, &mut rng)?;
    let all_pids: Vec<_> = participant_configs.iter().map(|c| c.id()).collect();
    let mut central_server = central_server::CentralServer::new(all_pids.clone());
    let mut participant_inbox: HashMap<ParticipantIdentifier, Vec<Message>> =
        all_pids.iter().map(|pid| (*pid, Vec::new())).collect();

    // ---------------------------------------- Auxinfo ----------------------------------------
    let auxinfo_participants: Vec<auxinfo::participant::AuxInfoParticipant<C>> =
        participant_configs
            .iter()
            .map(|config| {
                AuxInfoParticipant::new(sid, config.id(), config.other_ids().to_vec(), ())
            })
            .collect::<Result<Vec<_>>>()?;

    // Auxinfo 프로토콜 실행
    let auxinfo_outputs = test_auxinfo(
        auxinfo_participants,
        &mut rng,
        sid,
        &mut central_server,
        &mut participant_inbox,
        all_pids.clone(),
        NUM_ALL_PARTICIPANTS,
    )?;
    central_server.clear();
    let mut central_server = central_server::CentralServer::new(all_pids.clone());

    assert!(participant_inbox.is_empty());

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

    // ---------------------------------------- Threshold trecover ----------------------------------------
    // P_1이 자신의 share를 잃어버렸다고 가정
    // 1. trecover 이전에 auxinfo를 수행

    let new_auxinfo_participants: Vec<auxinfo::participant::AuxInfoParticipant<C>> =
        participant_configs
            .iter()
            .map(|config| {
                AuxInfoParticipant::new(sid, config.id(), config.other_ids().to_vec(), ())
            })
            .collect::<Result<Vec<_>>>()?;

    // Auxinfo 프로토콜 실행
    let new_auxinfo_outputs = test_auxinfo(
        new_auxinfo_participants,
        &mut rng,
        sid,
        &mut central_server,
        &mut participant_inbox,
        all_pids.clone(),
        NUM_ALL_PARTICIPANTS,
    )?;
    central_server.clear();
    let mut central_server = central_server::CentralServer::new(all_pids.clone());

    assert!(participant_inbox.is_empty());

    // 2. trecover 프로토콜 실행
    let target_participant_pid = participant_configs[0].id();
    let helper_participant_pids = participant_configs
        .iter()
        .filter(|config| config.id() != target_participant_pid)
        .map(|config| config.id())
        .collect::<Vec<_>>();

    let helper_participants: Vec<trecover::participant::TrecoverHelperParticipant<C>> =
        participant_configs
            .iter()
            .filter(|config| config.id() != target_participant_pid)
            .map(|config| {
                let other_helper_pids = helper_participant_pids
                    .iter()
                    .filter(|pid| **pid != config.id())
                    .cloned()
                    .collect::<Vec<_>>();
                let helper_input = HelperInput::new(
                    THRESHOLD,
                    other_helper_pids,
                    target_participant_pid,
                    tshare_outputs.get(&config.id()).unwrap().clone(),
                    new_auxinfo_outputs.get(&config.id()).unwrap().clone(),
                );

                trecover::participant::TrecoverHelperParticipant::new(
                    sid,
                    config.id(),
                    config.other_ids().to_vec(),
                    helper_input,
                )
            })
            .collect::<Result<Vec<_>>>()?;

    let target_participant: trecover::participant::TrecoverTargetParticipant<C> =
        trecover::participant::TrecoverTargetParticipant::new(
            sid,
            target_participant_pid,
            participant_configs[0].other_ids().to_vec(),
            TargetInput::new(
                THRESHOLD,
                helper_participant_pids,
                new_auxinfo_outputs
                    .get(&target_participant_pid)
                    .unwrap()
                    .clone(),
            ),
        )?;

    let recovered_share = test_trecover(
        target_participant,
        helper_participants,
        &mut rng,
        sid,
        &mut central_server,
        &mut participant_inbox,
    )?;

    let tshare_before_recovery = tshare_outputs.get(&target_participant_pid).unwrap();

    assert_eq!(tshare_before_recovery, &recovered_share);
    Ok(())
}
