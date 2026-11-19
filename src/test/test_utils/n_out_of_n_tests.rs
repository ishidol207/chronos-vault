use super::test_imports::*;

pub fn test_keygen(
    mut participants: Vec<KeygenParticipant<C>>,
    mut rng: &mut (impl rand::RngCore + rand::CryptoRng),
    sid: Identifier,
    central_server: &mut central_server::CentralServer,
    participant_inbox: &mut HashMap<ParticipantIdentifier, Vec<Message>>,
    all_pids: Vec<ParticipantIdentifier>,
    QUORUM_SIZE: usize,
) -> Result<HashMap<ParticipantIdentifier, keygen::Output<C>>> {
    let mut keygen_outputs: HashMap<ParticipantIdentifier, keygen::Output<C>> = HashMap::new();

    // 중앙 서버 -> 각 P_i: keygen 시작 메시지
    for p in participants.iter_mut() {
        participant_inbox
            .entry(p.id())
            .or_insert_with(Vec::new)
            .push(
                Message::new(
                    MessageType::Keygen(KeygenMessageType::Ready),
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
    for p in participants.iter_mut() {
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

    // 각 P_i: 중앙서버로부터 keygen R1CommitHash 메시지를 받고 이를 처리하여 R2Decommit 메시지를 생성
    // R2Decommit 메시지를 중앙 서버로 전송
    for p in participants.iter_mut() {
        let current_pid = p.id();
        let msgs = central_server.fetch_messages(
            MessageType::Keygen(KeygenMessageType::R1CommitHash),
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
    assert!(participants.iter().all(|p| p.is_r1_done()));

    // 각 P_i: 중앙 서버로부터 keygen R2Decommit 메시지를 받고 이를 처리하여 R3Proof 메시지를 생성
    // R3Proof 메시지를 중앙 서버로 전송
    for p in participants.iter_mut() {
        let current_pid = p.id();
        let msgs = central_server.fetch_messages(
            MessageType::Keygen(KeygenMessageType::R2Decommit),
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

    // Check if all participants have completed round two
    assert!(participants.iter().all(|p| p.is_r2_done()));

    // 각 P_i: 중앙 서버로부터 keygen R3Proof 메시지를 받고 이를 처리하여 최종 출력 생성
    for p in participants.iter_mut() {
        let current_pid = p.id();
        let msgs = central_server.fetch_messages(
            MessageType::Keygen(KeygenMessageType::R3Proof),
            &current_pid,
        );
        for msg in msgs {
            let res = p.process_message(&mut rng, &msg)?;
            if let ProcessOutcome::Done(output) = res {
                keygen_outputs.insert(current_pid, output);
            }
        }
    }

    // Make sure every player got an output
    assert_eq!(keygen_outputs.len(), QUORUM_SIZE);

    // Check returned outputs
    //
    // Every participant should have a public output from every other participant
    // and, for a given participant, they should be the same in every output
    for &pid_to_check in &all_pids {
        let publics_for_pid: Vec<_> = keygen_outputs
                    .iter()
                    .map(|(pid,output)| {
                        output
                            .public_key_shares()
                            .iter()
                            .find(|key_share| key_share.participant() == pid_to_check)
                            .expect("Every participant should have a public output from every other participant")
                    })
                    .collect();

        // Assert that all collected public key shares are identical
        assert!(
            publics_for_pid.windows(2).all(|pks| pks[0] == pks[1]),
            "All collected public key shares must be identical"
        );
    }

    // Check that each participant's own `PublicKeyshare` corresponds to their `PrivateKeyshare`
    for (pid, output) in &keygen_outputs {
        let public_share = output
            .public_key_shares()
            .iter()
            .find(|public_share| public_share.participant() == *pid)
            .expect("Each participant's output must contain their own public key share");

        let expected_public_share =
            C::GENERATOR.multiply_by_bignum(output.private_key_share().as_ref())?;

        assert_eq!(public_share.as_ref(), &expected_public_share);
    }

    // Check that every participant has the same `rid` value
    let rids: Vec<_> = keygen_outputs.values().map(|output| output.rid()).collect();
    assert!(
        rids.windows(2).all(|r| r[0] == r[1]),
        "All participants must have the same rid"
    );

    Ok(keygen_outputs.clone())
}

pub fn test_auxinfo(
    mut participants: Vec<AuxInfoParticipant<C>>,
    mut rng: &mut (impl rand::RngCore + rand::CryptoRng),
    sid: Identifier,
    central_server: &mut central_server::CentralServer,
    participant_inbox: &mut HashMap<ParticipantIdentifier, Vec<Message>>,
    all_pids: Vec<ParticipantIdentifier>,
    QUORUM_SIZE: usize,
) -> Result<HashMap<ParticipantIdentifier, auxinfo::Output>> {
    let mut auxinfo_outputs = Vec::<auxinfo::Output>::new(); // 중앙 서버 -> 각 P_i: auxinfo 시작 메시지
    for p in participants.iter_mut() {
        participant_inbox
            .entry(p.id())
            .or_insert_with(Vec::new)
            .push(
                Message::new(
                    MessageType::Auxinfo(AuxinfoMessageType::Ready),
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
    for p in participants.iter_mut() {
        let current_pid = p.id();
        if let Some(messages_for_p) = participant_inbox.remove(&current_pid) {
            for msg in messages_for_p {
                let res = p.process_message(&mut rng, &msg)?;
                let res = res.into_messages().unwrap();
                // P_i -> 중앙 서버: auxinfo R1CommitHash
                for m in res {
                    central_server.send_message(m)?;
                }
            }
        }
    }

    // 각 P_i: 중앙서버로부터 auxinfo R1CommitHash 메시지를 받고 이를 처리하여 R2Decommit 메시지를 생성
    // R2Decommit 메시지를 중앙 서버로 전송
    for p in participants.iter_mut() {
        let current_pid = p.id();
        let msgs = central_server.fetch_messages(
            MessageType::Auxinfo(AuxinfoMessageType::R1CommitHash),
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
    assert!(participants.iter().all(|p| p.is_r1_done()));

    // 각 P_i: 중앙 서버로부터 auxinfo R2Decommit 메시지를 받고 이를 처리하여 R3Proof 메시지를 생성
    // R3Proof 메시지를 중앙 서버로 전송
    for p in participants.iter_mut() {
        let current_pid = p.id();
        let msgs = central_server.fetch_messages(
            MessageType::Auxinfo(AuxinfoMessageType::R2Decommit),
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

    // Check if all participants have completed round two
    assert!(participants.iter().all(|p| p.is_r2_done()));

    // 각 P_i: 중앙 서버로부터 auxinfo R3Proof 메시지를 받고 이를 처리하여 최종 출력 생성
    for p in participants.iter_mut() {
        let current_pid = p.id();
        let msgs = central_server.fetch_messages(
            MessageType::Auxinfo(AuxinfoMessageType::R3Proof),
            &current_pid,
        );
        for msg in msgs {
            let res = p.process_message(&mut rng, &msg)?;
            if let ProcessOutcome::Done(output) = res {
                auxinfo_outputs.push(output);
            }
        }
    }

    // Make sure every player got an output
    assert_eq!(auxinfo_outputs.len(), QUORUM_SIZE);

    let context: protocol::SharedContext<C> = SharedContext::fill_context(all_pids, sid);

    for party in participants.iter() {
        let pid = party.id();

        // Collect the AuxInfoPublic associated with pid from every output
        let mut publics_for_pid = vec![];
        for output in &mut *auxinfo_outputs {
            let public_key = output.find_public(pid);
            assert!(public_key.is_some());
            // Check that it's valid while we're here.
            assert!(public_key.unwrap().clone().verify(&context).is_ok());
            publics_for_pid.push(public_key.unwrap());
        }

        // Make sure they're all equal
        assert!(publics_for_pid.windows(2).all(|pks| pks[0] == pks[1]));
    }
    let mut res: HashMap<ParticipantIdentifier, auxinfo::Output> = HashMap::new();

    // Check that private outputs are consistent
    for (output, pid) in auxinfo_outputs
        .iter()
        .zip(participants.iter().map(|p| p.id()))
    {
        let public_key = output.find_public(pid);
        assert!(public_key.is_some());
        assert_eq!(
            *public_key.unwrap().pk(),
            output.private_auxinfo().encryption_key()
        );
        res.insert(pid, output.clone());
    }

    Ok(res)
}

pub fn test_keyrefresh(
    mut participants: Vec<KeyrefreshParticipant<C>>,
    mut rng: &mut (impl rand::RngCore + rand::CryptoRng),
    sid: Identifier,
    central_server: &mut central_server::CentralServer,
    participant_inbox: &mut HashMap<ParticipantIdentifier, Vec<Message>>,
    all_pids: Vec<ParticipantIdentifier>,
    QUORUM_SIZE: usize,
) -> Result<HashMap<ParticipantIdentifier, crate::keyrefresh::Output<C>>> {
    // 중앙 서버 -> 각 P_i: keyrefresh 시작 메시지
    for p in participants.iter_mut() {
        participant_inbox
            .entry(p.id())
            .or_insert_with(Vec::new)
            .push(
                Message::new(
                    MessageType::Keyrefresh(KeyrefreshMessageType::Ready),
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
    for p in participants.iter_mut() {
        let current_pid = p.id();
        if let Some(messages_for_p) = participant_inbox.remove(&current_pid) {
            for msg in messages_for_p {
                let res = p.process_message(&mut rng, &msg)?;
                let res = res.into_messages().unwrap();
                // P_i -> 중앙 서버: keyrefresh R1CommitHash
                for m in res {
                    central_server.send_message(m)?;
                }
            }
        }
    }

    // 각 P_i: 중앙서버로부터 keyrefresh R1CommitHash 메시지를 받고 이를 처리하여 R2Decommit 메시지를 생성
    // R2Decommit 메시지를 중앙 서버로 전송
    for p in participants.iter_mut() {
        let current_pid = p.id();
        let msgs = central_server.fetch_messages(
            MessageType::Keyrefresh(KeyrefreshMessageType::R1CommitHash),
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
    assert!(participants.iter().all(|p| p.is_r1_done()));

    // 각 P_i: 중앙 서버로부터 keyrefresh R2Decommit 메시지를 받고 이를 처리하여 R3Proof 및 R3PrivateUpdate 메시지를 생성
    // R3Proof 및 R3PrivateUpdate 메시지를 중앙 서버로 전송
    for p in participants.iter_mut() {
        let current_pid = p.id();
        let msgs = central_server.fetch_messages(
            MessageType::Keyrefresh(KeyrefreshMessageType::R2Decommit),
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

    // Check if all participants have completed round two
    assert!(participants.iter().all(|p| p.is_r2_done()));

    let mut keyrefresh_outputs: HashMap<ParticipantIdentifier, crate::keyrefresh::Output<C>> =
        HashMap::new();

    // 각 P_i: 중앙 서버로부터 keyrefresh R3Proof 및 R3PrivateUpdate 메시지를 받고 이를 처리하여 최종 출력 생성
    for p in participants.iter_mut() {
        let current_pid = p.id();
        // R3Proofs 메시지 fetch
        let mut msgs = central_server.fetch_messages(
            MessageType::Keyrefresh(KeyrefreshMessageType::R3Proofs),
            &current_pid,
        );

        // R3PrivateUpdate 메시지 fetch
        let priv_msgs = central_server.fetch_messages(
            MessageType::Keyrefresh(KeyrefreshMessageType::R3PrivateUpdate),
            &current_pid,
        );
        msgs.extend(priv_msgs);

        for msg in msgs {
            let res = p.process_message(&mut rng, &msg)?;
            if let ProcessOutcome::Done(output) = res {
                keyrefresh_outputs.insert(current_pid, output);
            }
        }
    }
    let outputs: Vec<_> = keyrefresh_outputs.values().collect();

    assert_eq!(outputs.len(), QUORUM_SIZE);

    // Check returned outputs
    //
    // Every participant should have a public output from every other participant
    // and, for a given participant, they should be the same in every output
    for party in participants.iter_mut() {
        let pid = party.id();

        // Collect the KeySharePublic associated with pid from every output
        let mut publics_for_pid = vec![];
        for output in &outputs {
            let key_share = output
                .public_key_shares()
                .iter()
                .find(|key_share| key_share.participant() == pid);

            // Make sure every participant had a key share for this pid
            assert!(key_share.is_some());
            publics_for_pid.push(key_share.unwrap());
        }

        // Make sure they're all equal
        assert!(publics_for_pid.windows(2).all(|pks| pks[0] == pks[1]));
    }
    // Check that each participant's own `PublicKeyshare` corresponds to their
    // `PrivateKeyshare`
    // todo: 기존 테스트와 달라짐 -> 재확인 필요
    for (pid, output) in &keyrefresh_outputs {
        let public_share = output
            .public_key_shares()
            .iter()
            .find(|public_share| public_share.participant() == *pid);
        assert!(public_share.is_some());

        let expected_public_share =
            C::GENERATOR.multiply_by_bignum(output.private_key_share().as_ref())?;
        assert_eq!(public_share.unwrap().as_ref(), &expected_public_share);
    }

    let inputs = participants
        .iter()
        .map(|p| p.get_input().clone())
        .collect::<Vec<_>>();

    for (input, output) in inputs.iter().zip(outputs.iter()) {
        // The public key of the quorum has not changed.
        let pk_before = input.keygen_output().public_key()?;
        let pk_after = output.public_key()?;
        assert_eq!(pk_before, pk_after);

        // All key shares have changed.
        let public_shares_before = input
            .public_key_shares()
            .iter()
            .map(|key_share| serialize!(key_share.as_ref()).unwrap())
            .collect::<HashSet<_>>();

        let public_shares_after = output
            .public_key_shares()
            .iter()
            .map(|key_share| serialize!(key_share.as_ref()).unwrap())
            .collect::<HashSet<_>>();

        public_shares_before
            .intersection(&public_shares_after)
            .for_each(|_| {
                panic!("All public key shares must change.");
            });

        // The rid has not changed.
        assert_eq!(input.keygen_output().rid(), output.rid());
    }

    Ok(keyrefresh_outputs.clone())
}

pub fn test_presign(
    mut participants: Vec<PresignParticipant<C>>,
    mut rng: &mut (impl rand::RngCore + rand::CryptoRng),
    sid: Identifier,
    central_server: &mut central_server::CentralServer,
    participant_inbox: &mut HashMap<ParticipantIdentifier, Vec<Message>>,
    all_pids: Vec<ParticipantIdentifier>,
    QUORUM_SIZE: usize,
    keygen_outputs: Vec<keygen::Output<C>>,
) -> Result<HashMap<ParticipantIdentifier, PresignRecord<C>>> {
    let mut presign_outputs: HashMap<ParticipantIdentifier, PresignRecord<C>> = HashMap::new();

    for p in participants.iter_mut() {
        participant_inbox
            .entry(p.id())
            .or_insert_with(Vec::new)
            .push(
                Message::new(
                    MessageType::Presign(PresignMessageType::Ready),
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
    for p in participants.iter_mut() {
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
    for p in participants.iter_mut() {
        let current_pid = p.id();
        let mut msgs = central_server.fetch_messages(
            MessageType::Presign(PresignMessageType::RoundOneBroadcast),
            &current_pid,
        );
        let msgs_priv = central_server.fetch_messages(
            MessageType::Presign(PresignMessageType::RoundOne),
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
    assert!(participants.iter().all(|p| p.is_r1_done()));

    // 각 P_i: 중앙 서버로부터 presign RoundTwo 메시지를 받고 이를 처리하여 RoundThree 메시지를 생성
    // RoundThree 메시지를 중앙 서버로 전송
    for p in participants.iter_mut() {
        let current_pid = p.id();
        let msgs = central_server.fetch_messages(
            MessageType::Presign(PresignMessageType::RoundTwo),
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

    // Check if all participants have completed round two
    assert!(participants.iter().all(|p| p.is_r2_done()));

    // 각 P_i: 중앙 서버로부터 keygen RoundThree 메시지를 받고 이를 처리하여 최종 출력 생성
    for p in participants.iter_mut() {
        let current_pid = p.id();
        let msgs = central_server.fetch_messages(
            MessageType::Presign(PresignMessageType::RoundThree),
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
    assert!(participants.iter().all(|p| p.is_r3_done()));

    let outputs: Vec<_> = presign_outputs.values().collect();

    // Make sure every player got an output
    assert_eq!(outputs.len(), QUORUM_SIZE);

    let records: Vec<_> = outputs.into_iter().cloned().collect();

    // Check validity of set; this will panic if anything is wrong
    presign_record_set_is_valid(records, keygen_outputs);

    Ok(presign_outputs.clone())
}

pub fn test_sign(
    participants: &mut Vec<SignParticipant<C>>,
    mut rng: &mut (impl rand::RngCore + rand::CryptoRng),
    sid: Identifier,
    central_server: &mut central_server::CentralServer,
    participant_inbox: &mut HashMap<ParticipantIdentifier, Vec<Message>>,
    all_pids: Vec<ParticipantIdentifier>,
    QUORUM_SIZE: usize,
    non_distributed_sig: <C as curve::CurveTrait>::ECDSASignature,
    public_key: &<C as curve::CurveTrait>::VerifyingKey,
    digest: Keccak256,
) -> Result<HashMap<ParticipantIdentifier, <C as curve::CurveTrait>::ECDSASignature>> {
    let mut sign_outputs: HashMap<ParticipantIdentifier, <C as curve::CurveTrait>::ECDSASignature> =
        HashMap::new();

    for p in participants.iter_mut() {
        participant_inbox
            .entry(p.id())
            .or_insert_with(Vec::new)
            .push(
                Message::new(
                    MessageType::Sign(SignMessageType::Ready),
                    sid,
                    p.id(),
                    Some(p.id()),
                    false,
                    b"init",
                )
                .unwrap(),
            );
    }

    // 각 P_i: handle 메시지 (Ready) 후 RoundOneShare 중앙 서버로 전송
    for p in participants.iter_mut() {
        let current_pid = p.id();
        if let Some(messages_for_p) = participant_inbox.remove(&current_pid) {
            for msg in messages_for_p {
                let res = p.process_message(&mut rng, &msg)?;
                let res = res.into_messages().unwrap();
                // P_i -> 중앙 서버: sign RoundOneShare
                for m in res {
                    central_server.send_message(m)?;
                }
            }
        }
    }

    // 각 P_i: 중앙서버로부터 sign RoundOneShare 메시지를 받고 이를 처리하여 서명 생성
    for p in participants.iter_mut() {
        let current_pid = p.id();
        let msgs = central_server.fetch_messages(
            MessageType::Sign(SignMessageType::RoundOneShare),
            &current_pid,
        );
        for msg in msgs {
            let res = p.process_message(&mut rng, &msg)?;
            if let ProcessOutcome::Done(output) = res {
                sign_outputs.insert(current_pid, output);
            }
        }
    }

    // Everyone should have gotten an output
    assert_eq!(sign_outputs.len(), QUORUM_SIZE);

    let signatures = sign_outputs.clone().into_values().collect::<Vec<_>>();

    // Everyone should have gotten the same output. We don't use a hashset because
    // the underlying signature type doesn't derive `Hash`
    assert!(signatures
        .windows(2)
        .all(|signature| signature[0] == signature[1]));

    // Make sure the signature we got matches the non-distributed one
    let distributed_sig = &signatures[0];
    assert_eq!(distributed_sig, &non_distributed_sig);

    // Verify that we have a valid signature under the public key for the `message`
    assert!(public_key
        .verify_digest(digest.clone(), distributed_sig.deref())
        .is_ok());

    // Check we are able to create a recoverable signature.
    let recid = RecoveryId::trial_recovery_from_digest(public_key, digest.clone(), distributed_sig)
        .expect("Failed to recover signature");
    let recovered_pk = <C as CurveTrait>::VerifyingKey::recover_from_digest(
        digest,
        distributed_sig,
        RecoveryId::from_byte(recid.into()).expect("Invalid recovery ID"),
    )
    .unwrap();
    assert_eq!(
        recovered_pk, *public_key,
        "Recovered public key does not match orig one."
    );

    Ok(sign_outputs.clone())
}
