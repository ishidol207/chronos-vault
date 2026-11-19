#[cfg(test)]
mod multi_session_tests {
    use std::sync::{Arc, Barrier};
    use std::thread;

    use crate::{
        delegate_process_message, participant_factory, ready_message_factory, remove_session,
        AUXINFOPARTICIPANT, SessionKey,
    };

    fn map_contains(sid: u64) -> bool {
        let key: SessionKey = sid;
        AUXINFOPARTICIPANT.read().unwrap().contains_key(&key)
    }

    // 테스트 1: State Overwrite 방지
    #[test]
    fn test_no_state_overwrite() {
        let sid_a: u64 = 110001;
        let sid_b: u64 = 110002;

        participant_factory("AuxInfo", sid_a, 1, &[2], "");
        assert!(map_contains(sid_a), "세션 A 등록 후 HashMap에 존재해야 함");

        participant_factory("AuxInfo", sid_b, 1, &[2], "");
        assert!(map_contains(sid_b), "세션 B 등록 후 HashMap에 존재해야 함");

        // ★ 세션 B 등록 후에도 세션 A 가 살아있어야 함
        assert!(map_contains(sid_a), "[State Overwrite 버그] 세션 B 등록 후 세션 A 가 사라짐");

        remove_session("AuxInfo", sid_a);
        remove_session("AuxInfo", sid_b);
    }

    // 테스트 2: 여러 세션 동시 공존
    #[test]
    fn test_multiple_sessions_coexist() {
        let base_sid: u64 = 130000;
        let n: u64 = 5;

        for i in 0..n {
            participant_factory("AuxInfo", base_sid + i, 1, &[2], "");
        }
        for i in 0..n {
            assert!(map_contains(base_sid + i), "세션 {} 이 HashMap에 없음", base_sid + i);
        }
        for i in 0..n {
            remove_session("AuxInfo", base_sid + i);
        }
    }

    // 테스트 3: remove_session 이 해당 세션만 삭제
    #[test]
    fn test_remove_session_isolates_correctly() {
        let sid_x: u64 = 140001;
        let sid_y: u64 = 140002;

        participant_factory("AuxInfo", sid_x, 1, &[2], "");
        participant_factory("AuxInfo", sid_y, 1, &[2], "");

        remove_session("AuxInfo", sid_x);

        assert!(!map_contains(sid_x), "remove 후 sid_x 가 남아있으면 안 됨");
        assert!(map_contains(sid_y),  "remove 가 sid_y 까지 삭제하면 안 됨");

        remove_session("AuxInfo", sid_y);
    }

    // 테스트 4: 멀티스레드 동시 등록 — 데이터 유실 없음
    #[test]
    fn test_concurrent_registration_no_data_loss() {
        let n_threads: u64 = 8;
        let base_sid: u64 = 150000;

        let barrier = Arc::new(Barrier::new(n_threads as usize));
        let handles: Vec<_> = (0..n_threads)
            .map(|i| {
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    participant_factory("AuxInfo", base_sid + i, 1, &[2], "");
                })
            })
            .collect();

        for h in handles { h.join().expect("스레드 패닉"); }

        let missing: Vec<u64> = (0..n_threads)
            .filter(|&i| !map_contains(base_sid + i))
            .map(|i| base_sid + i)
            .collect();
        assert!(missing.is_empty(), "[동시성 버그] 유실된 세션: {:?}", missing);

        for i in 0..n_threads { remove_session("AuxInfo", base_sid + i); }
    }

    // 테스트 5: delegate_process_message 가 올바른 세션 참여자를 라우팅
    #[test]
    fn test_delegate_routes_to_correct_session() {
        let sid_a: u64 = 160001;
        let sid_b: u64 = 160002;

        participant_factory("AuxInfo", sid_a, 1, &[2], "");
        participant_factory("AuxInfo", sid_b, 1, &[2], "");

        let ready_msg = ready_message_factory("AuxInfo", sid_a, 1);
        let result = delegate_process_message("AuxInfo", sid_a, &ready_msg);

        assert!(!result.is_empty(), "세션 A 메시지 처리 결과가 비어있으면 안 됨");
        assert!(map_contains(sid_b), "세션 A 처리가 세션 B 에 영향을 줌");

        remove_session("AuxInfo", sid_a);
        remove_session("AuxInfo", sid_b);
    }

    // 테스트 6: 미등록 세션에 delegate 호출 시 패닉
    #[test]
    fn test_nonexistent_session_panics() {
        let sid: u64 = 170001;
        let ready_msg = ready_message_factory("AuxInfo", sid, 1);
        let result = std::panic::catch_unwind(|| {
            delegate_process_message("AuxInfo", sid, &ready_msg);
        });
        assert!(result.is_err(), "미등록 세션 호출 시 패닉이 발생해야 함");
    }
}