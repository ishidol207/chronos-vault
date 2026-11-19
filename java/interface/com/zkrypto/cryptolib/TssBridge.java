package com.example.cryptolib;

public class TssBridge {

    static {
        // Cargo.toml의 package.name에 따라 라이브러리 이름을 지정합니다.
        // 예를 들어 package.name = "my_crypto_lib" 라면 "my_crypto_lib"를 로드합니다.
        try {
            System.loadLibrary("my_crypto_lib"); // cargo build --release로 생성된 라이브러리 파일명
        } catch (UnsatisfiedLinkError e) {
            System.err.println("Native code library failed to load.\n" + e);
            System.exit(1);
        }
    }

    // --- Rust FFI 함수에 매핑되는 Native 메서드들 ---

    public static native void participantFactory(
            String participantType,
            long sid,
            long id,
            long[] otherParticipantIds,
            String input
    );

    public static native String readyMessageFactory(
            String participantType,
            long sid,
            long myId
    );

    public static native String delegateProcessMessage(
            String participantType,
            String message
    );

    public static native String generateTshareInput(
            String auxinfoOutput,
            int threshold
    );

    public static native String generateTrefreshInput(
            String tshareOutput,
            String auxinfoOutput,
            int threshold
    );

    public static native String generateTpresignInput(
            long[] signerParticipantIds,
            String auxinfoOutput,
            String tshareOutput
    );

    public static native String generateSignInput(
            long myId,
            long[] signerParticipantIds,
            String tpresignOutput,
            String tshareOutput,
            byte[] messageBytes,
            int threshold
    );

    public static native String generateTrecoverHelperInput(
            long[] helperParticipantIds,
            long myParticipantId,
            long targetParticipantId,
            String tshareOutput,
            String auxinfoOutput,
            int threshold
    );

    public static native String generateTrecoverTargetInput(
            long[] helperParticipantIds,
            String auxinfoOutput,
            int threshold
    );

    /**
     * 중앙 서버를 위한 서명 조각 모으기 함수입니다.
     * @param messages 각 참여자로부터 받은 서명 조각 메시지(JSON 문자열) 배열
     * @return 최종 서명 결과 (JSON 문자열)
     */
    public static native String computeOutput(
            String[] messages,
            byte[] messageBytes,
            String publicKey,
            String chainId
    );

    public static native String getMasterKey(
            String tshareOutput
    );

    // --- 사용 예시 ---
    public static void main(String[] args) {
        System.out.println("TssBridge native library loaded successfully.");
        // 간단한 함수 호출 테스트
        try {
            String readyMsg = readyMessageFactory("AuxInfo", 123456789L, 1L);
            System.out.println("Successfully called readyMessageFactory.");
            System.out.println("Result: " + readyMsg);
        } catch (RuntimeException e) {
            System.err.println("A runtime exception occurred during native call:");
            e.printStackTrace();
        }
    }
}