# Chronos Vault 팀원 연동 가이드

Chronos Vault는 Bitcoin Testnet4 지갑입니다. 사용자 기기의 U(1), 인증 서버의 S(2), 비상 카드·파일의 R(3) 중 두 참여자가 임계 ECDSA 서명을 만듭니다. 각 참여자는 자기 위치에서 키를 열고, 브라우저는 완성한 서명을 지갑 공동 공개키로 검증합니다.

## 팀 레포에서 시작하기

기존 클론에서는 레포 루트에서 아래 명령으로 서버·브라우저 래퍼·연동 문서를 함께 받습니다.

```sh
git switch main
git pull --ff-only origin main
```

**프론트 담당자**는 `bitcoin/browser/`에 들어 있는 빌드된 WASM과 JavaScript를 앱의 정적 폴더에 복사합니다. Rust 설치 없이 연동할 수 있습니다. [복사 명령과 호출 예제](bitcoin/browser/README.md)

**인증 담당자**는 등록된 소유자·상속인과 해당 거래를 확인한 뒤 S 서버에서 티켓을 발급받아 프론트에 전달합니다. [S 서버 실행 및 티켓 발급](bitcoin/SIGNING_SERVER.md)

## 1. 화면별 서명 조합

| 화면 | 서명자 | 기기가 선택할 신원 파일 | 호출 |
|---|---|---|---|
| 일반 송금 | U + S | U의 `peer-2.json` | `signWithServer()`, 목적 `normal_sign` |
| 기기 분실 복구 | R + S | R의 `peer-2.json` | `signWithServer()`, 목적 `recovery` |
| 지정 상속인 송금 | R + S | R의 `peer-2.json` | `signWithServer()`, 목적 `inheritance` |
| 서버 없이 비상 송금 | U + R | U의 `peer-3.json`, R의 `peer-1.json` | `signOffline()`. 티켓 없이 실행 |

기기에서 열 조각마다 **파일 세 개**를 준비합니다. `secrets.cvparty`는 암호화된 서명 조각과 보조 정보, `<공동공개키>-party-N.key`는 이를 여는 32바이트 AES 키, `peer-N.json`은 상대 참여자와 공동 공개키를 확인하는 신원 파일입니다. S 파일과 S의 AES 키는 인증 서버에 둡니다.

## 2. 네 송금 경로의 연동 순서

1. **거래 준비.** 코디네이터가 위 표에 맞는 두 서명자를 지정해 경로별로 새 미서명 거래 `payment.json`을 만듭니다. 기존 지갑의 공동 공개키와 Testnet4 수신 주소를 사용합니다. [거래 준비 명령](bitcoin/README.md)
2. **사용자 확인.** 프론트가 파일을 문자열로 한 번 읽고 `await reviewPayment(packageJson)`으로 수신 주소·송금액·수수료를 표시합니다. 사용자가 확인한 거래 원문을 서명에 사용하고, S가 참여하는 경로에서는 생체인증에도 전달합니다. 공백이나 줄바꿈도 거래 해시에 포함됩니다. [프론트 호출 예제](bitcoin/browser/README.md)
3. **S가 참여하는 경로의 인증과 티켓 발급.** 인증 핸들러가 `GET /v1/signing/context`에서 읽은 공동 공개키·서버 실행 식별자, 거래 해시, 목적을 이번 인증 요청에 연결합니다. 일반 송금·복구는 소유자를, 상속은 지정 상속인과 상속 조건을 확인한 뒤 `buildSigningSessionRequest()`로 인증 결과에 서명하고 `POST /v1/signing/sessions`를 호출합니다. S가 반환한 `ticket`을 해당 사용자 세션에 전달합니다. 상속은 지정 상속인의 얼굴·등록 기록과 사망 증빙 또는 비활성 타임락 충족까지 확인합니다. [얼굴 캡처·인증 규격](%5Bfacial%20recognition%5D.md) · [티켓 발급 코드와 S 서버 설정](bitcoin/SIGNING_SERVER.md)
4. **서명.** 일반 송금은 U의 세 파일을, 복구·상속은 R의 세 파일을 거래 원문·목적·티켓과 함께 `signWithServer()`에 전달합니다. 앱과 같은 출처의 `POST /v1/signing/steps`를 S 서버로 프록시하면 래퍼가 입력별 3라운드와 서명 검증을 처리합니다. U+R 화면에서는 사용자 확인 후 두 조각의 파일을 `signOffline()`에 전달합니다.
5. **전송과 결과 표시.** 반환된 `signed.txid`는 로컬에서 계산한 거래번호입니다. 사용자가 송금을 실행하면 앱이 `signed.raw_tx_hex` 원문을 Testnet4 API의 `POST /tx`에 `text/plain`으로 제출합니다. 응답의 거래번호가 `signed.txid`와 일치하면 전송 접수를 표시하고, 블록 포함 여부는 해당 거래번호로 조회합니다.

## 3. 담당별 준비 상태

| 담당 | 바로 사용할 수 있는 부분 | 앱에 연결할 부분 |
|---|---|---|
| 프론트 | 거래 검토, 브라우저 키 파일 열기, U+S·R+S·U+R 서명 및 검증 | 송금 확인 화면, 파일 선택, 인증 티켓 수신, 라운드 프록시, 전송·상태 표시 |
| 생체인증 | 브라우저 얼굴 캡처·라이브니스 모듈, 서버용 `biometrics/server/signing-session.mjs` | 얼굴 등록·서버 측 대조, 사용자 세션의 일회성 챌린지, 지정 상속인·상속 조건 조회 |
| S 서버 | `threshold-runner serve`, 거래별 티켓 발급 및 라운드 API | S 지갑과 AES 키 배치, 인증 결과 검증용 Ed25519 공개키 설정, 프론트 프록시와 연결 |

## 4. 실제 지갑을 연결하기 전 검증

레포 루트에서 아래 명령을 실행합니다. 서버·테스트용 Rust stable과 네이티브 C 컴파일러, Node.js 20 이상, Python 3이 필요합니다. 브라우저는 레포에 있는 WASM을 사용합니다. 테스트가 임시 지갑과 S 서버를 준비하므로 팀 지갑의 키 파일이나 faucet 잔액을 사용할 필요가 없습니다.

```sh
cd bitcoin
cargo build --release --locked --features threshold-runner --examples
python3 tests/browser_signing_smoke.py
```

터미널에 출력된 localhost 주소를 브라우저에서 엽니다. `normal_sign verified`, `recovery verified`, `inheritance verified`, `offline verified`가 모두 표시되면 네 경로의 로컬 서명 테스트를 통과한 것입니다. 이 테스트는 모의 인증 결과와 합성 거래를 사용합니다. 연동한 앱에서 아래 실송금 테스트까지 진행합니다.

## 5. 연동 완료 기준 · Testnet4 실송금 4건

아래 네 경로에서 각각 새 거래를 서명해 Testnet4에 전송합니다. 각 거래가 Testnet4 탐색기에서 조회되면 경로명과 TXID를 팀에 공유합니다.

| 경로 | 실제 앱에서 확인할 조건 |
|---|---|
| 일반 송금 | 소유자가 얼굴 인증을 마친 뒤 U+S로 송금 |
| 기기 분실 복구 | U 없이 소유자가 얼굴 인증을 마친 뒤 R+S로 새 지갑에 송금 |
| 상속 송금 | 지정 상속인의 얼굴·등록 기록과 상속 조건을 확인한 뒤 R+S로 상속인 지갑에 송금 |
| 비상 송금 | 테스트용 S 서버를 종료한 상태에서 U+R로 서명하고 Testnet4에 전송 |

## 프로토콜 출처

임계 ECDSA 구현은 [CGGMP20 논문](https://eprint.iacr.org/2021/060.pdf)과 [원본 tss-ecdsa 구현](https://github.com/boltlabs-inc/tss-ecdsa)을 기반으로 합니다.
