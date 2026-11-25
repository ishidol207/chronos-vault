# Bitcoin Testnet4 서명 서버 연동

이 서버는 Chronos Vault의 2번 참여자 S입니다. 신청자 기기가 U 또는 R 키를 열면 두 참여자가 거래 입력마다 HTTP로 사전서명 3라운드를 수행합니다. 그 결과로 각자 부분서명하고 기기에서 둘을 결합해 공동 공개키로 검증합니다. 브라우저 래퍼는 서명된 거래 객체를 반환하고 네이티브 CLI는 같은 형식의 JSON을 표준 출력에 씁니다. 전체 앱 연동 순서는 [팀원 연동 가이드](../README.md)에 있습니다.

| 사용 목적 | 승인할 `purpose` | 클라이언트 | 서버가 승인하기 전 확인할 조건 |
|---|---|---|---|
| 일반 송금 | `normal_sign` | U (1) | 소유자 인증 및 거래 확인 |
| 기기 분실 복구 | `recovery` | R (3) | 소유자 복구 인증 및 거래 확인 |
| 상속 | `inheritance` | R (3) | 지정 상속인 인증, 상속 조건, 거래 확인 |
| 서버 장애 시 비상 송금 | 해당 없음 | U와 R | 소유자 기기의 U와 비상 백업 R로 로컬 서명. S 서버·티켓 없이 진행 |

## 1. 준비

S 서버 또는 네이티브 CLI를 사용할 컴퓨터에서 레포의 `bitcoin/` 디렉터리를 기준으로 빌드합니다. 브라우저 기기는 배포용 래퍼를 사용합니다.

```sh
cargo build --release --locked --features threshold-runner --examples
RUN=./target/release/examples/threshold-runner
BTC=./target/release/examples/testnet4
```

기존 지갑의 **같은 공동 공개키**로 생성한 파일을 역할별로 배치합니다.

| 위치 | 지갑 디렉터리 | AES 키 디렉터리 |
|---|---|---|
| S 인증 서버 | `wallet-s/{public-key.json,party-store.version,party-2/}` | S 전용 `<공동공개키>-party-2.key` |
| U 기기 | `wallet-u/{public-key.json,party-store.version,party-1/}` | U 전용 `<공동공개키>-party-1.key` |
| R 파일을 여는 기기 | `wallet-r/{public-key.json,party-store.version,party-3/}` | R 전용 `<공동공개키>-party-3.key` |

각 `party-N/`에는 해당 `secrets.cvparty`와 키 생성 시 저장한 `peer-*.json`이 들어갑니다. 사용 이력이 있는 참여자를 옮길 때는 그 참여자의 `spent-nonces/`와 기존 `sessions/` 이력을 보존합니다. 각 장치는 자기 지갑의 `sessions/`와 `party-N/spent-nonces/`에 쓸 수 있어야 합니다. 기존 지갑을 사용한다면 새로 `keygen`할 필요가 없습니다.

## 2. S 서버 시작

S는 Chronos Vault 인증 서버가 보관하는 지갑별 2번 서명 조각입니다. 생체인증 핸들러와 S 서명 프로세스는 같은 서버에 둘 수 있습니다. 인증 핸들러는 확인한 사실에 서명하고 S는 해당 지갑의 역할·거래 조건을 검사해 세션을 엽니다.

서버 구성 시 인증 결과 서명용 Ed25519 키 쌍을 한 번 준비합니다. 이 키는 지갑의 ECDSA 키와 별개입니다. 아래 명령은 인증 핸들러의 비공개 설정 디렉터리에서 실행합니다.

```sh
node --input-type=module <<'JS'
import { generateKeyPairSync } from 'node:crypto';
import { writeFileSync } from 'node:fs';
const { privateKey, publicKey } = generateKeyPairSync('ed25519');
writeFileSync('auth-verifier.pem', privateKey.export({format:'pem',type:'pkcs8'}), {mode:0o600,flag:'wx'});
console.log(Buffer.from(publicKey.export({format:'jwk'}).x, 'base64url').toString('hex'));
JS
```

인증 핸들러가 개인키를 보관하고, S 서명 프로세스에는 출력된 공개키만 설정합니다.

```sh
export CHRONOS_PARTY_2_KEY_DIR="$PWD/keys-s"
export CHRONOS_AUTH_PUBLIC_KEY='<위에서 출력한 Ed25519 공개키 hex>'
"$RUN" serve ./wallet-s --listen 127.0.0.1:8787
```

다른 터미널에서 `curl -fsS http://127.0.0.1:8787/health`가 `ok`를 반환하면 S 지갑을 열고 요청을 받을 준비가 끝난 것입니다. 별도 기기에서 접근할 때는 HTTPS 리버스 프록시를 사용합니다.

## 3. 거래 확인 → 생체인증 → 서명

1. 기존 `testnet4 prepare`로 `payment.json`을 생성합니다. 일반 송금은 `--party-a 1 --party-b 2`, 복구·상속은 `--party-a 3 --party-b 2`입니다. 사용자가 `testnet4 review`에 해당하는 수신 주소·금액·수수료를 확인합니다.
2. 인증 핸들러는 인증을 시작할 때 `GET /v1/signing/context`로 S의 실행 식별자와 공동 공개키를 읽습니다. 등록된 지갑, 거래 원문 해시, 목적을 사용자 세션의 1회성 생체인증 챌린지와 연결합니다. 검증된 등록 기록에서 역할을 결정하고, 상속은 지정 상속인과 사망 증빙 또는 비활성 조건 충족을 확인합니다.
3. 인증 핸들러가 그 결과로 아래 요청을 만들어 S에 전달합니다. S가 발급한 거래 전용 티켓만 신청자 기기에 반환합니다. 동일한 인증서 재전송은 유효기간 안에 같은 세션을 반환합니다.

아래 코드는 앱에서 구현할 인증 핸들러의 **서버 측** 연결 예입니다. `biometrics/server/signing-session.mjs`는 거래 해시를 대조하고 인증 결과에 서명하는 헬퍼입니다. 생체 챌린지 발급·검증, DB 대조와 상속 조건 조회는 이 헬퍼를 호출하기 전에 핸들러에서 수행합니다. `verification`은 해당 챌린지를 검증한 서버 측 기록입니다. 브라우저가 보내는 `role`, `verified`, 상속 사유를 이 기록에 그대로 대입하면 안 됩니다.

```js
import { buildSigningSessionRequest } from '../biometrics/server/signing-session.mjs';

const body = buildSigningSessionRequest(paymentJson, verification, authPrivateKey);
const response = await fetch(signerUrl + '/v1/signing/sessions', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(body),
});
if (!response.ok) throw new Error('S 서명 세션 발급 실패');
const { ticket } = await response.json();
```

| `verification` 필드 | 핸들러가 확인한 값 |
|---|---|
| `instanceId`, `publicKey` | 챌린지에 저장한 S 실행 식별자와 등록 지갑의 압축 공동 공개키 |
| `packageSha256`, `purpose` | 사용자가 확인한 거래 원문 해시와 `normal_sign` / `recovery` / `inheritance` |
| `role`, `faceVerified` | 등록된 소유자 `owner` 또는 지정 상속인 `heir`, 서버 측 본인 인증 통과 여부 |
| `inheritanceEvidence` | 일반·복구는 `null`. 상속은 확인된 `death_verified` 또는 `inactivity_elapsed` |
| `expiresAt` | 인증 결과 만료 시각(Unix 초). 발급 시점부터 최대 120초 |

네이티브 U 기기 실행 예입니다. `ticket.txt`는 인증 핸들러가 이 거래에 발급받은 티켓 문자열만 담습니다.

```sh
export CHRONOS_PARTY_1_KEY_DIR="$PWD/keys-u"
SERVER_URL=http://127.0.0.1:8787
"$RUN" remote-sign ./wallet-u payment.json --server "$SERVER_URL" \
  --purpose normal_sign < ticket.txt > signed.json
```

R 기기에서는 `CHRONOS_PARTY_3_KEY_DIR`와 `wallet-r`를 사용하고 목적에 `recovery` 또는 `inheritance`를 지정합니다. 출력의 `txid`와 `raw_tx_hex`는 서명 검증을 마친 거래입니다. U+R은 S가 종료된 상태에서도 서명할 수 있습니다. [브라우저 예제](browser/README.md) · [네이티브 CLI 예제](README.md)

## 4. HTTP 계약

| 메서드와 경로 | 요청 | 응답 |
|---|---|---|
| `GET /health` | 없음 | `ok` |
| `GET /v1/signing/context` | 없음 | `instance_id`, `public_key` |
| `POST /v1/signing/sessions` | `package_json`, `authorization`(JSON 문자열), `signature`(그 문자열의 UTF-8 바이트에 대한 Ed25519 서명 hex) | `ticket`, `expires_in_seconds` (새 세션은 600초) |
| `POST /v1/signing/steps` | 거래 티켓을 Bearer로 전달. 최초 `{"step":0,"messages":[]}`, 이후 `{"step":1,"messages":["…","…"]}` 등 | `step`, `purpose`, `package_sha256`, `session_ids`, `packet` |

`package_sha256`는 `package_json` 원문 UTF-8 바이트의 SHA-256 hex입니다. 승인 후 JSON을 다시 직렬화하면 공백·개행까지 달라질 수 있으므로 동일한 원문을 사용합니다. 라운드 메시지는 **각각 JSON 문자열**로 전달합니다. 세션 ID는 64비트 정수의 십진 문자열입니다. JS에서 메시지 내부나 세션 ID를 `Number`로 변환하면 정밀도를 잃을 수 있습니다.

입력이 하나인 거래의 교환 예시입니다. 클라이언트는 서버와 동시에 같은 라운드를 계산하므로 **자기 쪽에서 직전에 만든 메시지**를 전송합니다.

| step | 클라이언트 → 서버 | 서버 → 클라이언트 |
|---:|---|---|
| 0 | 빈 배열 | 세션 ID 목록과 S의 1라운드 메시지 |
| 1 | U 또는 R의 1라운드 메시지 | S의 2라운드 메시지 |
| 2 | U 또는 R의 2라운드 메시지 | S의 3라운드 메시지 |
| 3 | U 또는 R의 3라운드 메시지 | 승인된 거래에 대한 S의 부분서명 |

진행 중인 응답은 `packet.messages`, 마지막 응답은 `packet.share`에 있습니다. 입력이 여러 개면 입력별 세션 ID로 3라운드씩 수행하며, 이전 입력의 3라운드 응답에 다음 입력의 첫 메시지가 옵니다. S의 장기 키와 사전서명 레코드는 서버에 남습니다.

- **응답 유실** 시 마지막 요청과 동일한 step·메시지를 보내면 같은 응답을 반환합니다. 완료된 마지막 응답도 티켓 만료까지 재조회할 수 있습니다.
- `401`은 자격 누락·오류·만료, `403`은 얼굴·역할·상속 조건 불충족, `409`는 순서 또는 재시도 내용 충돌, `422`는 승인 조건 불일치 또는 잘못된 라운드입니다. 라운드 계산 중 오류가 나면 세션을 종료합니다. `410`은 종료된 세션, `429`는 동시 처리 한도입니다.
- 서버 재시작·클라이언트 프로세스 종료로 진행 상태를 잃으면 새 티켓과 새 사전서명을 사용합니다. nonce 사용 이력은 디스크에 남습니다.
- 브라우저에서는 [브라우저 서명 래퍼](browser/README.md)의 `signWithServer()`로 U+S·R+S를, `signOffline()`으로 U+R을 실행합니다.

## 5. 독립 실행 검증

```sh
# bitcoin/에서 release 예제를 빌드한 뒤 실행 (Python 3 및 Node.js 20+)
python3 tests/signing_server_smoke.py
```

테스트는 새 임시 키를 생성하고 U·S·R의 키 및 지갑을 서로 다른 디렉터리에 배치합니다. 로컬 HTTP 서버를 실제로 띄워 일반 송금, 다중 입력 복구, 상속을 검증하고 인증·라운드 순서 오류도 확인합니다. 이어 서버를 종료하고 S가 없는 지갑에서 U+R 서명을 검증합니다. 생체인증 판정에는 테스트용 서명된 결과를 사용합니다. 테스트 입력은 합성이며 브로드캐스트는 수행하지 않습니다.
