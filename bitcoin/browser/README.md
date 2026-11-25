# Chronos Vault 브라우저 서명 래퍼

프론트는 거래를 확인한 뒤 `signWithServer()` 또는 `signOffline()`을 호출합니다. 반환값의 `raw_tx_hex`는 공동 공개키로 검증한 Testnet4 거래입니다. 브로드캐스트는 호출하는 앱에서 처리합니다.

처음 연동하는 팀원은 레포 최상위의 `README.md`에서 담당별 작업과 인증 흐름을 확인하세요. 이 문서의 예제는 브라우저 화면에 넣는 코드입니다.

## 정적 파일 배치

팀 레포를 pull한 뒤 루트에서 아래 명령을 실행합니다. `APP_PUBLIC`을 프론트 앱의 정적 폴더 경로로 바꾸세요. Vite 프로젝트라면 해당 앱의 `public/`입니다.

```sh
APP_PUBLIC=/path/to/frontend/public
mkdir -p "$APP_PUBLIC/browser-signer"
cp bitcoin/browser/signer.js bitcoin/browser/signer-worker.js \
   bitcoin/browser/chronos_signer.wasm bitcoin/browser/signer.d.ts \
   "$APP_PUBLIC/browser-signer/"
```

브라우저는 HTTPS 또는 localhost에서 열고, 정적 파일은 앱과 같은 출처에서 제공합니다. 앱에 CSP가 있다면 해당 출처의 모듈 Worker와 WebAssembly 컴파일을 허용해야 합니다.

서명 엔진을 수정해 WASM을 갱신할 때는 레포의 `bitcoin/`에서 다음을 실행합니다. wasm32 타깃을 지원하는 Clang과 llvm-ar가 필요합니다. macOS에서 Homebrew LLVM을 사용하면 스크립트가 경로를 설정합니다.

```sh
rustup target add wasm32-unknown-unknown
./browser/build.sh
# 갱신된 bitcoin/browser/chronos_signer.wasm을 소스 변경과 함께 커밋합니다.
```

## 입력 파일

각 파일은 사용자가 기기에서 선택한 브라우저 `File` 객체입니다. 키 파일을 업로드하는 API는 필요하지 않습니다. 비상 조각을 별도 보관한 사용자는 해당 카드나 파일을 기기에 연결합니다.

| 경로 | 로컬 참여자가 여는 파일 |
|---|---|
| 일반 송금 U+S | U의 `secrets.cvparty`, `<공동공개키>-party-1.key`, U 폴더의 `peer-2.json` |
| 복구·상속 R+S | R의 `secrets.cvparty`, `<공동공개키>-party-3.key`, R 폴더의 `peer-2.json` |
| 서버 없이 U+R | U의 암호화 파일·AES 키·`peer-3.json`, R의 암호화 파일·AES 키·`peer-1.json` |

래퍼는 네이티브 지갑의 암호화 형식 `CVPART v1`을 읽습니다. AES 키는 바이너리 32바이트 파일입니다. 각 참여자의 암호화 파일과 신원 파일은 같은 지갑에서 생성한 것을 사용합니다.

## 일반 송금, 복구, 상속

아래 예제의 `showPaymentForConfirmation`과 `authenticateTransaction`은 앱의 화면과 인증 핸들러입니다. 서명 서버와 인증 핸들러의 요청·응답은 레포의 `bitcoin/SIGNING_SERVER.md`에 있습니다.

```js
const signerUrl = '/browser-signer/signer.js';
const { reviewPayment, signWithServer } = await import(/* @vite-ignore */ signerUrl);

const packageJson = await paymentFile.text();
const purpose = 'normal_sign';  // 복구: 'recovery', 상속: 'inheritance'
const review = await reviewPayment(packageJson);
await showPaymentForConfirmation(review); // 수신 주소, 금액, 수수료 확인. 취소 시 중단
const { ticket } = await authenticateTransaction({ packageJson, purpose });

const signed = await signWithServer({
  packageJson, purpose, ticket,
  files: {
    envelope: envelopeInput.files[0],
    aesKey: keyInput.files[0],
    identity: peerIdentityInput.files[0],
  },
});
console.log(signed.txid);
```

서명 라운드는 기본적으로 같은 출처의 `POST /v1/signing/steps`를 사용합니다. 프론트 서버에서 이 경로를 S 서버로 프록시하세요. 프록시 경로가 다르면 `stepsUrl: '/api/vault/signing/steps'`를 넘깁니다. 인증 때 사용한 `packageJson` 원문을 그대로 전달합니다. 반환값에는 `txid`, `raw_tx_hex`, `sent_sat`, `fee_sat`, `change_sat`, `vsize`가 있습니다.

개발 중 프론트가 Vite이고 S가 같은 컴퓨터의 8787 포트에서 실행될 때는 기존 Vite 설정의 `server.proxy`에 아래 항목을 추가합니다. 배포 환경에서도 같은 경로와 `Authorization` 헤더를 S까지 전달합니다.

```js
// vite.config.js
import { defineConfig } from 'vite';

export default defineConfig({
  server: { proxy: { '/v1/signing/steps': 'http://127.0.0.1:8787' } },
});
```

## S가 없는 비상 송금

```js
const signerUrl = '/browser-signer/signer.js';
const { reviewPayment, signOffline } = await import(/* @vite-ignore */ signerUrl);

await showPaymentForConfirmation(await reviewPayment(packageJson));
const signed = await signOffline({
  packageJson,  // 서명자 ID 1, 3으로 준비한 거래
  userFiles: { envelope: uEnvelope, aesKey: uKey, identity: uPeer3 },
  recoveryFiles: { envelope: rEnvelope, aesKey: rKey, identity: rPeer1 },
});
```

U와 R을 현재 기기에서 열고 Worker 안의 별도 WASM 인스턴스끼리 라운드를 교환합니다. 앱 정적 파일을 읽을 수 있으면 S 서버·티켓 없이 서명합니다.

## 취소와 재시도

두 서명 함수는 `signal: abortController.signal`을 받습니다. 취소하면 Worker가 종료됩니다. HTTP 응답 유실이나 `429`에는 래퍼가 같은 라운드만 재전송합니다. 탭을 닫거나 중단한 세션을 처음부터 다시 진행하려면 새 인증 티켓을 발급받으세요. IndexedDB에 세션 ID와 사용한 nonce를 기록할 수 있어야 서명이 완료됩니다.

## 브라우저 통합 테스트

`bitcoin/`에서 실행합니다. 테스트는 `browser/`의 WASM과 JS를 직접 사용합니다. S 서버를 빌드할 Rust와 네이티브 C 컴파일러, Python 3, Node.js 20 이상이 필요합니다.

```sh
cargo build --release --locked --features threshold-runner --examples
python3 tests/browser_signing_smoke.py
```

출력한 localhost URL을 브라우저로 열면 임시 지갑·합성 거래·모의 인증 결과로 일반 송금, 다중 입력 복구, 상속, U+R 비상 송금을 검증합니다. 잘못된 AES 키 거부와 라운드 응답 유실 후 재시도도 시험합니다. 마지막 U+R 서명 전에는 S 프로세스를 종료합니다.
