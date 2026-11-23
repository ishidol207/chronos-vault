# Chronos Vault · Bitcoin Testnet4 임계서명

코디네이터가 송금 요청을 준비하고 두 참여자가 각자 서명 조각을 반환한다. 코디네이터는 각 입력의 조각 두 개를 합친 뒤 공동 공개키로 ECDSA 서명을 검증하고 P2WPKH witness를 완성한다. 입금 주소는 TShare 공동 공개키에서 직접 만든 Testnet4 주소다. 기존 BIP-84 데모 지갑에 입금한 코인은 기존 키로 새 주소에 송금해야 한다.

## 팀원이 테스트 지갑 만들기

레포를 클론한 뒤 `bitcoin/`에서 실행한다. 로컬 데모용 실행기는 한 컴퓨터에서 참여자 1·2·3을 별도 Rust 프로세스로 띄워 루트 크레이트의 `AuxInfo`와 2-of-3 `TShare` 라운드를 진행한다. 각 프로세스는 자기 장기 키 조각과 보조 정보를 자기 폴더에 저장한다. 같은 OS 계정이 세 폴더를 모두 읽을 수 있다.

```sh
cd bitcoin
cargo build --release --locked --features threshold-runner --examples
RUN=./target/release/examples/threshold-runner
BTC=./target/release/examples/testnet4
WALLET=./party-demo

MASTER_PK=$("$RUN" keygen "$WALLET")
printf '%s\n' "$MASTER_PK"
"$BTC" address "$MASTER_PK"
```

`keygen`은 새 디렉터리에만 지갑을 만들고, 세 참여자의 공개키가 일치하면 33바이트 압축 공개키를 hex로 출력한다. 팀원이 코디네이터에게 전달할 값은 이 **공개키와 Testnet4 입금 주소**다. `party-1/`부터 `party-3/`까지의 `aux.json`과 `share.json`은 다음 사전서명에 필요하므로 생성한 컴퓨터에 보관한다. 나중에 셸을 다시 열면 같은 지갑에서 `MASTER_PK=$(cat "$WALLET/public-key.json")`으로 공개키를 다시 읽을 수 있다. 지갑 루트의 `public-key.json`은 세 참여자가 모두 성공한 뒤에 생성된다. 키 생성이 중단되면 새 디렉터리로 다시 실행한다. 새 지갑의 주소로 faucet 입금을 받은 뒤 아래 절차를 진행한다.

## 송금

코디네이터에서 위 주소로 입금한 Testnet4 UTXO를 조회해 송금 요청을 만든다. 전액 송금은 `--amount-sat 5000` 자리에 `--sweep`을 쓴다.

```sh
"$BTC" prepare --public-key "$MASTER_PK" --party-a 1 --party-b 3 \
  --recipient "$RECIPIENT" --amount-sat 5000 > payment.json
"$BTC" review payment.json
```

`payment.json`에는 두 ID, 공동 공개키, 송금 조건, 미서명 트랜잭션 hex 및 선택한 UTXO의 원거래가 들어 있다. 각 참여자는 원거래의 txid·출력 인덱스·금액·잠금 스크립트를 확인하고 미서명 트랜잭션을 다시 구성한다. `review`가 표시하는 수신 주소, 송금액, 거스름돈, 수수료를 승인한 뒤 서명한다. `input_sighashes`의 길이가 각 참여자에게 필요한 사전서명 레코드 개수다. 각 서명 대상은 BIP143의 입력별 32바이트 `SIGHASH_ALL`이다.

| 실행 위치 | 입력 | 외부로 보내는 값 |
| --- | --- | --- |
| 코디네이터 | 공동 공개키, 수신 주소, 금액, UTXO | 같은 `payment.json`을 양쪽에 전달 |
| 참여자 1 | 승인한 요청, 로컬 신원, 자기 TPreSign 레코드 | `reply-1.json` |
| 참여자 3 | 승인한 요청, 로컬 신원, 자기 TPreSign 레코드 | `reply-3.json` |
| 코디네이터 | 원래 요청과 두 응답 | 검증한 raw transaction을 Testnet4에 제출 |

코디네이터가 팀원에게 `payment.json`을 보내면, 팀원은 같은 지갑에서 요청을 검토하고 사전서명을 실행한다. 실행기는 요청의 공동 공개키와 서명자 ID를 확인하고, 각 입력마다 새 세션으로 두 참여자의 `TPreSign`을 수행한다. 두 배치가 완성되면 그 디렉터리 경로를 출력한다.

```sh
# 지갑을 만든 컴퓨터에서 실행한다. 이 요청의 서명자는 1과 3이다.
"$BTC" review payment.json
BATCH=$("$RUN" presign "$WALLET" payment.json)
"$BTC" sign-share "$WALLET/party-1" "$BATCH/party-1.json" --peer-id 3 < payment.json > reply-1.json
"$BTC" sign-share "$WALLET/party-3" "$BATCH/party-3.json" --peer-id 1 < payment.json > reply-3.json
```

`--peer-id`는 키 생성 시 각 참여자가 저장한 상대별 신원 파일을 선택한다. 참여자별 nonce 사용 이력은 항상 같은 `party-N/spent-nonces/`에 기록된다. 다른 조합을 쓰려면 `prepare`에서 해당 두 ID를 지정하고 위 두 서명 명령의 ID도 맞춘다. `presign`을 다시 실행하면 새 배치가 만들어진다. 팀원은 두 `reply-*.json`만 코디네이터에게 보낸다.

```sh
# 코디네이터
"$BTC" combine payment.json reply-1.json reply-3.json
"$BTC" broadcast payment.json reply-1.json reply-3.json
"$BTC" status "$TXID"
```

별도 장치에서 이미 threshold ECDSA를 구동하는 경우에는 각 장치가 `get_master_pk`로 공동 공개키를 확인하고, 같은 입력 순서로 생성한 자기 `TPreSign` 출력 배열을 `batch.json`에 보관한다. 기존 방식대로 `testnet4 identity`로 `identity.json`을 만든 뒤 `sign-share`를 실행할 수 있다.

### 두 참여자를 호출해 바로 전송하기

`send`는 실행 가능한 어댑터 두 개에 같은 패키지를 표준 입력으로 보내고, 표준 출력에서 응답 JSON을 읽는다. 어댑터는 각 장치의 승인된 서명 서비스 또는 SSH 명령에 연결한다. 예를 들어 SSH를 쓰는 참여자 1의 어댑터는 아래 형태다. 참여자 3도 자기 호스트와 로컬 경로를 지정한다. 장치의 인증·승인 절차는 어댑터에서 처리한다.

```sh
#!/bin/sh
exec ssh -T party-one '/opt/chronos/testnet4 sign-share /vault/wallet /vault/wallet/batch.json'
```

```sh
"$BTC" send payment.json ./call-party-1 ./call-party-3 --dry-run
"$BTC" send payment.json ./call-party-1 ./call-party-3
```

`--dry-run`도 두 참여자의 레코드를 소비한다. 코디네이터는 검증에 쓸 응답을 패키지 옆의 `exchange-<해시>/`에 저장한다. 같은 요청으로 실제 전송하거나 전송 실패 후 재시도하면 저장한 응답을 재사용한다. 서명 도중 한쪽의 레코드를 소모한 상태에서 짝이 맞는 응답을 잃었다면, 두 참여자가 모두 새 TPreSign 세트를 준비하고 새 교환 디렉터리에서 시작한다.

### 일회성 레코드 보관

참여자의 CLI는 배치 파일을 인수한 뒤 각 nonce를 고정된 지갑 디렉터리의 `spent-nonces/`에 독점 등록한다. 등록이 끝나야 조각을 반환한다. 해당 배치 파일은 한 번의 시도에 사용한다. 지갑 디렉터리를 복제하거나 사용 이력을 과거 시점으로 복원하면 같은 레코드를 다시 쓸 수 있으므로, 백업 복구 시 남은 사전서명 레코드는 폐기하고 새로 생성한다.

## 브라우저

- 코디네이터에서 `walletAddress(masterKey)`, `prepareTransaction(masterKey, signersJson, requestJson)`을 호출한다. 요청의 `funding_transactions`는 txid를 키, 트랜잭션 hex를 값으로 하는 객체다. `prepareTransaction`은 두 참여자에게 그대로 전달할 JSON 문자열을 반환한다.
- 각 참여자의 브라우저에서 `reviewTransaction(packageJson)` 결과를 확인한 뒤 `await signShare(identityJson, packageJson, myRecordsJson)`을 호출한다. 반환값은 응답 JSON 문자열이다. 사용한 레코드는 앱의 비밀 저장소에서 폐기한다. nonce 사용 이력은 각 장치의 IndexedDB에 기록한다.
- 코디네이터에서 `combineTransaction(packageJson, replyAJson, replyBJson)` 결과의 `raw_tx_hex`를 Testnet4 API의 `POST /tx` 본문으로 보낸다. 패키지와 응답 문자열을 그대로 전달하면 64비트 참여자 ID의 정밀도가 보존된다.

## 빌드와 검증

```sh
cargo test --locked --all-targets
rustup target add wasm32-unknown-unknown
cargo build --release --locked --target wasm32-unknown-unknown --lib
```

macOS의 기본 Clang에 wasm32 타깃이 없으면 Homebrew LLVM의 `clang`과 `llvm-ar`를 각각 `CC_wasm32_unknown_unknown`, `AR_wasm32_unknown_unknown`으로 설정한다. 브라우저 JS 바인딩은 `wasm-pack build --release --target web`으로 생성한다.

[Bitcoin BIP143](https://bips.dev/143/) · [mempool.space Testnet4 API](https://mempool.space/testnet4/docs/api/rest)
