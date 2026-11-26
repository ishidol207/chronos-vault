# Chronos Vault 일반 송금 화면

Bitcoin Testnet4 일반 송금(U+S)용 로컬 연동 앱입니다. 동작 중 얼굴 특징은 로컬 개발 서버의 메모리에만 등록되며 서버를 종료하면 삭제됩니다.

## Windows에서 실행

레포 루트에서 생체인증 의존성과 모델을 준비합니다.

```powershell
cd biometrics
npm.cmd ci
npm.cmd run fetch-models
cd ..
```

[`bitcoin/SIGNING_SERVER.md`](../bitcoin/SIGNING_SERVER.md)의 안내에 따라 S 서명 서버를 시작합니다. 기본 주소는 `http://127.0.0.1:8787`입니다. 다른 주소를 쓰면 프론트 실행 전에 `CHRONOS_SIGNER_URL`을 설정합니다.

별도 PowerShell에서 서명 서버와 일치하는 테스트 지갑의 공동 공개키 파일과 인증용 Ed25519 개인키 경로를 설정합니다.

```powershell
$env:CHRONOS_TEST_WALLET_PUBLIC_KEY_PATH = '<테스트 지갑의 public-key.json 절대 경로>'
$env:CHRONOS_AUTH_PRIVATE_KEY_PATH = '<인증용 Ed25519 PEM 절대 경로>'
node .\biometrics\node_modules\vite\bin\vite.js --config .\frontend-v2\vite.config.mjs --configLoader native
```

1. `http://127.0.0.1:5181/#send`에서 [`bitcoin/README.md`](../bitcoin/README.md)의 U+S 절차로 준비한 미서명 거래 파일을 불러옵니다.
2. 테스트 지갑 소유자 얼굴을 등록한 뒤 본인 인증을 진행합니다.
3. U의 `secrets.cvparty`, `*-party-1.key`, `peer-2.json`을 선택해 공동 서명합니다.
4. 수신 주소와 금액을 확인한 뒤 Testnet4에 전송하고 거래번호와 확인 상태를 조회합니다.

지갑 파일, 개인키, AES 키, 모델 바이너리 및 테스트 거래 파일은 별도로 준비합니다.
