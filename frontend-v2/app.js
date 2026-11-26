const app = document.querySelector('#app');
const sample = {
  recipient: 'tb1q402dy0…uq69h6',
  amount: 120000,
  fee: 420,
  txid: 'DEMO-TX-001'
};
const titles = { wallet: '메인 지갑', send: '일반 송금', history: '거래 내역' };
let stage = 'empty';
let faceSession;
let signingSession;
let payment;

function btc(satoshis) {
  return `${(satoshis / 100_000_000).toFixed(8)} BTC`;
}

function showStep(index, title, message, buttons) {
  [...app.querySelectorAll('.progress li')].forEach((item, position) => {
    item.classList.toggle('done', position < index);
    if (position === index) item.setAttribute('aria-current', 'step');
    else item.removeAttribute('aria-current');
  });
  const step = app.querySelector('#step');
  const heading = document.createElement('h2');
  heading.tabIndex = -1;
  heading.textContent = title;
  const description = document.createElement('p');
  description.textContent = message;
  description.setAttribute('role', 'status');
  const controls = document.createElement('div');
  controls.className = 'controls';
  buttons.forEach(([label, next, secondary]) => {
    if (payment && next === 'auth') return;
    if (!payment && next === 'enroll') return;
    const button = document.createElement('button');
    button.type = 'button';
    button.textContent = label;
    if (secondary) button.className = 'secondary';
    button.addEventListener('click', () => transition(next));
    controls.append(button);
  });
  if (stage === 'empty' || stage === 'review') {
    const label = document.createElement('label');
    label.className = 'payment-picker';
    label.textContent = payment ? '다른 거래 파일 선택' : '거래 파일 선택 (payment.json)';
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = '.json,application/json';
    input.addEventListener('change', () => void loadPayment(input, description, controls));
    label.append(input);
    controls.prepend(label);
    if (payment) {
      const selectedFile = document.createElement('p');
      selectedFile.className = 'selected-payment';
      selectedFile.textContent = `불러온 파일: ${payment.filename}`;
      controls.prepend(selectedFile);
      const challengeButton = document.createElement('button');
      challengeButton.type = 'button';
      challengeButton.className = 'secondary';
      challengeButton.textContent = '인증 연결 확인';
      challengeButton.addEventListener('click', async () => {
        const packageJson = payment.packageJson;
        challengeButton.disabled = true;
        description.textContent = '인증 서버 연결을 확인하고 있습니다.';
        try {
          const response = await fetch('/api/vault/face/challenge', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ packageJson })
          });
          const result = await response.json();
          if (!response.ok || !result.challengeNonce) {
            throw new Error(result.error || '인증 번호를 받지 못했습니다.');
          }
          description.textContent = '인증 번호를 받았습니다. 얼굴 대조는 다음 연동 단계입니다.';
        } catch (error) {
          description.textContent = `인증 연결 실패: ${error.message}`;
        } finally {
          challengeButton.disabled = false;
        }
      });
      controls.append(challengeButton);
    }
  }
  const stepHeading = step.querySelector('#step-heading');
  stepHeading.classList.toggle('result', index === 3);
  stepHeading.replaceChildren(heading, description);
  if (index === 3) {
    const total = document.createElement('strong');
    total.className = 'result-amount';
    total.textContent = btc(payment?.review.sent_sat ?? sample.amount);
    stepHeading.prepend(total);
    const close = document.createElement('a');
    close.className = 'secondary close-result';
    close.href = '#wallet';
    close.textContent = '닫기';
    controls.append(close);
  }
  step.querySelector('#step-controls').replaceChildren(controls);
  if (stage === 'ticket') controls.prepend(createSigningForm(description));
  if (['real-signed', 'real-pending', 'real-confirmed'].includes(stage)) {
    const txid = document.createElement('code');
    txid.className = 'signed-txid';
    txid.textContent = payment.signed.txid;
    stepHeading.append(txid);
    controls.prepend(createBroadcastControls(description));
  }
  return heading;
}

function createBroadcastControls(status) {
  const controls = document.createElement('div');
  controls.className = 'broadcast-controls';
  const current = payment;
  if (stage === 'real-signed' && ['payment.demo.json', 'payment.local-demo.json'].includes(current.filename)) {
    const notice = document.createElement('p');
    notice.textContent = '예시 거래입니다. 전송하려면 Testnet4 잔액으로 만든 거래 파일이 필요합니다.';
    controls.append(notice);
    return controls;
  }
  const button = document.createElement('button');
  button.type = 'button';
  const sending = stage === 'real-signed';
  button.textContent = sending ? 'Testnet4에 전송' : '거래 상태 새로고침';
  button.addEventListener('click', async () => {
    if (current.broadcastBusy) return;
    current.broadcastBusy = true;
    button.disabled = true;
    status.textContent = sending ? 'Testnet4에 거래를 전송 중입니다.' : '블록 확인 상태를 조회 중입니다.';
    try {
      const { broadcastTransaction, transactionConfirmed } = await import('./testnet.js');
      if (sending) {
        await broadcastTransaction(current.signed);
        current.chainStage = 'real-pending';
      } else {
        current.chainStage = await transactionConfirmed(current.signed.txid) ? 'real-confirmed' : 'real-pending';
      }
    } catch (error) {
      status.textContent = `Testnet4 요청 실패: ${error.message} 거래번호로 탐색기에서 상태를 확인할 수 있습니다.`;
      return;
    } finally {
      current.broadcastBusy = false;
      button.disabled = false;
      if (payment === current && !status.isConnected && location.hash === '#send') {
        const activeButton = app.querySelector('.broadcast-controls button');
        if (activeButton) activeButton.disabled = false;
      }
    }
    if (payment === current && location.hash === '#send' &&
        ['real-signed', 'real-pending', 'real-confirmed'].includes(stage)) transition(current.chainStage);
  });
  button.disabled = Boolean(current.broadcastBusy);
  const explorer = document.createElement('a');
  explorer.className = 'close-result';
  explorer.href = `https://mempool.space/testnet4/tx/${current.signed.txid}`;
  explorer.target = '_blank';
  explorer.rel = 'noopener noreferrer';
  explorer.textContent = 'Testnet4 탐색기에서 보기';
  controls.append(button, explorer);
  return controls;
}

function createSigningForm(status) {
  const form = document.createElement('form');
  form.className = 'signing-files';
  const entries = [
    ['envelope', 'U의 secrets.cvparty', '.cvparty'],
    ['aesKey', 'U의 party-1.key', '.key'],
    ['identity', 'U의 peer-2.json', '.json']
  ];
  const inputs = entries.map(([name, title, accept]) => {
    const label = document.createElement('label');
    label.textContent = title;
    const input = document.createElement('input');
    input.name = name;
    input.type = 'file';
    input.accept = accept;
    input.required = true;
    label.append(input);
    form.append(label);
    return input;
  });
  const button = document.createElement('button');
  button.textContent = 'U + S 공동 서명';
  button.type = 'submit';
  form.append(button);
  form.addEventListener('submit', async event => {
    event.preventDefault();
    if (signingSession || inputs.some(input => !input.files[0])) return;
    const current = payment;
    const ticket = current.ticket;
    if (!ticket) {
      status.textContent = '새 티켓이 필요합니다. 거래 확인 화면으로 돌아가 다시 인증해 주세요.';
      return;
    }
    const files = Object.fromEntries(inputs.map(input => [input.name, input.files[0]]));
    const controller = new AbortController();
    signingSession = controller;
    delete current.ticket;
    for (const input of inputs) input.disabled = true;
    button.disabled = true;
    status.textContent = '사용자 기기와 서버가 공동 서명하고 있습니다.';
    try {
      const signerUrl = '/browser-signer/signer.js';
      const { signWithServer } = await import(/* @vite-ignore */ signerUrl);
      const signed = await signWithServer({
        packageJson: current.packageJson,
        purpose: 'normal_sign',
        ticket,
        files,
        signal: controller.signal
      });
      if (controller.signal.aborted) return;
      current.signed = signed;
      transition('real-signed');
    } catch (error) {
      if (!controller.signal.aborted) {
        status.textContent = `공동 서명 실패: ${error.message} 거래 확인 화면으로 돌아가 다시 인증해 주세요.`;
      }
    } finally {
      form.reset();
      if (signingSession === controller) signingSession = undefined;
    }
  });
  return form;
}

const steps = {
  empty: [0, '거래 선택', '거래 파일을 선택하거나 예시 거래를 불러오세요.', [['예시 거래 불러오기', 'review', true]]],
  review: [0, '송금 정보 확인', '수령 주소, 송금액, 수수료가 맞으면 얼굴 인증을 시작하세요.', [['얼굴 인증 시작', 'camera'], ['테스트 소유자 얼굴 등록', 'enroll', true], ['모의 흐름 보기', 'auth', true]]],
  camera: [1, '카메라로 얼굴 확인', '카메라를 준비하고 있습니다.', [['취소', 'review', true]]],
  enroll: [1, '테스트 소유자 얼굴 등록', '얼굴 특징을 로컬 서버 메모리에만 등록합니다. 카메라를 준비하고 있습니다.', [['취소', 'review', true]]],
  enrolled: [1, '테스트 얼굴 등록 완료', '등록 정보는 로컬 개발 서버를 종료하면 지워집니다.', [['거래 확인으로 돌아가기', 'review']]],
  ticket: [2, '본인 확인 및 티켓 수신 완료', '사용자 기기(U)의 파일 세 개를 선택하세요. 파일은 브라우저에서 열립니다.', [['거래 확인으로 돌아가기', 'review', true]]],
  'real-signed': [2, '공동 서명 검증 완료', '거래에 서명했습니다. 이 거래는 블록체인에 전송되지 않았습니다.', [['거래 확인으로 돌아가기', 'review', true]]],
  'real-pending': [3, 'Testnet4 전송 접수', '블록 확인을 기다리는 중입니다.', [['새 거래 선택', 'empty', true]]],
  'real-confirmed': [3, 'Testnet4 블록 확인 완료', '거래가 블록에 포함되었습니다.', [['새 거래 선택', 'empty', true]]],
  captured: [1, '라이브니스 검사 완료', '브라우저에서 얼굴을 캡처했습니다. 본인 확인과 공동 서명에는 서버 연동이 필요합니다.', [['거래 확인으로 돌아가기', 'review', true]]],
  auth: [1, '모의 얼굴 인증', '모의 인증 결과를 선택해 다음 단계를 확인하세요.', [['모의 인증 성공', 'signing'], ['모의 인증 실패', 'failed', true]]],
  failed: [1, '얼굴 인증 실패', '공동 서명을 진행하려면 다시 인증해 주세요.', [['다시 인증하기', 'auth']]],
  signing: [2, '공동 서명 대기', '사용자 기기(U)와 인증 서버(S)의 서명 과정을 모의 실행합니다.', [['공동 서명 실행', 'signed']]],
  signed: [2, '공동 서명 검증 완료', '거래 정보를 다시 확인한 후 모의 송금을 실행하세요.', [['모의 송금하기', 'pending']]],
  pending: [3, '거래 전송 접수', `블록 확인 대기 · ${sample.txid}`, [['블록 확인 시뮬레이션', 'confirmed']]],
  confirmed: [3, '블록 확인 완료', `모의 거래번호 · ${sample.txid}`, [['새 예시 거래 시작', 'empty', true]]]
};
const history = [];

function transition(next) {
  faceSession?.abort();
  signingSession?.abort();
  if (next === 'empty') payment = undefined;
  stage = next;
  if (next === 'pending') history.unshift({ txid: `DEMO-TX-${String(history.length + 1).padStart(3, '0')}`, confirmed: false });
  if (next === 'confirmed') history[0].confirmed = true;
  renderSend().focus();
  if (next === 'camera' || next === 'enroll') void startFaceCapture(next);
}

async function loadPayment(input, status, controls) {
  const file = input.files[0];
  if (!file) return;
  if (location.protocol === 'file:') {
    status.textContent = '거래 파일을 검토하려면 로컬 개발 서버에서 열어 주세요.';
    input.value = '';
    return;
  }
  const inputs = [...controls.querySelectorAll('button, input')];
  inputs.forEach(control => { control.disabled = true; });
  status.textContent = '거래 파일을 검토하고 있습니다.';
  try {
    const packageJson = await file.text();
    const signerUrl = '/browser-signer/signer.js';
    const { reviewPayment } = await import(/* @vite-ignore */ signerUrl);
    const review = await reviewPayment(packageJson);
    const { signers } = JSON.parse(packageJson);
    if (!Array.isArray(signers) || signers.length !== 2 ||
        !signers.includes(1) || !signers.includes(2)) {
      throw new Error('일반 송금은 U(1)와 S(2)의 거래 파일이 필요합니다.');
    }
    if (!input.isConnected) return;
    payment = { packageJson, review, filename: file.name };
    transition('review');
  } catch (error) {
    if (!input.isConnected) return;
    payment = undefined;
    stage = 'empty';
    renderSend().focus();
    app.querySelector('#step-heading [role="status"]').textContent =
      `거래 파일을 열 수 없습니다. (${error.message})`;
  } finally {
    inputs.forEach(control => { control.disabled = false; });
    input.value = '';
  }
}

async function startFaceCapture(mode) {
  const controller = new AbortController();
  faceSession = controller;
  const container = app.querySelector('#step');
  const status = container.querySelector('[role="status"]');
  if (location.protocol === 'file:') {
    status.textContent = '카메라 테스트는 로컬 개발 서버(http://127.0.0.1:5181)에서 실행해 주세요.';
    faceSession = undefined;
    return;
  }
  const video = document.createElement('video');
  video.className = 'face-preview';
  video.setAttribute('aria-label', '얼굴 인증 카메라 미리보기');
  status.after(video);
  try {
    const { captureFace } = await import('./face-capture.js');
    const result = await captureFace(video, controller.signal, message => {
      if (!controller.signal.aborted) status.textContent = message;
    }, { action: mode === 'enroll' ? 'enroll' : 'verify', packageJson: payment?.packageJson });
    if (controller.signal.aborted) return;
    if (result?.enrolled) transition('enrolled');
    else if (result?.verified && result.ticket) {
      payment.ticket = result.ticket;
      transition('ticket');
    } else if (!payment) transition('captured');
    else throw new Error('서명 티켓을 받지 못했습니다.');
  } catch (error) {
    if (!controller.signal.aborted) {
      status.textContent = `얼굴 확인을 완료하지 못했습니다. 카메라 권한을 확인하고 다시 시도해 주세요. (${error.message})`;
      video.remove();
    }
  } finally {
    if (faceSession === controller) faceSession = undefined;
  }
}

function renderSend() {
  const selected = stage !== 'empty';
  const recipient = payment?.review.recipient_address ?? sample.recipient;
  const amount = payment?.review.sent_sat ?? sample.amount;
  const fee = payment?.review.fee_sat ?? sample.fee;
  app.querySelector('.summary').hidden = !selected || stage === 'camera' || stage === 'enroll';
  app.querySelector('#recipient').textContent = selected ? recipient : '거래 선택 대기';
  app.querySelector('#amount').textContent = selected ? btc(amount) : '—';
  app.querySelector('#fee').textContent = selected ? btc(fee) : '—';
  app.querySelector('#total').textContent = selected ? btc(amount + fee) : '—';
  app.querySelector('.badge').textContent = payment ? '거래 검토' : '모의 데이터';
  const [index, title, message, buttons] = steps[stage];
  const detail = message.includes(sample.txid) ? message.replace(sample.txid, history[0].txid) : message;
  return showStep(index, title, detail, buttons);
}

function renderHistory() {
  const list = app.querySelector('#history-list');
  if (history.length === 0) {
    list.textContent = '이 세션에서 실행한 모의 송금이 없습니다.';
    return;
  }
  for (const item of history) {
    const row = document.createElement('article');
    const label = document.createElement('strong');
    label.textContent = `${btc(sample.amount)} · ${item.confirmed ? '블록 확인 완료' : '확인 대기'}`;
    const id = document.createElement('code');
    id.textContent = item.txid;
    row.append(label, id);
    list.append(row);
  }
}

function renderRoute() {
  faceSession?.abort();
  signingSession?.abort();
  if (stage === 'camera' || stage === 'enroll' || (stage === 'ticket' && !payment?.ticket)) stage = 'review';
  const hash = location.hash.slice(1);
  const page = Object.hasOwn(titles, hash) ? hash : 'wallet';
  if (page === 'send' && ['real-signed', 'real-pending', 'real-confirmed'].includes(stage) && payment?.chainStage) {
    stage = payment.chainStage;
  }
  const header = document.createElement('header');
  header.className = 'heading';
  const title = document.createElement('h1');
  title.textContent = titles[page];
  title.tabIndex = -1;
  const badge = document.createElement('span');
  badge.className = 'badge';
  badge.textContent = '모의 데이터';
  header.append(title, badge);
  app.replaceChildren(header, document.getElementById(page).content.cloneNode(true));
  document.querySelectorAll('nav a').forEach(link => {
    if (link.dataset.page === page) link.setAttribute('aria-current', 'page');
    else link.removeAttribute('aria-current');
  });
  if (page === 'send') renderSend();
  if (page === 'history') renderHistory();
  return title;
}

window.addEventListener('hashchange', () => renderRoute().focus());
window.addEventListener('pagehide', () => {
  faceSession?.abort();
  signingSession?.abort();
});
renderRoute();
