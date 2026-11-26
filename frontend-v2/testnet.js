const path = '/api/testnet4/tx';

export async function broadcastTransaction(signed, fetchImpl = fetch) {
  const response = await fetchImpl(path, {
    method: 'POST',
    headers: { 'Content-Type': 'text/plain' },
    body: signed.raw_tx_hex,
    signal: AbortSignal.timeout(15000)
  });
  const body = (await response.text()).trim();
  if (!response.ok) throw new Error(body.slice(0, 250) || `HTTP ${response.status}`);
  if (body.toLowerCase() !== signed.txid.toLowerCase()) {
    throw new Error('서버가 반환한 거래번호가 로컬 거래번호와 다릅니다.');
  }
}

export async function transactionConfirmed(txid, fetchImpl = fetch) {
  const response = await fetchImpl(`${path}/${encodeURIComponent(txid)}/status`, {
    cache: 'no-store',
    signal: AbortSignal.timeout(15000)
  });
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  const status = await response.json();
  if (typeof status.confirmed !== 'boolean') throw new Error('거래 상태 응답이 올바르지 않습니다.');
  return status.confirmed;
}
