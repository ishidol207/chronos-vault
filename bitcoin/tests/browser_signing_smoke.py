"""Open the printed local URL in a browser to test with a freshly generated disposable wallet."""
import base64
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib import request, error

from signing_server_smoke import RUN, package, verifier_key, session_request, post, double_sha

HERE = Path(__file__).resolve().parent
ASSETS = HERE.parent / "browser"
PAGE = """<!doctype html><meta charset="utf-8"><title>Browser signing test</title>
<h1>Chronos Vault browser signing test</h1><pre id="status">Running</pre>
<script type="module">
import {reviewPayment, signOffline, signWithServer} from '/assets/signer.js';
const status = document.querySelector('#status');
const report = text => { status.textContent += '\\n' + text; };
function files(encoded) {
 const [envelope, aesKey, identity] = encoded.map((s,i) =>
   new File([Uint8Array.from(atob(s), c => c.charCodeAt(0))], ['secrets.cvparty','party.key','peer.json'][i]));
 return {envelope, aesKey, identity};
}
let success = false;
try {
 for (const purpose of ['normal_sign','recovery','inheritance','offline']) {
   const f = await (await fetch(location.pathname + '/case/' + purpose)).json();
   const a = files(f.files);
   const args = {purpose,packageJson:f.raw,ticket:f.ticket,files:a};
   const review = await reviewPayment(f.raw);
   if (!review.sent_sat) throw Error('Missing review');
   if (purpose === 'normal_sign') {
     let refused = false;
     try { await signWithServer({...args,files:{...a,aesKey:new File([new Uint8Array(32)],'wrong')}}); }
     catch { refused = true; }
     if (!refused) throw Error('Accepted wrong key');
   }
   const signed = purpose === 'offline'
     ? await signOffline({packageJson:f.raw,userFiles:a,recoveryFiles:files(f.recovery)})
     : await signWithServer(args);
   if (signed.txid !== f.txid || !signed.raw_tx_hex) throw Error('Incorrect signed transaction');
   report(purpose + ' verified');
 }
 success = true;
} catch (err) {report('Failed: ' + err.message);}
await fetch(location.pathname + '/result', {method:'POST',body:JSON.stringify({success,report:status.textContent})});
</script>"""


def run(temp):
    env = {k: v for k, v in os.environ.items() if not k.startswith("CHRONOS_")}
    env["XDG_DATA_HOME"] = str(temp / "key-home")
    wallet = temp / "wallet"
    pk = subprocess.check_output([RUN, "keygen", wallet], env=env, text=True).strip()
    key_home = temp / "key-home/chronos-vault/keys"
    def fixture_files(local, peer):
        paths = [wallet / f"party-{local}/secrets.cvparty", key_home / f"{pk}-party-{local}.key",
                 wallet / f"party-{local}/peer-{peer}.json"]
        return [base64.b64encode(p.read_bytes()).decode("ascii") for p in paths]
    verifier = temp / "auth.pem"
    pub = verifier_key(verifier)
    prefix = "/" + secrets.token_urlsafe(20)
    done = threading.Event()
    result = {}
    class Frontend(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def reply(self, data, kind):
            self.send_response(200)
            self.send_header("Content-Type", kind)
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            if self.headers.get("Host") != host:
                self.send_error(403)
                return
            resources = {"/assets/" + n: ASSETS / n for n in ["signer.js", "signer-worker.js", "chronos_signer.wasm"]}
            if self.path == prefix:
                self.reply(PAGE.encode(), "text/html")
            elif self.path in resources:
                kind = "application/wasm" if self.path.endswith(".wasm") else "text/javascript"
                self.reply(resources[self.path].read_bytes(), kind)
            elif self.path.startswith(prefix + "/case/"):
                mode = self.path.split("/")[-1]
                if mode not in ("normal_sign", "recovery", "inheritance", "offline"):
                    self.send_error(404)
                    return
                peer = 1 if mode in ("normal_sign", "offline") else 3
                raw = package(pk, peer, [30000, 20000] if mode == "recovery" else [20000])
                doc = json.loads(raw)
                if mode == "offline":
                    proc.terminate()
                    proc.wait(timeout=5)
                    doc["signers"] = [1, 3]
                    raw = json.dumps(doc)
                    fixture = dict(files=fixture_files(1, 3), recovery=fixture_files(3, 1))
                else:
                    verification = dict(instanceId=context["instance_id"], publicKey=pk,
                                        packageSha256=hashlib.sha256(raw.encode()).hexdigest(), purpose=mode,
                                        role="heir" if mode == "inheritance" else "owner", faceVerified=True,
                                        inheritanceEvidence="death_verified" if mode == "inheritance" else None,
                                        expiresAt=int(time.time()) + 110)
                    proof = session_request(verifier, raw, verification)
                    ticket = post(signer, "/v1/signing/sessions", "", proof)["ticket"]
                    fixture = dict(files=fixture_files(peer, 2), ticket=ticket)
                txid = double_sha(bytes.fromhex(doc["unsigned_tx_hex"]))[::-1].hex()
                self.reply(json.dumps(dict(raw=raw, txid=txid, **fixture)).encode(), "application/json")
            else:
                self.send_error(404)

        def do_POST(self):
            if self.headers.get("Host") != host or self.headers.get("Origin") != "http://" + host:
                self.send_error(403)
                return
            body = self.rfile.read(int(self.headers["content-length"]))
            if self.path == prefix + "/result":
                result.update(json.loads(body))
                self.reply(b"ok", "text/plain")
                done.set()
                return
            if self.path != "/v1/signing/steps":
                self.send_error(404)
                return
            assert set(json.loads(body)) == {"step", "messages"}
            req = request.Request(signer + self.path, data=body, headers={
                "Content-Type": "application/json", "Authorization": self.headers["Authorization"]})
            try:
                with request.urlopen(req, timeout=60) as res:
                    data, status = res.read(), res.status
            except error.HTTPError as exc:
                data, status = exc.read(), exc.code
            if json.loads(body)["step"] == 1 and not self.server.dropped:
                self.server.dropped = True
                return
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(data)

    with ThreadingHTTPServer(("127.0.0.1", 0), Frontend) as front, subprocess.Popen(
        [RUN, "serve", wallet, "--listen", "127.0.0.1:0"], env={**env, "CHRONOS_AUTH_PUBLIC_KEY": pub},
        stderr=subprocess.PIPE, text=True) as proc:
        try:
            front.dropped = False
            host = f"127.0.0.1:{front.server_port}"
            info = proc.stderr.readline().strip()
            assert info.startswith("Testnet4 signing server listening on "), info
            signer = "http://" + info.split()[-1]
            with request.urlopen(signer + "/v1/signing/context") as res:
                context = json.load(res)
            threading.Thread(target=front.serve_forever, daemon=True).start()
            print("Open http://" + host + prefix, flush=True)
            if not done.wait(600):
                raise TimeoutError("Browser test timed out")
            print(result["report"], flush=True)
            assert result["success"] and front.dropped
        finally:
            proc.terminate()


if __name__ == "__main__":
    with tempfile.TemporaryDirectory() as folder:
        run(Path(folder))
