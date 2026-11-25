"""Black-box HTTP test. Uses a disposable generated wallet and synthetic Testnet4 outputs."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import time
from urllib import error, request

EXAMPLES = Path(__file__).resolve().parents[1] / "target/release/examples"
RUN = EXAMPLES / "threshold-runner"
BTC = EXAMPLES / "testnet4"


def double_sha(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def package(key, peer, amounts):
    addr = subprocess.check_output([BTC, "address", key], text=True).strip()
    key_hash = hashlib.new("ripemd160", hashlib.sha256(bytes.fromhex(key)).digest()).digest()
    script = bytes.fromhex("160014") + key_hash
    header = struct.pack("<I", 2)
    lock = bytes(4)
    parents, coins = {}, []
    for value in amounts:
        parent = (header + b"\x01" + bytes(32) + b"\xff" * 4 + b"\x02\x01\x01"
                  + b"\xff" * 4 + b"\x01" + struct.pack("<Q", value) + script + lock)
        txid = double_sha(parent)[::-1].hex()
        parents[txid] = parent.hex()
        coins.append(dict(txid=txid, vout=0, value=value))
    inputs = b"".join(bytes.fromhex(c["txid"])[::-1] + bytes(5) + bytes.fromhex("fdffffff")
                      for c in coins)
    fee = (4 * (10 + 41 * len(coins) + 31) + 2 + 108 * len(coins) + 3) // 4
    unsigned = header + bytes([len(coins)]) + inputs + b"\x01" + struct.pack("<Q", sum(amounts) - fee) + script + lock
    return json.dumps(dict(public_key=key, signers=[peer, 2], unsigned_tx_hex=unsigned.hex(),
                           request=dict(sender_address=addr, recipient_address=addr, amount={"type": "sweep"},
                                        fee_rate_sat_vb=1, utxos=coins, funding_transactions=parents)))


def post(url, path, token, body, expect=200):
    req = request.Request(url + path, data=json.dumps(body).encode(), headers={
        "Authorization": "Bearer " + token, "Content-Type": "application/json"})
    try:
        with request.urlopen(req, timeout=30) as res:
            assert res.status == expect
            return json.load(res)
    except error.HTTPError as exc:
        if exc.code != expect:
            raise AssertionError((exc.code, exc.read())) from exc


# File is a disposable Ed25519 verifier key, independent of all three wallet shares.
def verifier_key(path):
    return subprocess.check_output(["node", "--input-type=module", "-e", """
        import { generateKeyPairSync } from 'node:crypto';
        import { writeFileSync } from 'node:fs';
        const {publicKey, privateKey} = generateKeyPairSync('ed25519');
        writeFileSync(process.argv[1], privateKey.export({type:'pkcs8', format:'pem'}), {mode:0o600});
        console.log(Buffer.from(publicKey.export({format:'jwk'}).x,'base64url').toString('hex'));
    """, path], text=True).strip()


def session_request(path, raw, verification):
    helper = Path(__file__).resolve().parents[2] / "biometrics/server/signing-session.mjs"
    return json.loads(subprocess.check_output(["node", "--input-type=module", "-e", """
        import { readFileSync } from 'node:fs';
        import { pathToFileURL } from 'node:url';
        const {buildSigningSessionRequest} = await import(pathToFileURL(process.argv[1]));
        const {raw, verification} = JSON.parse(readFileSync(0, 'utf8'));
        console.log(JSON.stringify(buildSigningSessionRequest(raw, verification, readFileSync(process.argv[2]))));
    """, helper, path], input=json.dumps(dict(raw=raw, verification=verification)), text=True))


def run(temp):
    # Deliberately ignore any real wallet or key-directory environment.
    env = {k: v for k, v in os.environ.items() if not k.startswith("CHRONOS_")}
    env["XDG_DATA_HOME"] = str(temp / "initial-keys")
    initial = temp / "initial"
    key = subprocess.check_output([RUN, "keygen", initial], env=env, text=True).strip()
    wallets, envs = {}, {}
    for i in (1, 2, 3):
        home = temp / str(i)
        home.mkdir()
        wallets[i] = home / "wallet"
        wallets[i].mkdir()
        for name in ("public-key.json", "party-store.version"):
            shutil.copyfile(initial / name, wallets[i] / name)
        (initial / f"party-{i}").rename(wallets[i] / f"party-{i}")
        keydir = home / "keys"
        keydir.mkdir()
        name = f"{key}-party-{i}.key"
        (Path(env["XDG_DATA_HOME"]) / "chronos-vault/keys" / name).rename(keydir / name)
        envs[i] = {**env, f"CHRONOS_PARTY_{i}_KEY_DIR": str(keydir)}

    verifier = temp / "test-verifier.pem"
    verifier_pub = verifier_key(verifier)
    sessions = "/v1/signing/sessions"
    with subprocess.Popen([RUN, "serve", wallets[2], "--listen", "127.0.0.1:0"],
                          env={**envs[2], "CHRONOS_AUTH_PUBLIC_KEY": verifier_pub},
                          stderr=subprocess.PIPE, text=True) as server:
        try:
            ready = server.stderr.readline().strip()
            assert ready.startswith("Testnet4 signing server listening on "), ready
            url = "http://" + ready.split()[-1]
            with request.urlopen(url + "/v1/signing/context", timeout=5) as res:
                context = json.load(res)
            assert context["public_key"] == key
            post(url, "/v1/approvals", "old-admin", {}, 404)
            for mode, peer, amounts in [("normal_sign", 1, [20000]), ("recovery", 3, [30000, 20000]),
                                         ("inheritance", 3, [20000])]:
                raw = package(key, peer, amounts)
                payment = temp / (mode + ".json")
                payment.write_text(raw)
                verification = dict(instanceId=context["instance_id"], publicKey=key,
                                    packageSha256=hashlib.sha256(raw.encode()).hexdigest(),
                                    purpose=mode, role="heir" if mode == "inheritance" else "owner",
                                    faceVerified=True, inheritanceEvidence="death_verified" if mode == "inheritance" else None,
                                    expiresAt=int(time.time()) + 90)
                def issue(changes):
                    return session_request(verifier, raw, {**verification, **changes})
                valid = issue({})
                post(url, sessions, "", {**valid, "signature": "00" * 64}, 401)
                post(url, sessions, "", {**valid, "package_json": raw + " "}, 401)
                post(url, sessions, "", issue({"faceVerified": False}), 403)
                post(url, sessions, "", issue({"role": "owner" if mode == "inheritance" else "heir"}), 403)
                post(url, sessions, "", issue({"expiresAt": int(time.time()) - 1}), 401)
                post(url, sessions, "", issue({"instanceId": "other-instance"}), 401)
                post(url, sessions, "", issue({"publicKey": "other-wallet"}), 401)
                if mode == "inheritance":
                    post(url, sessions, "", issue({"inheritanceEvidence": None}), 403)
                    post(url, sessions, "", issue({"inheritanceEvidence": "inactivity_elapsed"}))
                if mode == "normal_sign":
                    post(url, sessions, "", issue({"purpose": "recovery"}), 422)
                ticket = post(url, sessions, "", valid)["ticket"]
                assert post(url, sessions, "", valid)["ticket"] == ticket
                start = {"step": 0, "messages": []}
                post(url, "/v1/signing/steps", "bad-ticket", start, 401)
                first = post(url, "/v1/signing/steps", ticket, start)
                assert first == post(url, "/v1/signing/steps", ticket, start)
                post(url, "/v1/signing/steps", ticket, {"step": 2, "messages": []}, 409)
                post(url, "/v1/signing/steps", ticket, {"step": 0, "messages": ["changed"]}, 409)
                other = temp / "different-payment.json"
                other.write_text(package(key, peer, [40000]))
                mismatch = subprocess.run(
                    [RUN, "remote-sign", wallets[peer], other, "--server", url, "--purpose", mode],
                    input=ticket, env=envs[peer], text=True, capture_output=True)
                assert mismatch.returncode != 0 and "approved transaction" in mismatch.stderr
                signed = json.loads(subprocess.check_output(
                    [RUN, "remote-sign", wallets[peer], payment, "--server", url, "--purpose", mode],
                    input=ticket, env=envs[peer], text=True))
                unsigned = bytes.fromhex(json.loads(raw)["unsigned_tx_hex"])
                assert signed["txid"] == double_sha(unsigned)[::-1].hex()
                assert signed["sent_sat"] + signed["fee_sat"] == sum(amounts)
                post(url, "/v1/signing/steps", ticket, start, 409)
                print(f"{mode}: {len(amounts)} input(s), signature verified", flush=True)
            # A malformed peer round closes that ticket, without killing the server.
            grant = post(url, sessions, "", issue({"expiresAt": int(time.time()) + 110}))["ticket"]
            post(url, "/v1/signing/steps", grant, start)
            post(url, "/v1/signing/steps", grant, {"step": 1, "messages": []}, 422)
            post(url, "/v1/signing/steps", grant, {"step": 1, "messages": []}, 410)
            post(url, "/v1/signing/steps", grant, start, 410)
            assert len(list((wallets[2] / "party-2/spent-nonces").iterdir())) == 4
        finally:
            server.terminate()

    # Original emergency path: server is stopped and S is absent from this wallet.
    for i in (1, 3):
        (wallets[i] / f"party-{i}").rename(initial / f"party-{i}")
    assert not (initial / "party-2").exists()
    offline_env = {**envs[1], "CHRONOS_PARTY_3_KEY_DIR": envs[3]["CHRONOS_PARTY_3_KEY_DIR"]}
    doc = json.loads(package(key, 1, [20000]))
    doc["signers"] = [1, 3]
    raw = json.dumps(doc)
    payment = temp / "offline-payment.json"
    payment.write_text(raw)
    batch = Path(subprocess.check_output([RUN, "presign", initial, payment], env=offline_env, text=True).strip())
    replies = []
    for i, peer in [(1, 3), (3, 1)]:
        reply = temp / f"reply-{i}.json"
        reply.write_text(subprocess.check_output([BTC, "sign-share", initial / f"party-{i}", batch / f"party-{i}.json",
                         "--peer-id", str(peer)], input=raw, env=offline_env, text=True))
        replies.append(reply)
    signed = json.loads(subprocess.check_output([BTC, "combine", payment, *replies], text=True))
    assert signed["txid"] == double_sha(bytes.fromhex(doc["unsigned_tx_hex"]))[::-1].hex()
    print("U+R offline: signature verified with S stopped", flush=True)


if __name__ == "__main__":
    with tempfile.TemporaryDirectory() as temp:
        run(Path(temp))
