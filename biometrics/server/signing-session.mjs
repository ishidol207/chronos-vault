// Server-side only. verification is the authentication handler's verified record for this transaction.
import { createHash, sign } from 'node:crypto';

export function buildSigningSessionRequest(packageJson, verification, privateKey) {
  const digest = createHash('sha256').update(packageJson, 'utf8').digest('hex');
  if (digest !== verification.packageSha256) {
    throw new Error('Transaction differs from the one presented for authentication');
  }
  const authorization = JSON.stringify({
    audience: 'chronos-vault:testnet4:signing:v1',
    instance_id: verification.instanceId,
    public_key: verification.publicKey,
    package_sha256: digest,
    purpose: verification.purpose,
    role: verification.role,
    face_verified: verification.faceVerified,
    inheritance_evidence: verification.inheritanceEvidence ?? null,
    expires_at: verification.expiresAt,
  });
  return {
    package_json: packageJson,
    authorization,
    signature: sign(null, Buffer.from(authorization, 'utf8'), privateKey).toString('hex'),
  };
}
