use crate::parameters::SECURITY_PARAM;
use crate::ring_pedersen::RingPedersen;
use crate::{
    curve::CurveTrait,
    errors::*,
    paillier::{Ciphertext, EncryptionKey, MaskedNonce, Nonce, PaillierError},
    parameters::{ELL, ELL_PRIME, EPSILON},
    ring_pedersen::{Commitment, MaskedRandomness, VerifiedRingPedersen},
    utils::{plusminus_challenge_from_transcript, random_plusminus_by_size, within_bound_by_size},
    zkp::{Proof, ProofContext},
};
use itertools::Itertools;
use libpaillier::unknown_order::BigNumber;
use merlin::Transcript;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use std::iter::repeat_with;
use tracing::error;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct PiDecProof<C> {
    As: Vec<Ciphertext>,
    Bs: Vec<C>,
    Cs: Vec<C>,
    zs: Vec<BigNumber>,
    ws: Vec<BigNumber>,
    vs: Vec<BigNumber>,
}

#[derive(Serialize, Clone, Copy)]
pub(crate) struct PiDecInput<'a, C> {
    //prover's encryption key
    N0: &'a EncryptionKey,
    K: &'a Ciphertext,
    X: &'a C,
    D: &'a Ciphertext,
    S: &'a C,
    g: &'a C,
}

impl<'a, C> PiDecInput<'a, C> {
    pub(crate) fn new(
        prover_encryption_key: &'a EncryptionKey,
        K: &'a Ciphertext,
        X: &'a C,
        D: &'a Ciphertext,
        S: &'a C,
        g: &'a C,
    ) -> PiDecInput<'a, C> {
        Self {
            N0: prover_encryption_key,
            K,
            X,
            D,
            S,
            g,
        }
    }
}

pub(crate) struct PiDecSecret<'a> {
    // γ_i (Γ_i의 지수승에 있는 값)
    x: &'a BigNumber,
    // δ_i
    y: &'a BigNumber,
    rho: &'a Nonce,
}

impl Debug for PiDecSecret<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Paillier Dec Operation Proof Secret")
            .field("x", &"[redacted]")
            .field("y", &"[redacted]")
            .field("rho", &"[redacted]")
            .finish()
    }
}

impl<'a> PiDecSecret<'a> {
    pub(crate) fn new(x: &'a BigNumber, y: &'a BigNumber, rho: &'a Nonce) -> PiDecSecret<'a> {
        Self { x, y, rho }
    }
}

impl<C: CurveTrait> Proof for PiDecProof<C> {
    type CommonInput<'a> = PiDecInput<'a, C>;
    type ProverSecret<'b> = PiDecSecret<'b>;

    #[cfg_attr(feature = "flame_it", flame("PiDecProof"))]
    fn prove<R: RngCore + CryptoRng>(
        input: Self::CommonInput<'_>,
        secret: Self::ProverSecret<'_>,
        context: &impl ProofContext,
        transcript: &mut Transcript,
        rng: &mut R,
    ) -> Result<Self> {
        let alphas = repeat_with(|| random_plusminus_by_size(rng, ELL + EPSILON))
            .take(SECURITY_PARAM)
            .collect::<Vec<BigNumber>>();
        let betas = repeat_with(|| random_plusminus_by_size(rng, ELL_PRIME + EPSILON))
            .take(SECURITY_PARAM)
            .collect::<Vec<BigNumber>>();

        let (ciphertexts, rs): (Vec<Ciphertext>, Vec<Nonce>) = (0..SECURITY_PARAM)
            .map(|i| {
                input
                    .N0
                    .encrypt(rng, &betas[i])
                    .map_err(|_| InternalError::InternalInvariantFailed)
            })
            .collect::<Result<Vec<(Ciphertext, Nonce)>>>()?
            .into_iter()
            .unzip();

        let As = (0..SECURITY_PARAM)
            .map(|i| {
                input
                    .N0
                    .multiply_and_add(&(-alphas[i].clone()), input.K, &ciphertexts[i])
                    .map_err(|_| InternalError::InternalInvariantFailed)
            })
            .collect::<Result<Vec<Ciphertext>>>()?;

        let Bs = (0..SECURITY_PARAM)
            .map(|i| input.g.multiply_by_bignum(&betas[i]))
            .collect::<Result<Vec<C>>>()?;

        let Cs = (0..SECURITY_PARAM)
            .map(|i| C::scale_generator(&alphas[i]))
            .collect::<Result<Vec<C>>>()?;

        let commitments = vec![
            As.iter()
                .fold(vec![], |vec, A| [vec, A.to_bytes()].concat()),
            Bs.iter().map(|B| serialize!(B).unwrap()).concat(),
            Cs.iter().map(|C| serialize!(C).unwrap()).concat(),
        ]
        .concat();

        let challenge = generate_challenge_bytes(&input, commitments, context, transcript)?;

        let zs = (0..SECURITY_PARAM)
            .map(|i| {
                if challenge[i] % 2 == 1 {
                    &alphas[i] + secret.x
                } else {
                    alphas[i].clone()
                }
            })
            .collect::<Vec<BigNumber>>();

        let ws = (0..SECURITY_PARAM)
            .map(|i| {
                if challenge[i] % 2 == 1 {
                    &betas[i] + secret.y
                } else {
                    betas[i].clone()
                }
            })
            .collect::<Vec<BigNumber>>();

        let vs = (0..SECURITY_PARAM)
            .map(|i| {
                if challenge[i] % 2 == 1 {
                    (&rs[i].0 * &secret.rho.0).nmod(input.N0.0.n())
                } else {
                    rs[i].0.nmod(input.N0.0.n())
                }
            })
            .collect::<Vec<BigNumber>>();

        Ok(Self {
            As,
            Bs,
            Cs,
            zs,
            ws,
            vs,
        })
    }

    #[cfg_attr(feature = "flame_it", flame("PiDecProof"))]
    fn verify(
        self,
        input: Self::CommonInput<'_>,
        context: &impl ProofContext,
        transcript: &mut Transcript,
    ) -> Result<()> {
        let commitments = vec![
            self.As
                .iter()
                .fold(vec![], |vec, A| [vec, A.to_bytes()].concat()),
            self.Bs.iter().map(|B| serialize!(B).unwrap()).concat(),
            self.Cs.iter().map(|C| serialize!(C).unwrap()).concat(),
        ]
        .concat();

        let challenge = generate_challenge_bytes(&input, commitments, context, transcript)?;

        for i in 0..SECURITY_PARAM {
            let tmp = input
                .N0
                .encrypt_with_nonce(&self.ws[i], &MaskedNonce(self.vs[i].clone()))
                .map_err(|_| InternalError::InternalInvariantFailed)?;

            let lhs = input
                .N0
                .multiply_and_add(&(-self.zs[i].clone()), input.K, &tmp)
                .map_err(|_| InternalError::InternalInvariantFailed)?;

            let rhs = if challenge[i] % 2 == 1 {
                self.As[i].0.clone() * input.D.0.clone()
            } else {
                self.As[i].0.clone()
            };
            let rhs = rhs.nmod(input.N0.0.nn());

            if lhs.0 != rhs {
                error!("Affine operation check failed for index {}", i);
                return Err(InternalError::ProtocolError(None));
            }

            let lhs = C::scale_generator(&self.zs[i])?;

            let rhs = if challenge[i] % 2 == 1 {
                self.Cs[i] + input.X.clone()
            } else {
                self.Cs[i]
            };

            if lhs != rhs {
                error!("Group exponentiation 1 check failed for index {}", i);
                return Err(InternalError::ProtocolError(None));
            }

            let lhs = input.g.multiply_by_bignum(&self.ws[i])?;

            let rhs = if challenge[i] % 2 == 1 {
                self.Bs[i] + input.S.clone()
            } else {
                self.Bs[i]
            };

            if lhs != rhs {
                error!("Group exponentiation 2 check failed for index {}", i);
                return Err(InternalError::ProtocolError(None));
            }

            if !within_bound_by_size(&self.zs[i], ELL + EPSILON)
                || !within_bound_by_size(&self.ws[i], ELL_PRIME + EPSILON)
            {
                error!("Challenge values out of range for index {}", i);
                return Err(InternalError::ProtocolError(None));
            }
        }

        Ok(())
    }
}

fn generate_challenge_bytes<C: CurveTrait>(
    input: &PiDecInput<C>,
    commitments: Vec<u8>,
    context: &impl ProofContext,
    transcript: &mut Transcript,
) -> Result<Vec<u8>> {
    transcript.append_message(b"PiDec ProofContext", &context.as_bytes()?);
    transcript.append_message(b"PiDec Common input", &serialize!(&input)?);
    transcript.append_message(b"PiDec Commitments", &commitments);
    // Extract challenge bytes from the transcript.
    let mut challenges = [0u8; crate::parameters::SECURITY_PARAM];
    transcript.challenge_bytes(b"Challenges", challenges.as_mut_slice());
    Ok(challenges.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::curve::TestCurve;
    use crate::k256::k256_order;
    use crate::utils::random_positive_bn;
    use crate::{
        curve::{CurveTrait, TestCurve as C},
        paillier::DecryptionKey,
        utils::{random_plusminus, random_plusminus_by_size_with_minimum, testing::init_testing},
        zkp::BadContext,
    };
    use rand::{rngs::StdRng, Rng, SeedableRng};

    type PiDecProof = super::PiDecProof<C>;
    type PiDecInput<'a> = super::PiDecInput<'a, C>;

    type TestFn = fn(PiDecProof, PiDecInput) -> Result<()>;

    fn transcript() -> Transcript {
        Transcript::new(b"random_paillier_dec_proof")
    }

    fn with_random_paillier_dec_proof<R: RngCore + CryptoRng>(
        rng: &mut R,
        x: &BigNumber,
        mut test_code: impl FnMut(PiDecProof, PiDecInput) -> Result<()>,
    ) -> Result<()> {
        let (decryption_key, _, _) = DecryptionKey::new(rng).unwrap();
        let pk = decryption_key.encryption_key();

        let X = C::GENERATOR.multiply_by_bignum(x)?; // Γ_i 값과 같음

        // F_q 에서 k 뽑기
        let k = random_positive_bn(rng, &k256_order());
        let (K, _) = pk
            .encrypt(rng, &k)
            .map_err(|_| InternalError::InternalInvariantFailed)?;

        // 편의를 위해 참여자가 3명 있다고 가정하겠습니다. 또한 D_ij 의 계산을 γk-β 의 암호화로 대체합니다.
        let gamma_1 = random_positive_bn(rng, &k256_order());
        let beta_1i = random_plusminus_by_size(rng, ELL_PRIME);
        let (D_i1, _) = pk
            .encrypt(rng, &(&gamma_1 * &k - &beta_1i))
            .map_err(|_| InternalError::InternalInvariantFailed)?;
        let beta_i1 = random_plusminus_by_size(rng, ELL_PRIME);
        let (F_1i, _) = pk
            .encrypt(rng, &beta_i1)
            .map_err(|_| InternalError::InternalInvariantFailed)?;

        let gamma_2 = random_positive_bn(rng, &k256_order());
        let beta_2i = random_plusminus_by_size(rng, ELL_PRIME);
        let (D_i2, _) = pk
            .encrypt(rng, &(&gamma_2 * &k - &beta_2i))
            .map_err(|_| InternalError::InternalInvariantFailed)?;
        let beta_i2 = random_plusminus_by_size(rng, ELL_PRIME);
        let (F_2i, _) = pk
            .encrypt(rng, &beta_i2)
            .map_err(|_| InternalError::InternalInvariantFailed)?;

        let y = x * &k
            + &(&gamma_1 * &k - &beta_1i)
            + &(&gamma_2 * &k - &beta_2i)
            + &beta_i1
            + &beta_i2; // delta_i 값
        let S = C::GENERATOR.multiply_by_bignum(&y)?; // delta_i 를 지수승한 값

        // 모두 곱해 D 를 계산합니다.
        let D = Ciphertext(
            D_i1.0
                .modmul(&D_i2.0, pk.0.nn())
                .modmul(&F_1i.0, pk.0.nn())
                .modmul(&F_2i.0, pk.0.nn()),
        );

        let Delta = Ciphertext(D.0.modmul(&K.0.modpow(&x, pk.0.nn()), pk.0.nn()));
        let rho = Nonce(
            decryption_key
                .get_rho(Delta.clone())
                .map_err(|_| InternalError::InternalInvariantFailed)?,
        );

        let input = PiDecInput::new(&pk, &K, &X, &D, &S, &C::GENERATOR);
        let secret = PiDecSecret::new(x, &y, &rho);

        let proof = PiDecProof::prove(input, secret, &(), &mut transcript(), rng)?;
        test_code(proof, input)?;
        Ok(())
    }

    fn random_paillier_dec_verified_proof<R: RngCore + CryptoRng>(
        rng: &mut R,
        x: &BigNumber,
    ) -> Result<()> {
        let f: TestFn = |proof, input| proof.verify(input, &(), &mut transcript());
        with_random_paillier_dec_proof(rng, x, f)
    }

    #[test]
    fn test_paillier_dec_proof() -> Result<()> {
        let mut rng = init_testing();

        let x = random_positive_bn(&mut rng, &k256_order());

        assert!(random_paillier_dec_verified_proof(&mut rng, &x).is_ok());

        Ok(())
    }
}
