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
    ParticipantIdentifier,
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
pub(crate) struct PiAffgStarProof<C> {
    As: Vec<Ciphertext>,
    Bs: Vec<Ciphertext>,
    Rs: Vec<C>,
    zs: Vec<BigNumber>,
    z_primes: Vec<BigNumber>,
    ws: Vec<BigNumber>,
    lamdas: Vec<BigNumber>,
    verifier_pid: ParticipantIdentifier,
}

#[derive(Serialize, Clone, Copy)]
pub(crate) struct PiAffgStarInput<'a, C> {
    /// The verifier's Paillier encryption key (`N_0` in the paper).
    verifier_encryption_key: &'a EncryptionKey,
    /// The prover's Paillier encryption key (`N_1` in the paper).
    prover_encryption_key: &'a EncryptionKey,
    /// The original Paillier ciphertext encrypted under the verifier's
    /// encryption key (`C` in the paper).
    original_ciphertext_verifier: &'a Ciphertext,
    /// The transformed Paillier ciphertext encrypted under the verifier's
    /// encryption key (`D` in the paper).
    transformed_ciphertext_verifier: &'a Ciphertext,
    /// Paillier ciphertext of the prover's additive coefficient under the
    /// prover's encryption key (`Y` in the paper).
    add_coeff_ciphertext_prover: &'a Ciphertext,
    /// Exponentiation of the prover's multiplicative coefficient (`X` in the
    /// paper).
    mult_coeff_exp: &'a C,
    verifier_pid: ParticipantIdentifier,
}

impl<'a, C> PiAffgStarInput<'a, C> {
    pub(crate) fn new(
        verifier_encryption_key: &'a EncryptionKey,
        prover_encryption_key: &'a EncryptionKey,
        original_ciphertext_verifier: &'a Ciphertext,
        transformed_ciphertext_verifier: &'a Ciphertext,
        add_coeff_ciphertext_prover: &'a Ciphertext,
        mult_coeff_exp: &'a C,
        verifier_pid: ParticipantIdentifier,
    ) -> PiAffgStarInput<'a, C> {
        Self {
            verifier_encryption_key,
            prover_encryption_key,
            original_ciphertext_verifier,
            transformed_ciphertext_verifier,
            add_coeff_ciphertext_prover,
            mult_coeff_exp,
            verifier_pid,
        }
    }
}

pub(crate) struct PiAffgStarSecret<'a> {
    /// The multiplicative coefficient (`x` in the paper).
    mult_coeff: &'a BigNumber,
    /// The additive coefficient (`y` in the paper).
    add_coeff: &'a BigNumber,
    /// The additive coefficient's nonce produced when encrypted using the
    /// verifier's encryption key (`ρ` in the paper).
    add_coeff_nonce_verifier_key: &'a Nonce,
    /// The additive coefficient's nonce produced when encrypted using the
    /// prover's encryption key (`µ` in the paper).
    add_coeff_nonce_prover_key: &'a Nonce,
}

impl Debug for PiAffgStarSecret<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Paillier Affine Star Operation Proof Secret")
            .field("mult_coeff", &"[redacted]")
            .field("add_coeff", &"[redacted]")
            .field("add_coeff_nonce_verifier", &"[redacted]")
            .field("add_coeff_nonce_prover", &"[redacted]")
            .finish()
    }
}

impl<'a> PiAffgStarSecret<'a> {
    /// Construct a new [`PiAffgStarSecret`] type.
    pub(crate) fn new(
        mult_coeff: &'a BigNumber,
        add_coeff: &'a BigNumber,
        add_coeff_nonce_verifier_key: &'a Nonce,
        add_coeff_nonce_prover_key: &'a Nonce,
    ) -> PiAffgStarSecret<'a> {
        Self {
            mult_coeff,
            add_coeff,
            add_coeff_nonce_verifier_key,
            add_coeff_nonce_prover_key,
        }
    }
}

impl<C: CurveTrait> Proof for PiAffgStarProof<C> {
    type CommonInput<'a> = PiAffgStarInput<'a, C>;
    type ProverSecret<'b> = PiAffgStarSecret<'b>;

    #[cfg_attr(feature = "flame_it", flame("PiAffgStarProof"))]
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
                    .verifier_encryption_key
                    .encrypt(rng, &betas[i])
                    .map_err(|_| InternalError::InternalInvariantFailed)
            })
            .collect::<Result<Vec<(Ciphertext, Nonce)>>>()?
            .into_iter()
            .unzip();

        let As = (0..SECURITY_PARAM)
            .map(|i| {
                input
                    .verifier_encryption_key
                    .multiply_and_add(
                        &alphas[i],
                        input.original_ciphertext_verifier,
                        &ciphertexts[i],
                    )
                    .map_err(|_| InternalError::InternalInvariantFailed)
            })
            .collect::<Result<Vec<Ciphertext>>>()?;

        let Rs = (0..SECURITY_PARAM)
            .map(|i| C::scale_generator(&alphas[i]))
            .collect::<Result<Vec<C>>>()?;

        let (Bs, ss): (Vec<Ciphertext>, Vec<Nonce>) = (0..SECURITY_PARAM)
            .map(|i| {
                input
                    .prover_encryption_key
                    .encrypt(rng, &betas[i])
                    .map_err(|_| InternalError::InternalInvariantFailed)
            })
            .collect::<Result<Vec<(Ciphertext, Nonce)>>>()?
            .into_iter()
            .unzip();

        let commitments = vec![
            As.iter()
                .fold(vec![], |vec, A| [vec, A.to_bytes()].concat()),
            Bs.iter()
                .fold(vec![], |vec, B| [vec, B.to_bytes()].concat()),
            Rs.iter().map(|R| serialize!(R).unwrap()).concat(),
        ]
        .concat();

        let challenge = generate_challenge_bytes(&input, commitments, context, transcript)?;

        let zs = (0..SECURITY_PARAM)
            .map(|i| {
                if challenge[i] % 2 == 1 {
                    &alphas[i] + secret.mult_coeff
                } else {
                    alphas[i].clone()
                }
            })
            .collect::<Vec<BigNumber>>();

        let z_primes = (0..SECURITY_PARAM)
            .map(|i| {
                if challenge[i] % 2 == 1 {
                    &betas[i] - secret.add_coeff
                } else {
                    betas[i].clone()
                }
            })
            .collect::<Vec<BigNumber>>();

        let ws = (0..SECURITY_PARAM)
            .map(|i| {
                if challenge[i] % 2 == 1 {
                    (&rs[i].0 * &secret.add_coeff_nonce_verifier_key.0)
                        .nmod(input.verifier_encryption_key.0.n())
                } else {
                    rs[i].0.clone()
                }
            })
            .collect::<Vec<BigNumber>>();

        let lamdas = (0..SECURITY_PARAM)
            .map(|i| {
                if challenge[i] % 2 == 1 {
                    (&ss[i].0
                        * &secret
                            .add_coeff_nonce_prover_key
                            .0
                            .invert(input.prover_encryption_key.0.n())
                            .unwrap())
                        .nmod(input.prover_encryption_key.0.n())
                } else {
                    ss[i].0.clone()
                }
            })
            .collect::<Vec<BigNumber>>();

        Ok(Self {
            As,
            Bs,
            Rs,
            zs,
            z_primes,
            ws,
            lamdas,
            verifier_pid: input.verifier_pid,
        })
    }

    #[cfg_attr(feature = "flame_it", flame("PiAffgStarProof"))]
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
            self.Bs
                .iter()
                .fold(vec![], |vec, B| [vec, B.to_bytes()].concat()),
            self.Rs.iter().map(|R| serialize!(R).unwrap()).concat(),
        ]
        .concat();

        let challenge = generate_challenge_bytes(&input, commitments, context, transcript)?;

        for i in 0..SECURITY_PARAM {
            let tmp = input
                .verifier_encryption_key
                .encrypt_with_nonce(&self.z_primes[i], &MaskedNonce(self.ws[i].clone()))
                .map_err(|_| InternalError::InternalInvariantFailed)?;

            let lhs = input
                .verifier_encryption_key
                .multiply_and_add(&self.zs[i], input.original_ciphertext_verifier, &tmp)
                .map_err(|_| InternalError::InternalInvariantFailed)?;

            let rhs = if challenge[i] % 2 == 1 {
                input.transformed_ciphertext_verifier.0.clone() * self.As[i].0.clone()
            } else {
                self.As[i].0.clone()
            };
            let rhs = rhs.nmod(input.verifier_encryption_key.0.nn());

            if lhs.0 != rhs {
                error!("Affine operation check failed for index {}", i);
                return Err(InternalError::ProtocolError(None));
            }

            let lhs = C::scale_generator(&self.zs[i])?;

            let rhs = if challenge[i] % 2 == 1 {
                self.Rs[i] + input.mult_coeff_exp.clone()
            } else {
                self.Rs[i]
            };

            if lhs != rhs {
                error!("Group exponentiation check failed for index {}", i);
                return Err(InternalError::ProtocolError(None));
            }

            let lhs = input
                .prover_encryption_key
                .encrypt_with_nonce(&self.z_primes[i], &MaskedNonce(self.lamdas[i].clone()))
                .map_err(|_| InternalError::ProtocolError(None))?;

            let rhs = if challenge[i] % 2 == 1 {
                self.Bs[i].0.clone()
                    * input
                        .add_coeff_ciphertext_prover
                        .0
                        .invert(input.prover_encryption_key.0.nn())
                        .unwrap()
            } else {
                self.Bs[i].0.clone()
            };
            let rhs = rhs.nmod(input.prover_encryption_key.0.nn());

            if lhs.0 != rhs {
                error!(
                    "Masked additive coefficient check (third equality check) failed {}",
                    i
                );
                return Err(InternalError::ProtocolError(None));
            }

            if !within_bound_by_size(&self.zs[i], ELL + EPSILON)
                || !within_bound_by_size(&self.z_primes[i], ELL_PRIME + EPSILON)
            {
                error!("Challenge values out of range for index {}", i);
                return Err(InternalError::ProtocolError(None));
            }
        }

        Ok(())
    }
}

impl<C: CurveTrait> PiAffgStarProof<C> {
    pub(crate) fn verifier_pid(&self) -> ParticipantIdentifier {
        self.verifier_pid
    }
}

fn generate_challenge_bytes<C: CurveTrait>(
    input: &PiAffgStarInput<C>,
    commitments: Vec<u8>,
    context: &impl ProofContext,
    transcript: &mut Transcript,
) -> Result<Vec<u8>> {
    transcript.append_message(b"PiAffgStar ProofContext", &context.as_bytes()?);
    transcript.append_message(b"PiAffgStar Common input", &serialize!(&input)?);
    transcript.append_message(b"PiAffgStar Commitments", &commitments);
    // Extract challenge bytes from the transcript.
    let mut challenges = [0u8; SECURITY_PARAM];
    transcript.challenge_bytes(b"Challenges", challenges.as_mut_slice());
    Ok(challenges.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        curve::{CurveTrait, TestCurve as C},
        paillier::DecryptionKey,
        utils::{random_plusminus, random_plusminus_by_size_with_minimum, testing::init_testing},
        zkp::BadContext,
    };
    use rand::{rngs::StdRng, Rng, SeedableRng};

    type PiAffgStarProof = super::PiAffgStarProof<C>;
    type PiAffgStarInput<'a> = super::PiAffgStarInput<'a, C>;

    type TestFn = fn(PiAffgStarProof, PiAffgStarInput) -> Result<()>;

    fn transcript() -> Transcript {
        Transcript::new(b"random_paillier_affg_star_proof")
    }

    fn with_random_paillier_affg_star_proof<R: RngCore + CryptoRng>(
        rng: &mut R,
        x: &BigNumber,
        y: &BigNumber,
        mut test_code: impl FnMut(PiAffgStarProof, PiAffgStarInput) -> Result<()>,
    ) -> Result<()> {
        let (decryption_key_0, _, _) = DecryptionKey::new(rng).unwrap();
        let pk0 = decryption_key_0.encryption_key();

        let (decryption_key_1, _, _) = DecryptionKey::new(rng).unwrap();
        let pk1 = decryption_key_1.encryption_key();

        let mult_coeff_exp = C::GENERATOR.multiply_by_bignum(x)?;
        let (add_coeff_ciphertext_prover, rho_y) = pk1
            .encrypt(rng, y)
            .map_err(|_| InternalError::InternalInvariantFailed)?;

        let original_ciphertext_verifier = pk0.random_ciphertext(rng);

        let (transformed_ciphertext_verifier, rho) = {
            let (transformed_ciphertext_verifier_intermediate, rho) =
                pk0.encrypt(rng, &-y).unwrap();
            let transformed_ciphertext_verifier = pk0
                .multiply_and_add(
                    x,
                    &original_ciphertext_verifier,
                    &transformed_ciphertext_verifier_intermediate,
                )
                .unwrap();
            (transformed_ciphertext_verifier, rho)
        };

        let input = PiAffgStarInput::new(
            &pk0,
            &pk1,
            &original_ciphertext_verifier,
            &transformed_ciphertext_verifier,
            &add_coeff_ciphertext_prover,
            &mult_coeff_exp,
            ParticipantIdentifier::from_u128(0),
        );
        let secret = PiAffgStarSecret::new(x, y, &rho, &rho_y);

        let proof = PiAffgStarProof::prove(input, secret, &(), &mut transcript(), rng)?;
        test_code(proof, input)?;
        Ok(())
    }

    fn random_paillier_affg_star_verified_proof<R: RngCore + CryptoRng>(
        rng: &mut R,
        x: &BigNumber,
        y: &BigNumber,
    ) -> Result<()> {
        let f: TestFn = |proof, input| proof.verify(input, &(), &mut transcript());
        with_random_paillier_affg_star_proof(rng, x, y, f)
    }

    #[test]
    fn piaffg_star_proof_with_inconsistent_secret_inputs() -> Result<()> {
        let mut rng = init_testing();
        let x = random_plusminus_by_size(&mut rng, ELL);
        let y = random_plusminus_by_size(&mut rng, ELL_PRIME);

        let (decryption_key_0, _, _) = DecryptionKey::new(&mut rng).unwrap();
        let pk0 = decryption_key_0.encryption_key();

        let (decryption_key_1, _, _) = DecryptionKey::new(&mut rng).unwrap();
        let pk1 = decryption_key_1.encryption_key();

        let mult_coeff_exp = C::GENERATOR.multiply_by_bignum(&x)?;
        let (add_coeff_ciphertext_prover, rho_y) = pk1
            .encrypt(&mut rng, &y)
            .map_err(|_| InternalError::InternalInvariantFailed)?;

        let original_ciphertext_verifier = pk0.random_ciphertext(&mut rng);

        let (transformed_ciphertext_verifier, rho) = {
            let (transformed_ciphertext_verifier_intermediate, rho) =
                pk0.encrypt(&mut rng, &y).unwrap();
            let transformed_ciphertext_verifier = pk0
                .multiply_and_add(
                    &x,
                    &original_ciphertext_verifier,
                    &transformed_ciphertext_verifier_intermediate,
                )
                .unwrap();
            (transformed_ciphertext_verifier, rho)
        };

        let input = PiAffgStarInput::new(
            &pk0,
            &pk1,
            &original_ciphertext_verifier,
            &transformed_ciphertext_verifier,
            &add_coeff_ciphertext_prover,
            &mult_coeff_exp,
            ParticipantIdentifier::from_u128(0),
        );
        let secret = PiAffgStarSecret::new(&x, &y, &rho, &rho_y);

        // Generate some random elements to use as replacements
        let random_bignumber = random_plusminus(&mut rng, &C::order());
        let random_nonce = Nonce::random(&mut rng, input.prover_encryption_key.modulus());

        // Swap multi coefficient with a random [`BigNumber`]
        assert_ne!(secret.mult_coeff, &random_bignumber);
        let bad_secret = PiAffgStarSecret::new(&random_bignumber, &y, &rho, &rho_y);
        let bad_proof =
            PiAffgStarProof::prove(input, bad_secret, &(), &mut transcript(), &mut rng)?;
        assert!(bad_proof.verify(input, &(), &mut transcript()).is_err());

        // Swap add coefficient with a random [`BigNumber`]
        assert_ne!(secret.add_coeff, &random_bignumber);
        let bad_secret = PiAffgStarSecret::new(&x, &random_bignumber, &rho, &rho_y);
        let bad_proof =
            PiAffgStarProof::prove(input, bad_secret, &(), &mut transcript(), &mut rng)?;
        assert!(bad_proof.verify(input, &(), &mut transcript()).is_err());

        // Swap add coefficient nonce verifier key with a random [`Nonce`]
        assert_ne!(secret.add_coeff_nonce_verifier_key, &random_nonce);
        let bad_secret = PiAffgStarSecret::new(&x, &y, &random_nonce, &rho_y);
        let bad_proof =
            PiAffgStarProof::prove(input, bad_secret, &(), &mut transcript(), &mut rng)?;
        assert!(bad_proof.verify(input, &(), &mut transcript()).is_err());

        // Swap add coefficient nonce prover key with a random [`Nonce`]
        assert_ne!(secret.add_coeff_nonce_prover_key, &random_nonce);
        let bad_secret = PiAffgStarSecret::new(&x, &y, &rho, &random_nonce);
        let bad_proof =
            PiAffgStarProof::prove(input, bad_secret, &(), &mut transcript(), &mut rng)?;
        assert!(bad_proof.verify(input, &(), &mut transcript()).is_err());
        Ok(())
    }

    #[test]
    fn test_paillier_affg_star_proof() -> Result<()> {
        let mut rng = init_testing();

        let x_small = random_plusminus_by_size(&mut rng, ELL);
        let y_small = random_plusminus_by_size(&mut rng, ELL_PRIME);
        let x_large =
            random_plusminus_by_size_with_minimum(&mut rng, ELL + EPSILON + 1, ELL + EPSILON)?;
        let y_large = random_plusminus_by_size_with_minimum(
            &mut rng,
            ELL_PRIME + EPSILON + 1,
            ELL_PRIME + EPSILON,
        )?;

        random_paillier_affg_star_verified_proof(&mut rng, &x_small, &y_small)?;

        assert!(random_paillier_affg_star_verified_proof(&mut rng, &x_small, &y_large).is_err());
        assert!(random_paillier_affg_star_verified_proof(&mut rng, &x_large, &y_small).is_err());
        assert!(random_paillier_affg_star_verified_proof(&mut rng, &x_large, &y_large).is_err());

        Ok(())
    }
}
