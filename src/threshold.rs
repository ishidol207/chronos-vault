use bytemuck::checked::from_bytes;
use k256::elliptic_curve::point;
use num_bigint::BigUint;
use std::marker::PhantomData;

use crate::{
    curve::{CurveTrait, ScalarTrait},
    errors::{CallerError, InternalError, Result},
    keygen::{KeySharePrivate, KeySharePublic, KeygenParticipant},
    tshare, ParticipantIdentifier, ProtocolParticipant,
};

pub struct ToutofTHelper<C: CurveTrait> {
    _marker: PhantomData<C>,
}

impl<C: CurveTrait> ToutofTHelper<C> {
    pub fn new() -> Self {
        Self {
            _marker: PhantomData,
        }
    }

    pub fn convert_to_t_out_of_t_share(
        my_id: &ParticipantIdentifier,
        signers_participants: &[ParticipantIdentifier],
        tshare: &tshare::Output<C>,
        rid: [u8; 32],
    ) -> Result<<KeygenParticipant<C> as ProtocolParticipant>::Output> {
        let public_key_shares = signers_participants
            .iter()
            .map(|pid| {
                let public_t_of_n = tshare
                    .public_key_shares()
                    .iter()
                    .find(|x| x.participant() == *pid)
                    .expect("public key share not found");

                let lagrange = Self::lagrange_coefficient_at_zero(pid, signers_participants);

                let public_t_of_t = public_t_of_n.as_ref().multiply_by_scalar(&lagrange);
                KeySharePublic::new(*pid, public_t_of_t)
            })
            .collect::<Vec<_>>();

        let private_key_share = {
            let lagrange = Self::lagrange_coefficient_at_zero(my_id, signers_participants);
            let private_t_of_t = tshare.private_key_share().mul(&lagrange);
            KeySharePrivate::from_bigint(&C::scalar_to_bn(&private_t_of_t))
        };
        crate::keygen::Output::from_parts(public_key_shares, private_key_share, rid)
    }

    /// Lagrange coefficent 계산
    /// L_i(x) = Π_{j ∈ S, j ≠ i} (x - j) / (i - j)
    pub fn lagrange_coefficient(
        eval_point: C::Scalar,            // x
        my_point: &ParticipantIdentifier, // i
        points: &[ParticipantIdentifier], // J
    ) -> C::Scalar {
        let mut result = C::Scalar::one();
        let my_point_coord = &Self::participant_coordinate(*my_point);

        for point in points {
            if point != my_point {
                let point_coord = &Self::participant_coordinate(*point);
                let numerator = eval_point.sub(point_coord);
                let denominator = my_point_coord.sub(point_coord);
                let inv = denominator.invert().unwrap();
                result.mul_assign(&numerator.mul(&inv));
            }
        }
        result
    }

    /// Lagrange coefficient at zero
    pub fn lagrange_coefficient_at_zero(
        my_point: &ParticipantIdentifier,
        points: &[ParticipantIdentifier],
    ) -> C::Scalar {
        let zero = C::Scalar::zero();
        Self::lagrange_coefficient(zero, my_point, points)
    }

    /// Assign a non-null x coordinate to each participant.
    pub fn participant_coordinate(pid: ParticipantIdentifier) -> C::Scalar {
        C::Scalar::convert_from_u128(pid.as_u128()).add(&C::Scalar::one())
    }

    // /// share로부터 다항식의 계수 복구
    // /// todo: FFT 사용?
    // pub fn reconstruct_coefficients(
    //     shares: &[(ParticipantIdentifier, C::Scalar)],
    // ) -> Result<Vec<C::Scalar>> {
    //     let t = shares.len();
    //     if t == 0 {
    //         return Err(CallerError::BadInput.into());
    //     }
    //     let mut final_coeffs = vec![C::Scalar::zero(); t];
    //     let points: Vec<ParticipantIdentifier> = shares.iter().map(|(pid, _)| *pid).collect();
    //     for (i, (my_pid, my_share)) in shares.iter().enumerate() {
    //         let my_coord = Self::participant_coordinate(*my_pid);

    //         // 분자 Π_{j ≠ i} (x - x_j)
    //         let mut numerator_coeffs = vec![C::Scalar::one()];
    //         for (j, other_pid) in points.iter().enumerate() {
    //             if i == j {
    //                 continue;
    //             }
    //             let other_coord = Self::participant_coordinate(*other_pid);
    //             let term_poly = vec![C::Scalar::zero().sub(&other_coord), C::Scalar::one()];
    //             numerator_coeffs = Self::mul_poly(&numerator_coeffs, &term_poly)?;
    //         }

    //         //분모  Π_{j ≠ i} (i - x_j)
    //         let mut denominator = C::Scalar::one();
    //         for (j, other_pid) in points.iter().enumerate() {
    //             if i == j {
    //                 continue;
    //             }
    //             let other_coord = Self::participant_coordinate(*other_pid);
    //             denominator.mul_assign(&my_coord.sub(&other_coord));
    //         }

    //         //  L_i(x)의 계수
    //         let inv_denominator = denominator.invert().unwrap();
    //         let li_coeffs: Vec<C::Scalar> = numerator_coeffs
    //             .iter()
    //             .map(|c| c.mul(&inv_denominator))
    //             .collect();

    //         for k in 0..li_coeffs.len() {
    //             let term = my_share.mul(&li_coeffs[k]);
    //             final_coeffs[k] = final_coeffs[k].add(&term);
    //         }
    //     }

    //     Ok(final_coeffs)
    // }

    // // 두 다항식을 곱하는 함수
    // // 다항식은 계수의 벡터(상수항부터)로 표현
    // fn mul_poly(p1: &[C::Scalar], p2: &[C::Scalar]) -> Result<Vec<C::Scalar>> {
    //     if p1.is_empty() || p2.is_empty() {
    //         return Err(CallerError::BadInput.into());
    //     }
    //     let mut result = vec![C::Scalar::zero(); p1.len() + p2.len() - 1];
    //     for i in 0..p1.len() {
    //         for j in 0..p2.len() {
    //             let term = p1[i].mul(&p2[j]);
    //             result[i + j] = result[i + j].add(&term);
    //         }
    //     }
    //     Ok(result)
    // }
}
