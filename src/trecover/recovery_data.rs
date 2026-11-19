use serde::{Deserialize, Serialize};

use crate::{curve::CurveTrait, keygen::KeySharePublic, paillier::Ciphertext};

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound = "C: CurveTrait")]
pub struct RecoveryData<C: CurveTrait> {
    /// Helper's share * L_H(T) + (Helper 간 주고받은 비밀값)
    pub recovery_fragment: Ciphertext,
    /// Helper가 알고 있는 전체 참여자의 public key share 목록
    pub public_key_shares: Vec<KeySharePublic<C>>,
    /// Helper가 알고 있는 전체 rid
    pub rid: [u8; 32],
    /// threshold 값
    pub threshold: usize,
}

impl<C: CurveTrait> RecoveryData<C> {
    pub fn new(
        recovery_fragment: Ciphertext,
        public_key_shares: Vec<KeySharePublic<C>>,
        rid: [u8; 32],
        threshold: usize,
    ) -> Self {
        Self {
            recovery_fragment,
            public_key_shares,
            rid,
            threshold,
        }
    }
}
