use crate::{
    curve::CurveTrait,
    errors::{InternalError, Result},
    messages::{Message, MessageType, TrecoverMessageType},
    {Identifier, ParticipantIdentifier},
};
use merlin::Transcript;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use tracing::error;

/// Public commitment to `TrecoveryDecommit` in round 1.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub(crate) struct TrecoveryCommit {
    hash: [u8; 32],
}
impl TrecoveryCommit {
    pub(crate) fn from_message(message: &Message) -> Result<Self> {
        message.check_type(MessageType::Trecover(TrecoverMessageType::R1CommitHash))?;
        let trecovery_commit: TrecoveryCommit = deserialize!(&message.unverified_bytes)?;
        Ok(trecovery_commit)
    }
}

/// Decommitment published in round 2.
#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct TrecoveryDecommit<C: CurveTrait> {
    sid: Identifier,
    randomizer: C::Scalar,
    sender: ParticipantIdentifier,
    u_i: [u8; 32], // The blinding factor is never read but it is included in the commitment.
}

impl<C: CurveTrait> TrecoveryDecommit<C> {
    pub(crate) fn new<R: RngCore + CryptoRng>(
        rng: &mut R,
        sid: Identifier,
        randomizer: C::Scalar,
        sender: ParticipantIdentifier,
    ) -> Self {
        let mut u_i = [0u8; 32];
        rng.fill_bytes(u_i.as_mut_slice());
        TrecoveryDecommit {
            sid,
            randomizer,
            sender,
            u_i,
        }
    }

    pub(crate) fn randomizer(&self) -> &C::Scalar {
        &self.randomizer
    }

    /// Deserialize a TrecoveryDecommit from a message and verify it.
    pub(crate) fn from_message(message: &Message, com: &TrecoveryCommit) -> Result<Self> {
        message.check_type(MessageType::Trecover(TrecoverMessageType::R2Decommit))?;
        let tshare_decommit: TrecoveryDecommit<C> = deserialize!(&message.unverified_bytes)?;
        tshare_decommit.verify(message.id(), message.from(), com)?;
        Ok(tshare_decommit)
    }

    pub(crate) fn commit(&self) -> Result<TrecoveryCommit> {
        let mut transcript = Transcript::new(b"TshareR1");
        transcript.append_message(b"decom", &serialize!(&self)?);
        let mut hash = [0u8; 32];
        transcript.challenge_bytes(b"hashing r1", &mut hash);
        Ok(TrecoveryCommit { hash })
    }

    fn verify(
        &self,
        sid: Identifier,
        sender: ParticipantIdentifier,
        com: &TrecoveryCommit,
    ) -> Result<()> {
        // Check the commitment.
        let rebuilt_com = self.commit()?;
        if &rebuilt_com != com {
            error!("decommitment does not match original commitment");
            return Err(InternalError::ProtocolError(Some(sender)));
        }

        // Check the session ID and sender ID.
        if self.sid != sid {
            error!("Incorrect session ID");
            return Err(InternalError::ProtocolError(Some(sender)));
        }
        if self.sender != sender {
            error!("Incorrect sender ID");
            return Err(InternalError::ProtocolError(Some(sender)));
        }

        Ok(())
    }
}
