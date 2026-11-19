use crate::{
    auxinfo,
    curve::CurveTrait,
    errors::{CallerError, InternalError, Result},
    tshare::{self},
    ParticipantConfig, ParticipantIdentifier,
};
use serde::{Deserialize, Serialize};

/// Input needed for a
/// [`RecoverTargetParticipant`]
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TargetInput {
    /// How many parties are needed to sign.
    threshold: usize,
    /// The participant IDs of the helper parties.
    helper_pids: Vec<ParticipantIdentifier>,
    /// The result of the `auxinfo` protocol, which must be re-run for the target participant.
    /// This contains the new Paillier keys required to decrypt shares sent by helpers during recovery.
    auxinfo_output: auxinfo::Output,
}

/// Input needed for a
/// [`RecoverHelperParticipant`]
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(bound = "C: CurveTrait")]
pub struct HelperInput<C: CurveTrait> {
    /// How many parties are needed to sign.
    threshold: usize,
    /// The participant IDs of other helper parties.
    other_helper_pids: Vec<ParticipantIdentifier>,
    /// The participant ID of the target participant.
    target_pid: ParticipantIdentifier,
    /// The shares of the helper participant.
    tshare: tshare::Output<C>,
    /// The result of the `auxinfo` protocol, which must be re-run for the target participant.
    /// This contains the new Paillier keys required to encrypt shares during recovery.
    auxinfo_output: auxinfo::Output,
}

impl TargetInput {
    pub fn new(
        threshold: usize,
        helper_pids: Vec<ParticipantIdentifier>,
        auxinfo_output: auxinfo::Output,
    ) -> Self {
        Self {
            threshold,
            helper_pids,
            auxinfo_output,
        }
    }

    pub fn threshold(&self) -> usize {
        self.threshold
    }

    pub fn helper_pids(&self) -> &[ParticipantIdentifier] {
        self.helper_pids.as_ref()
    }

    pub fn auxinfo_output(&self) -> &auxinfo::Output {
        &self.auxinfo_output
    }
}

impl<C: CurveTrait> HelperInput<C> {
    pub fn new(
        threshold: usize,
        other_helper_pids: Vec<ParticipantIdentifier>,
        target_pid: ParticipantIdentifier,
        tshare: tshare::Output<C>,
        auxinfo_output: auxinfo::Output,
    ) -> Self {
        Self {
            threshold,
            other_helper_pids,
            target_pid,
            tshare,
            auxinfo_output,
        }
    }

    pub fn threshold(&self) -> usize {
        self.threshold
    }

    pub fn target_pid(&self) -> &ParticipantIdentifier {
        &self.target_pid
    }

    pub fn tshare(&self) -> &tshare::Output<C> {
        &self.tshare
    }

    pub fn auxinfo_output(&self) -> &auxinfo::Output {
        &self.auxinfo_output
    }

    pub fn other_helper_pids(&self) -> &[ParticipantIdentifier] {
        &self.other_helper_pids
    }
}
