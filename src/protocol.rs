use crate::{
    curve::CurveTrait,
    errors::{CallerError, InternalError, Result},
    messages::Message,
    participant::{InnerProtocolParticipant, ProtocolParticipant},
    protocol::participant_config::ParticipantConfig,
    zkp::ProofContext,
};
use libpaillier::unknown_order::BigNumber;
use rand::{CryptoRng, Rng, RngCore};
use serde::{Deserialize, Serialize};
use std::{
    cmp::{Ord, PartialOrd},
    fmt::{Debug, Formatter},
};
use tracing::{error, info, instrument, trace};

#[derive(Debug)]
pub enum ProtocolType {
    Keygen,
    Tshare,
    Keyrefresh,
    AuxInfo,
    Presign,
    Broadcast,
    Sign,
    InteractiveSign,
    Trefresh,
    Tpresign,
    TpresignAbort,
    Trecover,
}

#[derive(Debug)]
pub struct Participant<P>
where
    P: ProtocolParticipant,
{
    /// An identifier for this participant.
    id: ParticipantIdentifier,

    /// The [`ProtocolParticipant`] driver defining the actual protocol
    /// execution.
    participant: P,
}

impl<P: ProtocolParticipant> Participant<P> {
    /// Initialize the participant from a [`ParticipantConfig`].
    pub fn from_config(
        config: ParticipantConfig,
        sid: Identifier,
        input: P::Input,
    ) -> Result<Self> {
        info!("Initializing participant from config.");

        let (id, other_ids) = config.into_parts();

        Ok(Participant {
            id,
            participant: P::new(sid, id, other_ids, input)?,
        })
    }

    /// Retrieve the [`ParticipantIdentifier`] for this `Participant`.
    pub fn id(&self) -> ParticipantIdentifier {
        self.id
    }

    /// Retrieve the unique session [`Identifier`] for this `Participant`.
    pub fn sid(&self) -> Identifier {
        self.participant.sid()
    }

    /// Produce a message to signal to this participant that the protocol can
    /// begin.
    #[instrument(skip_all)]
    pub fn initialize_message(&self) -> Result<Message> {
        info!("Initializing subprotocol.");
        let empty: [u8; 0] = [];
        Message::new(
            P::ready_type(),
            self.sid(),
            self.id,
            Some(self.id),
            false,
            &empty,
        )
    }
}

pub(crate) mod participant_config {
    use std::collections::HashSet;

    use super::*;

    /// The configuration for the participant.
    ///
    /// Contains a set of at least two unique participant identifiers.
    #[derive(Debug, Clone, Serialize, Deserialize, Default)]
    pub struct ParticipantConfig {
        /// The identifier for this participant.
        id: ParticipantIdentifier,
        /// The identifier for the other participants executing the protocol.
        other_ids: Vec<ParticipantIdentifier>,
    }

    impl ParticipantConfig {
        /// Get the [`ParticipantIdentifier`] for the owner of this config.
        pub fn id(&self) -> ParticipantIdentifier {
            self.id
        }

        /// Get the [`ParticipantIdentifier`] for all other participants.
        pub fn other_ids(&self) -> &[ParticipantIdentifier] {
            self.other_ids.as_slice()
        }

        /// Returns a list of all participant IDs, including `self`'s.
        pub fn all_participants(&self) -> Vec<ParticipantIdentifier> {
            let mut participant = self.other_ids().to_owned();
            participant.push(self.id());
            participant
        }

        /// Returns the total number of participants specified in the config
        /// (both other and self).
        pub fn count(&self) -> usize {
            self.other_ids.len() + 1
        }

        pub(crate) fn into_parts(self) -> (ParticipantIdentifier, Vec<ParticipantIdentifier>) {
            (self.id, self.other_ids)
        }

        /// Create a new [`ParticipantConfig`].
        ///
        /// The protocol requires at least two participants; `other_ids` cannot
        /// be empty. All participant identifiers must be unique.
        pub fn new(id: ParticipantIdentifier, other_ids: &[ParticipantIdentifier]) -> Result<Self> {
            if other_ids.is_empty() {
                error!(
                    "Tried to create a participant config with too few participants. There must be at least one `other_id`.",
                );
                Err(CallerError::ParticipantConfigError)?
            }

            // Test for uniqueness
            let unique_set =
                HashSet::<&ParticipantIdentifier>::from_iter(std::iter::once(&id).chain(other_ids));
            if unique_set.len() != other_ids.len() + 1 {
                error!(
                    "Tried to create a participant config with a non-unique set of participants"
                );
                Err(CallerError::ParticipantConfigError)?
            }

            Ok(Self {
                id,
                other_ids: other_ids.to_vec(),
            })
        }

        /// Returns a new [`ParticipantConfig`] including only the given
        /// participants.
        pub fn filter_participants(&self, pids: &[ParticipantIdentifier]) -> Self {
            let other_ids = self
                .other_ids()
                .iter()
                .filter(|pid| pids.contains(pid))
                .cloned()
                .collect();
            Self {
                id: self.id,
                other_ids,
            }
        }

        /// Get a list of `size` consistent [`ParticipantConfig`]s.
        ///
        /// Each config contains a different permutation of a single overall set
        /// of [`ParticipantIdentifier`]s.
        ///
        /// **⚠️ Security warning:** This method implies the existence of a
        /// trusted third party that generates the participant IDs. This
        /// method must not be used if your deployment does not have a
        /// trusted party.
        pub fn random_quorum<R: RngCore + CryptoRng>(
            size: usize,
            rng: &mut R,
        ) -> Result<Vec<ParticipantConfig>> {
            if size < 2 {
                Err(CallerError::ParticipantConfigError)?
            }
            let ids = std::iter::repeat_with(|| ParticipantIdentifier::random(rng))
                .take(size)
                .collect::<Vec<_>>();

            (0..size)
                .map(|i| {
                    let mut other_ids = ids.clone();
                    let id = other_ids.swap_remove(i);
                    Self::new(id, other_ids.as_slice())
                })
                .collect::<Result<_>>()
        }

        ///Create a random [`ParticipantConfig`].
        #[cfg(test)]
        pub(crate) fn random<R: RngCore + CryptoRng>(
            size: usize,
            rng: &mut R,
        ) -> ParticipantConfig {
            assert!(size > 1);
            let other_ids = std::iter::repeat_with(|| ParticipantIdentifier::random(rng))
                .take(size - 1)
                .collect::<Vec<_>>();
            let id = ParticipantIdentifier::random(rng);
            Self { id, other_ids }
        }

        /// Remove id from ParticipantConfig
        pub fn remove(&self) -> Result<Vec<ParticipantConfig>> {
            assert!(self.other_ids.len() > 1);
            let other_ids = self.other_ids();
            // for each element in other_ids, create a new ParticipantConfig
            // with that element as the id
            other_ids
                .iter()
                .enumerate()
                .map(|(i, id)| {
                    let mut others = other_ids.to_vec();
                    let _removed = others.swap_remove(i);
                    Self::new(*id, &others[..])
                })
                .collect::<Result<Vec<ParticipantConfig>>>()
        }
    }
}

/// An identifier for a [`Participant`].
///
/// All [`Participant`]s in a sub-protocol must agree on the
/// [`ParticipantIdentifier`]s. That is, these are not local identifiers
/// controlled by a single `Participant`; they are unique, agreed-upon
/// identifiers for *all* the `Participant`s executing a sub-protocol. Each
/// member participating in a sub-protocol should have a different
/// `ParticipantIdentifier`.
///
/// The set of [`ParticipantIdentifier`]s are forever associated with a key and
/// must remain the same throughout all (sub-protocol) operations on that key.
/// For example, if a set of participants run keygen, aux-info, and then compute
/// several signatures, they must use the same set of identifiers throughout.
///
/// These `ParticipantIdentifier`s are embedded in the output
/// of our key operations. For example: this library will check the expected
/// `ParticipantIdentifier` from the aux-info output against the
/// `ParticipantIdentifier` of the `Participant` object executing the
/// sub-protocol. An error will be returned if they don't match. It is up to the
/// calling application to remember and use the expected `ParticipantIdentifier`
/// when executing sub-protocols.
///
/// A single `ParticipantIdentifier` should not be used
/// to represent different participants (even in different sub-protocols with
/// non-overlapping participant sets!).
///
/// `ParticipantIdentifier`s should be unique within a deployment, but they
/// don't necessarily have to be globally unique. `ParticipantIdentifier`s may
/// be re-used to execute multiple, unrelated, tss-ecdsa sub-protocols.
#[derive(
    Debug, Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, Default,
)]
pub struct ParticipantIdentifier(u128);

impl ParticipantIdentifier {
    /// Generates a random [`ParticipantIdentifier`].
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        // Sample random 32 bytes and convert to hex
        let random_bytes = rng.gen::<u128>();
        let pid = Self(random_bytes);
        trace!("Created new {}", pid);
        pid
    }

    /// Note: This method is for convenience only. The `id` value is still
    /// expected to be generated from a cryptographically secure generator,
    /// for example [`Self::random`].
    pub fn from_u128(id: u128) -> Self {
        Self(id)
    }

    pub fn from_u64(id: u64) -> Self {
        Self(id as u128)
    }

    pub fn from_u64_slice(ids: &[u64]) -> Vec<Self> {
        ids.iter().map(|&id| Self::from_u64(id)).collect()
    }

    /// Get the ID as a number.
    pub fn as_u128(&self) -> u128 {
        self.0
    }
}

impl std::fmt::Display for ParticipantIdentifier {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        // 16 byte number. Take last five bytes for display purposes.
        let last_bytes = &self.0.to_be_bytes()[11..];
        write!(f, "ParticipantId(0x{})", hex::encode(last_bytes))
    }
}

/// The `SharedContext` contains fixed known parameters across the entire
/// protocol. It does not however contain the entire protocol context.
#[derive(Debug, Clone)]
pub(crate) struct SharedContext<C> {
    sid: Identifier,
    participants: Vec<ParticipantIdentifier>,
    generator: C,
    order: BigNumber,
}

impl<C: CurveTrait> ProofContext for SharedContext<C> {
    fn as_bytes(&self) -> Result<Vec<u8>> {
        Ok([
            self.sid.0.to_be_bytes().into_iter().collect(),
            self.participants
                .iter()
                .flat_map(|pid| pid.0.to_le_bytes())
                .collect(),
            bincode::serialize(&self.generator)
                .map_err(|_| InternalError::InternalInvariantFailed)?,
            self.order.to_bytes(),
        ]
        .concat())
    }
}

impl<C: CurveTrait> SharedContext<C> {
    /// This function should not be used outside of the tests.
    #[cfg(test)]
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let sid = Identifier::random(rng);
        let participant = ParticipantIdentifier::random(rng);
        let participant2 = ParticipantIdentifier::random(rng);
        let participants = vec![participant, participant2];
        let generator = C::GENERATOR;
        let order = C::order();
        SharedContext {
            sid,
            participants,
            generator,
            order,
        }
    }

    #[cfg(test)]
    pub fn fill_context(mut participants: Vec<ParticipantIdentifier>, sid: Identifier) -> Self {
        participants.sort();
        SharedContext {
            sid,
            participants,
            generator: C::GENERATOR,
            order: C::order(),
        }
    }

    pub(crate) fn collect<P: InnerProtocolParticipant>(p: &P) -> Self {
        let mut participants = p.all_participants();
        participants.sort();
        let generator = C::GENERATOR;
        let order = C::order();
        SharedContext {
            sid: p.sid(),
            participants,
            generator,
            order,
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
/// A session [`Identifier`] uniquely identifies a single
/// instance of a sub-protocol and all messages associated with it.
///
/// Session identifiers have two roles in the protocol: they tag messages
/// and they are incorporated as context into zero-knowledge proofs.
/// They must be _globally unique_; this allows participants to distinguish
/// messages belonging to different, concurrent sub-protocol runs,
/// prevents collisions between messages belonging to
/// different sessions, and prevents replay attacks by associating messages and
/// zero-knowledge proofs
/// with the session, fixed parameters, and previous subprotocols to which
/// they correspond. Global uniqueness is required in order to achieve
/// universally-composable (UC) security, the paradigm used by the paper to
/// prove security of the protocol.
///
/// 🔒 It is the responsibility of the calling application to pick session
/// identifiers. The calling application must select a protocol with
/// appropriate trust assumptions for its deployment to ensure the chosen
/// [`Identifier`] is unique and that all parties have the same one.
/// Sample protocols (with varying trust models!) could include:
/// - A trusted party randomly samples a unique identifier with
///   `Identifier::random()` and sends it to all parties;
/// - The participants run a Byzantine agreement protocol.
///
/// # Discrepancies with the paper with respect to session identifiers:
/// The paper defines session identifiers, denoted `sid` and `ssid`, somewhat
/// differently that we implement them in this codebase. We believe the
/// implementation achieves the same guarantees that the paper describes.
///
/// 1. The paper incorporates many types of data into its session and
/// sub-session identifiers, including fixed parameters, the participant set,
/// and key- and party-specific parameters that the calling application
/// persists[^outs]; these identifiers are used both to tag
/// messages and incorporate context into proofs. The codebase defines a single
/// `Identifier` type; this is a global, unique identifier
/// used to tag messages. The other fields (as well as
/// the `Identifier`) are incorporated into proofs using a different mechanism
/// to define the proof context.
///
/// 2. The paper distinguishes between identifiers for sessions (keygen) and
/// sub-sessions (auxinfo and presign)[^bug].
/// The codebase requires the calling application to select a new, unique
/// session [`Identifier`]s at three points:
/// (1) immediately before starting a new keygen session;
/// (2) immediately before starting a new auxinfo session;
/// (3) immediately before starting a new presigning session (for use in
/// presigning and the subsequent signature).
///
///
/// 3. 🔒 In the paper, `ssid` is updated each time the participants run the
/// key-refresh subprotocol.
/// The codebase relies on the calling application to generate a new, unique
/// `Identifier` for each new session.
///
/// [^outs]: These can include public key shares and shared randomness that were
/// returned as output from a previous run of keygen and public commitment
/// parameters that were returned as output from a previous run of auxinfo.
///
/// [^bug]: In fact, we think there is a minor bug in Figure 6 of the paper, since
/// the definition of `ssid` includes outputs of auxinfo, and thus cannot be
/// passed as input to auxinfo. We believe the correct instantiation of the
/// `ssid` for auxinfo is in Figure 3, which includes fixed parameters (`sid`)
/// and outputs from keygen, but _not_ outputs from auxinfo.
#[derive(Default)]
pub struct Identifier(u128);

impl Debug for Identifier {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Id({})", hex::encode(&self.0.to_le_bytes()[..4]))
    }
}

impl Identifier {
    /// Produces an [`Identifier`] chosen uniformly at random.
    ///
    /// **⚠️ Security warning:** This method implies the existence of a trusted
    /// third party that generates session IDs and correctly distributes
    /// them to all participants. This method must not be used if your
    /// deployment does not have a trusted party.
    #[instrument(skip_all)]
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        // Sample random 32 bytes and convert to hex
        let random_bytes = rng.gen::<u128>();
        trace!("Created new Session Identifier({random_bytes})");
        Self(random_bytes)
    }
}

impl From<u64> for Identifier {
    fn from(value: u64) -> Self {
        Self(value as u128)
    }
}

impl std::fmt::Display for Identifier {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "Id({})", hex::encode(&self.0.to_be_bytes()[..4]))
    }
}
