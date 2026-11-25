//! Types and functions related to the key generation sub-protocol Participant.

// Copyright (c) Facebook, Inc. and its affiliates.
// Modifications Copyright (c) 2022-2023 Bolt Labs Holdings, Inc
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use std::fmt::Debug;

use crate::{
    errors::{InternalError, Result},
    local_storage::{storage as local_storage, LocalStorage, TypeTag},
    messages::{Message, MessageType},
    protocol::ProtocolType,
    Identifier, Participant, ParticipantConfig, ParticipantIdentifier,
};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use tracing::error;

#[derive(Serialize, Deserialize)]
pub enum ProcessOutcome<O> {
    /// The protocol round is complete. Contains the outgoing messages that must be
    /// delivered to participants to begin the next round.
    Continue(Vec<Message>),
    /// The protocol has terminated. This is the final output.
    Done(O),
}

impl<O> Debug for ProcessOutcome<O> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let descriptor = match self {
            ProcessOutcome::Continue(_) => "Continue",
            ProcessOutcome::Done(_) => "Done",
        };
        write!(f, "ProcessOutcome::{descriptor}")
    }
}

impl<O> ProcessOutcome<O>
where
    O: std::fmt::Debug,
{
    /// Check if the protocol is done
    pub(crate) fn is_done(&self) -> bool {
        match self {
            Self::Done(_) => true,
            _ => false,
        }
    }

    /// Check if the protocol is continuing
    pub(crate) fn is_continuing(&self) -> bool {
        match self {
            Self::Continue(_) => true,
            _ => false,
        }
    }

    /// Extract the final output if the protocol is done
    pub(crate) fn into_output(self) -> Option<O> {
        match self {
            Self::Done(output) => Some(output),
            _ => None,
        }
    }

    /// Extract the messages if the protocol is continuing
    pub(crate) fn into_messages(self) -> Option<Vec<Message>> {
        match self {
            Self::Continue(messages) => Some(messages),
            _ => None,
        }
    }
}

pub trait ProtocolParticipant {
    /// Input type for a new protocol instance.
    type Input: Debug;
    /// Output type of a successful protocol execution.
    type Output: Debug;

    /// Get the type of a "ready" message, signalling that a participant
    /// is ready to begin protocol execution.
    fn ready_type() -> MessageType;

    fn protocol_type() -> ProtocolType;

    fn new(
        sid: Identifier,
        id: ParticipantIdentifier,
        other_participant_ids: Vec<ParticipantIdentifier>,
        input: Self::Input,
    ) -> Result<Self>
    where
        Self: Sized;

    /// Return the participant id
    fn id(&self) -> ParticipantIdentifier;

    /// Return other Participant ids apart from the current one
    fn other_ids(&self) -> &[ParticipantIdentifier];

    /// Returns a list of all participant IDs, including `self`'s.
    fn all_participants(&self) -> Vec<ParticipantIdentifier> {
        let mut participant = self.other_ids().to_owned();
        participant.push(self.id());
        participant.to_vec()
    }

    fn process_message<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        message: &Message,
    ) -> Result<ProcessOutcome<Self::Output>>;

    /// The session identifier for the current session
    fn sid(&self) -> Identifier;
}

pub(crate) trait InnerProtocolParticipant: ProtocolParticipant {
    /// Context type that captures all relevant auxiliary information to the
    /// proof.
    type Context;

    /// Returns a reference to the participant's context.
    fn retrieve_context(&self) -> Self::Context;

    /// Returns a reference to the [`LocalStorage`] associated with this
    /// protocol.
    fn local_storage(&self) -> &LocalStorage;
    /// Returns a mutable reference to the [`LocalStorage`] associated with this
    /// protocol.
    fn local_storage_mut(&mut self) -> &mut LocalStorage;

    /// Returns a Result[`Vec<Message>`] which are intended for the other
    /// participants.
    /// This function is deprecated. Use broadcast instead.
    // fn message_for_other_participants<T: Serialize>(
    //     &self,
    //     message_type: MessageType,
    //     data: T,
    // ) -> Result<Vec<Message>> {
    //     self.other_ids()
    //         .iter()
    //         .map(|&other_participant_id| {
    //             Message::new(
    //                 message_type,
    //                 self.sid(),
    //                 self.id(),
    //                 Some(other_participant_id),
    //                 None,
    //                 &data,
    //             )
    //         })
    //         .collect()
    // }

    /// Retrieves an item from [`LocalStorage`] associated with the given
    /// [`TypeTag`]. If the entry is not found in storage, we populate the
    /// storage with its [`Default`].
    fn get_from_storage<T: TypeTag>(&mut self) -> Result<&mut T::Value>
    where
        T::Value: Default,
    {
        let pid = self.id();
        if !self.local_storage_mut().contains::<T>(pid) {
            self.local_storage_mut().store::<T>(pid, Default::default());
        }
        self.local_storage_mut()
            .retrieve_mut::<T>(pid)
            .ok_or_else(|| {
                error!(
                    "Failed to retrieve {} mutably from storage",
                    std::any::type_name::<T::Value>()
                );
                InternalError::InternalInvariantFailed
            })
    }

    fn write_progress(&mut self, func_name: String) -> Result<()> {
        let progress_storage = self.get_from_storage::<local_storage::ProgressStore>()?;
        let _ = progress_storage.insert(func_name);
        Ok(())
    }

    fn read_progress(&mut self, func_name: String) -> Result<bool> {
        let progress_storage = self.get_from_storage::<local_storage::ProgressStore>()?;
        Ok(progress_storage.get(&func_name).is_some())
    }
}
