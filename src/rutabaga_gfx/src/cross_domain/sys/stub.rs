// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fs::File;
use std::sync::Arc;

use super::super::cross_domain_protocol::CrossDomainInitV1;
use super::super::cross_domain_protocol::CrossDomainSendReceiveBase;
use super::super::CrossDomainContext;
use super::super::CrossDomainState;
use crate::cross_domain::CrossDomainEvent;
use crate::cross_domain::CrossDomainToken;
use crate::rutabaga_utils::RutabagaError;
use crate::rutabaga_utils::RutabagaResult;

pub struct Stub(());
pub type SystemStream = Stub;

impl CrossDomainState {
    pub(crate) fn receive_msg<const MAX_IDENTIFIERS: usize>(
        &self,
        _opaque_data: &mut [u8],
    ) -> RutabagaResult<(usize, Vec<File>)> {
        Err(RutabagaError::Unsupported)
    }
}

impl CrossDomainContext {
    pub(crate) fn get_connection(
        &mut self,
        _cmd_init: &CrossDomainInitV1,
    ) -> RutabagaResult<Option<SystemStream>> {
        Err(RutabagaError::Unsupported)
    }

    pub(crate) fn send<T: CrossDomainSendReceiveBase, const MAX_IDENTIFIERS: usize>(
        &self,
        _cmd_send: &mut T,
        _opaque_data: &[u8],
    ) -> RutabagaResult<()> {
        Err(RutabagaError::Unsupported)
    }
}

pub type Sender = Stub;
pub type Receiver = Stub;

pub fn channel_signal(_sender: &Sender) -> RutabagaResult<()> {
    Err(RutabagaError::Unsupported)
}

pub fn channel_wait(_receiver: &Receiver) -> RutabagaResult<()> {
    Err(RutabagaError::Unsupported)
}

pub fn read_volatile(_file: &File, _opaque_data: &mut [u8]) -> RutabagaResult<usize> {
    Err(RutabagaError::Unsupported)
}

pub fn write_volatile(_file: &File, _opaque_data: &[u8]) -> RutabagaResult<()> {
    Err(RutabagaError::Unsupported)
}

pub fn channel() -> RutabagaResult<(Sender, Receiver)> {
    Err(RutabagaError::Unsupported)
}

pub type WaitContext = Stub;

pub trait WaitTrait {}
impl WaitTrait for Stub {}
impl WaitTrait for &Stub {}
impl WaitTrait for Arc<Stub> {}
impl WaitTrait for File {}
impl WaitTrait for &File {}
impl WaitTrait for &mut File {}

impl WaitContext {
    pub fn new() -> RutabagaResult<WaitContext> {
        Err(RutabagaError::Unsupported)
    }

    pub fn add<Waitable: WaitTrait>(
        &mut self,
        _token: CrossDomainToken,
        _waitable: Waitable,
    ) -> RutabagaResult<()> {
        Err(RutabagaError::Unsupported)
    }

    pub fn wait(&mut self) -> RutabagaResult<Vec<CrossDomainEvent>> {
        Err(RutabagaError::Unsupported)
    }

    pub fn delete<Waitable: WaitTrait>(
        &mut self,
        _token: CrossDomainToken,
        _waitable: Waitable,
    ) -> RutabagaResult<()> {
        Err(RutabagaError::Unsupported)
    }
}
