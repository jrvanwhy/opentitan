// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use anyhow::Result;
use std::time::Duration;

use crate::io::uart::Uart;
use crate::test_utils::e2e_command::TestCommand;
use crate::test_utils::rpc::{UartRecv, UartSend};
use crate::test_utils::status::Status;

// Bring in the auto-generated sources.
include!(env!("spi_passthru"));

impl ConfigJedecId {
    pub fn execute(&self, uart: &dyn Uart) -> Result<()> {
        TestCommand::SpiConfigureJedecId.send(uart)?;
        self.send(uart)?;
        Status::recv(uart, Duration::from_secs(300), false)?;
        Ok(())
    }
}
