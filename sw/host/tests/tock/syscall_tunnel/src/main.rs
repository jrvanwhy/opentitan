// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use anyhow::Result;
use clap::Parser;
use std::time::Duration;

use opentitanlib::test_utils::init::InitializeTest;
use opentitanlib::uart::console::UartConsole;
use syscall_tunnel_defs::HostToDevice;

#[derive(Debug, Parser)]
struct Opts {
    #[command(flatten)]
    init: InitializeTest,

    /// Console receive timeout.
    #[arg(long, value_parser = humantime::parse_duration, default_value = "600s")]
    timeout: Duration,
}

fn main() -> Result<()> {
    let opts = Opts::parse();
    opts.init.init_logging();
    let transport = opts.init.init_target()?;
    let uart = transport.uart("console")?;
    uart.set_flow_control(true)?;
    // TODO: Improve regex quality
    let _ = UartConsole::wait_for(&*uart, r"initialisation complete\. Entering main loop", opts.timeout)?;
    let command = HostToDevice::Command { driver: 8, command: 3, arg0: 0xAAAAAAAA, arg1: 0x55555555 };
    let json_message = serde_json::to_string(&command)?;
    println!("JSON(len={}): {}", json_message.len(), json_message);
    uart.write(&json_message.as_bytes())?;
    let _ = UartConsole::wait_for(&*uart, r"ACK 064", opts.timeout)?;
    //uart.write(&json_message.as_bytes()[64..])?;
    let _ = UartConsole::wait_for(&*uart, r"ACK 008", opts.timeout)?;
    Ok(())
}
