// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
pub enum DeviceToHost {
    // TODO: Unconditionally returning r1, r2, and r3 doesn't seem ideal.
    CommandOut([u32; 4]),
}

#[derive(Deserialize, Serialize)]
pub enum HostToDevice {
    Command { driver: u32, command: u32, arg0: u32, arg1: u32 },
    Subscribe { upcall_idx: u8, driver_num: u32, subscribe_num: u32 },
}
