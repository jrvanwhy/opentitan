# Copyright lowRISC contributors.
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

load("@rules_rust//rust:defs.bzl", "rust_library")

package(default_visibility = ["//visibility:public"])

rust_library(
    name = "syscall_tunnel_defs",
    srcs = [
        "src/lib.rs",
    ],
    deps = [
        "@crate_index//:serde",
    ],
)
