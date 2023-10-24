# Copyright lowRISC contributors.
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

load("@rules_rust//rust:defs.bzl", "rust_binary")
load("//rules/opentitan:defs.bzl", "OPENTITAN_CPU", "cw310_params", "opentitan_test")
load("//rules:tock.bzl", "tock_elf2tab", "tock_image")

package(default_visibility = ["//visibility:public"])

rust_binary(
    name = "syscall_tunnel",
    srcs = [
        "src/allow.rs",
        "src/main.rs",
        "src/tx_queue.rs",
    ],
    # We specifically restrict our build target to the OpenTitan
    # CPU because libtock does not support an x86_64 target.
    target_compatible_with = [OPENTITAN_CPU],
    deps = [
        "//sw/device/silicon_owner/tock/apps:single_app_layout",
        "@libtock",
        "@tock_index//:serde-json-core",
    ],
)

tock_elf2tab(
    name = "tab",
    src = ":syscall_tunnel",
    arch = "rv32imc",
)

tock_image(
    name = "image",
    app_flash_start = 0x20040000,
    apps = [":tab"],
    kernel = "//sw/device/silicon_owner/tock/kernel",
)

opentitan_test(
    name = "syscall_tunnel_test",
    cw310 = cw310_params(
        binaries = {":image": "firmware"},
        test_cmd = """
            --bitstream="{bitstream}"
            --bootstrap="{firmware}"
        """,
        test_harness = "//sw/host/tests/tock/syscall_tunnel",
    ),
    exec_env = {
        "//hw/top_earlgrey:fpga_cw310_test_rom": None,
    },
)
