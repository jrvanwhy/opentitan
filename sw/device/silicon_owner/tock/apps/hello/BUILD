# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

load("@rules_rust//rust:defs.bzl", "rust_binary")
load("//rules/opentitan:defs.bzl", "EARLGREY_SILICON_OWNER_ROM_EXT_ENVS", "OPENTITAN_CPU", "cw310_params", "fpga_params", "opentitan_test", "silicon_params")
load("//rules:tock.bzl", "tock_elf2tab", "tock_image")

package(default_visibility = ["//visibility:public"])

rust_binary(
    name = "hello",
    srcs = [
        "src/hello.rs",
    ],
    # We specifically restrict our build target to the OpenTitan
    # CPU because libtock does not support an x86_64 target.
    target_compatible_with = [OPENTITAN_CPU],
    deps = [
        "//sw/device/silicon_owner/tock/apps:single_app_layout",
        "@libtock",
    ],
)

tock_elf2tab(
    name = "tab",
    src = ":hello",
    arch = "rv32imc",
)

tock_image(
    name = "image",
    apps = [":tab"],
    kernel = "//sw/device/silicon_owner/tock/kernel",
    manifest = "//sw/device/silicon_owner:manifest",
    rsa_key = {"//sw/device/silicon_creator/rom_ext/sival/keys:keyset": "earlgrey_z0_sival_1"},
)
