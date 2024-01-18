# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

load("@bazel_skylib//lib:dicts.bzl", "dicts")
load("@rules_rust//rust:defs.bzl", "rust_binary")
load("//rules:signing.bzl", "sign_binary")
load("//rules:tock.bzl", "tock_elf2tab", "tock_image")
load("//rules/opentitan:defs.bzl", "EARLGREY_SILICON_OWNER_ROM_EXT_ENVS", "OPENTITAN_CPU", "cw310_params", "fpga_params", "opentitan_test", "silicon_params")

package(default_visibility = ["//visibility:public"])

rust_binary(
    name = "basic",
    srcs = [
        "src/basic.rs",
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
    src = ":basic",
    arch = "rv32imc",
)

tock_image(
    name = "image",
    app_flash_start = 0x20040000,
    apps = [":tab"],
    kernel = "//sw/device/silicon_owner/tock/tests:test_kernel",
)

opentitan_test(
    name = "basic_test",
    exec_env = dicts.add(EARLGREY_SILICON_OWNER_ROM_EXT_ENVS, {
        "//hw/top_earlgrey:fpga_cw310_test_rom": None,
    }),
    fpga = fpga_params(
        binaries = {":image": "firmware"},
    ),
    silicon = silicon_params(
        binaries = {":image": "firmware"},
    ),
)
