# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

"""Rules for assembling Tock binaries.
"""

load("//rules/opentitan:toolchain.bzl", "LOCALTOOLS_TOOLCHAIN")
load("//rules:signing.bzl", "sign_binary")
load("@lowrisc_opentitan//rules/opentitan:exec_env.bzl", "ExecEnvInfo")
load("@lowrisc_opentitan//rules/opentitan:util.bzl", "get_fallback")
load("@rules_cc//cc:find_cc_toolchain.bzl", "find_cc_toolchain")
load(
    "//rules:rv.bzl",
    "rv_rule",
    _OPENTITAN_CPU = "OPENTITAN_CPU",
    _OPENTITAN_PLATFORM = "OPENTITAN_PLATFORM",
)
load("@tockloader_deps//:requirements.bzl", "entry_point")

TockApplication = provider(
    fields = {
        "tab": "TAB file for this application",
        "tbf": "TBF file for this application",
        "elf": "ELF file for this application",
        "flash_start": "Address at which the app image must start in flash",
    },
)

def _tock_elf2tab_impl(ctx):
    name = ctx.attr.package_name if ctx.attr.package_name else ctx.attr.name

    tabfile = ctx.actions.declare_file("{}.tab".format(name))
    tbffile = ctx.actions.declare_file("{}.tbf".format(name))

    elffile = ctx.actions.declare_file("{}.elf".format(name))
    ctx.actions.symlink(output = elffile, target_file = ctx.file.src)

    outputs = [tabfile, tbffile]
    args = [
        "--kernel-major={}".format(ctx.attr.kernel_major),
        "--kernel-minor={}".format(ctx.attr.kernel_minor),
        "--package-name={}".format(name),
        "--output-file={}".format(tabfile.path),
    ]
    if ctx.attr.protected_region_size:
        args.append("--protected-region-size={}".format(ctx.attr.protected_region_size))
    if ctx.attr.stack:
        args.append("--stack={}".format(ctx.attr.stack))
    if ctx.attr.verbose:
        args.append("--verbose")
    if ctx.attr.disable:
        args.append("--disable")
    args.append("{},{}".format(elffile.path, ctx.attr.arch))

    ctx.actions.run(
        mnemonic = "ELF2TAB",
        outputs = outputs,
        inputs = [elffile, ctx.executable._elf2tab],
        arguments = args,
        executable = ctx.executable._elf2tab,
    )

    outputs.append(elffile)
    return [
        TockApplication(tab = tabfile, tbf = tbffile, elf = elffile, flash_start = ctx.attr.flash_start),
        DefaultInfo(
            files = depset(outputs),
            data_runfiles = ctx.runfiles(files = outputs),
        ),
    ]

tock_elf2tab = rule(
    implementation = _tock_elf2tab_impl,
    attrs = {
        "kernel_major": attr.int(default = 2, doc = "Kernel major version required by the app"),
        "kernel_minor": attr.int(default = 0, doc = "Minimum kernel minor version required by the app"),
        "package_name": attr.string(default = "", doc = "Package name"),
        "protected_region_size": attr.int(doc = "Size of the TBF header"),
        "stack": attr.int(default = 0, doc = "Stack size"),
        "verbose": attr.bool(default = True, doc = "Verbose output"),
        "src": attr.label(mandatory = True, allow_single_file = True, doc = "ELF binary to convert"),
        "disable": attr.bool(default = False, doc = "Mark the application as disabled"),
        "arch": attr.string(mandatory = True, doc = "Target architecture for the ELF binary (e.g., `rv32imc`)"),
        "flash_start": attr.int(default = 0x20040000, doc = "Application starting address in flash"),
        "_elf2tab": attr.label(
            default = "@elf2tab//:bin",
            executable = True,
            cfg = "exec",
        ),
    },
)

# This `opt_mode` transition is used by the `tock_image` rule to transition the
# kernel and apps builds into the `opt` compilation mode.  This is required
# because `fastbuild` and `dbg` builds of tock will not fit into flash.
def _opt_mode_impl(settings, attr):
    return {"//command_line_option:compilation_mode": "opt"}

opt_mode = transition(
    implementation = _opt_mode_impl,
    inputs = [],
    outputs = ["//command_line_option:compilation_mode"],
)

# TODO: Refactor
def _as_group_info(name, items):
    """Prepare a dict of files for OutputGroupInfo.

    This renames all of the items to have `name` as a prefix and
    transforms the values into a depset.

    Args:
      name: A prefix for each dictionary key.
      items: A dict str:File to prepare.
    Returns:
      dict
    """
    groups = {}
    for k, v in items.items():
        if not v:
            continue
        elif type(v) == "list":
            # Depset wants a list; nothing to do.
            pass
        elif type(v) == "tuple":
            v = list(v)
        else:
            v = [v]
        groups["{}_{}".format(name, k)] = depset(v)
    return groups

def _tock_image_impl(ctx):
    cc_toolchain = find_cc_toolchain(ctx).cc


    providers = []
    default_info = []
    groups = {}
    for exec_env in ctx.attr.exec_env:
        exec_env = exec_env[ExecEnvInfo]
        kernel_binary = ctx.actions.declare_file("{}_{}_kernel.bin".format(ctx.attr.name, exec_env.exec_env))
        ctx.actions.run(
            outputs = [kernel_binary],
            inputs = [ctx.file.kernel] + cc_toolchain.all_files.to_list(),
            arguments = [
                "--output-target=binary",
                ctx.file.kernel.path,
                kernel_binary.path,
            ],
            executable = cc_toolchain.objcopy_executable,
        )
        image = ctx.actions.declare_file("{}_{}.bin".format(ctx.attr.name, exec_env.exec_env))
        ctx.actions.run(
            outputs = [image],
            inputs = [kernel_binary] + [app[TockApplication].tbf for app in ctx.attr.apps],
            arguments = [
                "--rcfile=",
                "image",
                "assemble",
                "--mirror=false",
                "--output={}".format(image.path),
                "--size=0x70000",
                "{}@0".format(kernel_binary.path),
            ] + ["{}@{}".format(app[TockApplication].tbf.path, app[TockApplication].flash_start - 0x20010000) for app in ctx.attr.apps],
            executable = ctx.toolchains[LOCALTOOLS_TOOLCHAIN].tools.opentitantool,
        )
        manifest = get_fallback(ctx, "file.manifest", exec_env)
        ecdsa_key = get_fallback(ctx, "attr.ecdsa_key", exec_env)
        rsa_key = get_fallback(ctx, "attr.rsa_key", exec_env)
        spx_key = get_fallback(ctx, "attr.spx_key", exec_env)
        signed = sign_binary(
            ctx,
            ctx.toolchains[LOCALTOOLS_TOOLCHAIN].tools.opentitantool,
            bin = image,
            ecdsa_key = ecdsa_key,
            rsa_key = rsa_key,
            spx_key = spx_key,
            manifest = manifest,
        )
        provides = exec_env.transform(
            ctx,
            exec_env,
            name = "{}_{}".format(ctx.attr.name, exec_env.exec_env),
            elf = None,
            binary = image,
            signed_bin = signed.get("signed"),
            disassembly = None,
            mapfile = None,
        )
        providers.append(exec_env.provider(**provides))
        default_info.append(provides["default"])
        groups.update(_as_group_info(exec_env.exec_env, signed))
        groups.update(_as_group_info(exec_env.exec_env, provides))

    providers.append(DefaultInfo(files = depset(default_info)))
    providers.append(OutputGroupInfo(**groups))
    return providers

tock_image = rv_rule(
    implementation = _tock_image_impl,
    attrs = {
        "apps": attr.label_list(mandatory = True, providers = [TockApplication], doc = "Application TAB labels", cfg = opt_mode),
        "ecdsa_key": attr.label_keyed_string_dict(
            allow_files = True,
            doc = "ECDSA public key to validate this image",
        ),
        "exec_env": attr.label_list(
            providers = [ExecEnvInfo],
            doc = "List of execution environments for this target.",
        ),
        "kernel": attr.label(mandatory = True, allow_single_file = True, doc = "Kernel ELF file", cfg = opt_mode),
        "kind": attr.string(
            doc = "Binary kind: flash, ram or rom",
            default = "flash",
            values = ["flash", "ram", "rom"],
        ),
        "manifest": attr.label(allow_single_file = True, mandatory = True),
        "rsa_key": attr.label_keyed_string_dict(
            allow_files = True,
            doc = "RSA public key to validate this image",
        ),
        "secver_write": attr.bool(
            doc = "Commit the security version to boot_data",
            default = True,
        ),
        "spx_key": attr.label_keyed_string_dict(
            allow_files = True,
            doc = "SPX public key to validate this image",
        ),
        "_cc_toolchain": attr.label(default = Label("@bazel_tools//tools/cpp:current_cc_toolchain")),
    },
    toolchains = ["@rules_cc//cc:toolchain_type", LOCALTOOLS_TOOLCHAIN],
)
