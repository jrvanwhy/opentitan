###############################################################################
# @generated
# DO NOT MODIFY: This file is auto-generated by a crate_universe tool. To
# regenerate this file, run the following:
#
#     bazel run @//third_party/tock:tock_index
###############################################################################
"""
# `crates_repository` API

- [aliases](#aliases)
- [crate_deps](#crate_deps)
- [all_crate_deps](#all_crate_deps)
- [crate_repositories](#crate_repositories)

"""

load("@bazel_skylib//lib:selects.bzl", "selects")
load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
load("@bazel_tools//tools/build_defs/repo:utils.bzl", "maybe")

###############################################################################
# MACROS API
###############################################################################

# An identifier that represent common dependencies (unconditional).
_COMMON_CONDITION = ""

def _flatten_dependency_maps(all_dependency_maps):
    """Flatten a list of dependency maps into one dictionary.

    Dependency maps have the following structure:

    ```python
    DEPENDENCIES_MAP = {
        # The first key in the map is a Bazel package
        # name of the workspace this file is defined in.
        "workspace_member_package": {

            # Not all dependencies are supported for all platforms.
            # the condition key is the condition required to be true
            # on the host platform.
            "condition": {

                # An alias to a crate target.     # The label of the crate target the
                # Aliases are only crate names.   # package name refers to.
                "package_name":                   "@full//:label",
            }
        }
    }
    ```

    Args:
        all_dependency_maps (list): A list of dicts as described above

    Returns:
        dict: A dictionary as described above
    """
    dependencies = {}

    for workspace_deps_map in all_dependency_maps:
        for pkg_name, conditional_deps_map in workspace_deps_map.items():
            if pkg_name not in dependencies:
                non_frozen_map = dict()
                for key, values in conditional_deps_map.items():
                    non_frozen_map.update({key: dict(values.items())})
                dependencies.setdefault(pkg_name, non_frozen_map)
                continue

            for condition, deps_map in conditional_deps_map.items():
                # If the condition has not been recorded, do so and continue
                if condition not in dependencies[pkg_name]:
                    dependencies[pkg_name].setdefault(condition, dict(deps_map.items()))
                    continue

                # Alert on any miss-matched dependencies
                inconsistent_entries = []
                for crate_name, crate_label in deps_map.items():
                    existing = dependencies[pkg_name][condition].get(crate_name)
                    if existing and existing != crate_label:
                        inconsistent_entries.append((crate_name, existing, crate_label))
                    dependencies[pkg_name][condition].update({crate_name: crate_label})

    return dependencies

def crate_deps(deps, package_name = None):
    """Finds the fully qualified label of the requested crates for the package where this macro is called.

    Args:
        deps (list): The desired list of crate targets.
        package_name (str, optional): The package name of the set of dependencies to look up.
            Defaults to `native.package_name()`.

    Returns:
        list: A list of labels to generated rust targets (str)
    """

    if not deps:
        return []

    if package_name == None:
        package_name = native.package_name()

    # Join both sets of dependencies
    dependencies = _flatten_dependency_maps([
        _NORMAL_DEPENDENCIES,
        _NORMAL_DEV_DEPENDENCIES,
        _PROC_MACRO_DEPENDENCIES,
        _PROC_MACRO_DEV_DEPENDENCIES,
        _BUILD_DEPENDENCIES,
        _BUILD_PROC_MACRO_DEPENDENCIES,
    ]).pop(package_name, {})

    # Combine all conditional packages so we can easily index over a flat list
    # TODO: Perhaps this should actually return select statements and maintain
    # the conditionals of the dependencies
    flat_deps = {}
    for deps_set in dependencies.values():
        for crate_name, crate_label in deps_set.items():
            flat_deps.update({crate_name: crate_label})

    missing_crates = []
    crate_targets = []
    for crate_target in deps:
        if crate_target not in flat_deps:
            missing_crates.append(crate_target)
        else:
            crate_targets.append(flat_deps[crate_target])

    if missing_crates:
        fail("Could not find crates `{}` among dependencies of `{}`. Available dependencies were `{}`".format(
            missing_crates,
            package_name,
            dependencies,
        ))

    return crate_targets

def all_crate_deps(
        normal = False,
        normal_dev = False,
        proc_macro = False,
        proc_macro_dev = False,
        build = False,
        build_proc_macro = False,
        package_name = None):
    """Finds the fully qualified label of all requested direct crate dependencies \
    for the package where this macro is called.

    If no parameters are set, all normal dependencies are returned. Setting any one flag will
    otherwise impact the contents of the returned list.

    Args:
        normal (bool, optional): If True, normal dependencies are included in the
            output list.
        normal_dev (bool, optional): If True, normal dev dependencies will be
            included in the output list..
        proc_macro (bool, optional): If True, proc_macro dependencies are included
            in the output list.
        proc_macro_dev (bool, optional): If True, dev proc_macro dependencies are
            included in the output list.
        build (bool, optional): If True, build dependencies are included
            in the output list.
        build_proc_macro (bool, optional): If True, build proc_macro dependencies are
            included in the output list.
        package_name (str, optional): The package name of the set of dependencies to look up.
            Defaults to `native.package_name()` when unset.

    Returns:
        list: A list of labels to generated rust targets (str)
    """

    if package_name == None:
        package_name = native.package_name()

    # Determine the relevant maps to use
    all_dependency_maps = []
    if normal:
        all_dependency_maps.append(_NORMAL_DEPENDENCIES)
    if normal_dev:
        all_dependency_maps.append(_NORMAL_DEV_DEPENDENCIES)
    if proc_macro:
        all_dependency_maps.append(_PROC_MACRO_DEPENDENCIES)
    if proc_macro_dev:
        all_dependency_maps.append(_PROC_MACRO_DEV_DEPENDENCIES)
    if build:
        all_dependency_maps.append(_BUILD_DEPENDENCIES)
    if build_proc_macro:
        all_dependency_maps.append(_BUILD_PROC_MACRO_DEPENDENCIES)

    # Default to always using normal dependencies
    if not all_dependency_maps:
        all_dependency_maps.append(_NORMAL_DEPENDENCIES)

    dependencies = _flatten_dependency_maps(all_dependency_maps).pop(package_name, None)

    if not dependencies:
        if dependencies == None:
            fail("Tried to get all_crate_deps for package " + package_name + " but that package had no Cargo.toml file")
        else:
            return []

    crate_deps = list(dependencies.pop(_COMMON_CONDITION, {}).values())
    for condition, deps in dependencies.items():
        crate_deps += selects.with_or({
            tuple(_CONDITIONS[condition]): deps.values(),
            "//conditions:default": [],
        })

    return crate_deps

def aliases(
        normal = False,
        normal_dev = False,
        proc_macro = False,
        proc_macro_dev = False,
        build = False,
        build_proc_macro = False,
        package_name = None):
    """Produces a map of Crate alias names to their original label

    If no dependency kinds are specified, `normal` and `proc_macro` are used by default.
    Setting any one flag will otherwise determine the contents of the returned dict.

    Args:
        normal (bool, optional): If True, normal dependencies are included in the
            output list.
        normal_dev (bool, optional): If True, normal dev dependencies will be
            included in the output list..
        proc_macro (bool, optional): If True, proc_macro dependencies are included
            in the output list.
        proc_macro_dev (bool, optional): If True, dev proc_macro dependencies are
            included in the output list.
        build (bool, optional): If True, build dependencies are included
            in the output list.
        build_proc_macro (bool, optional): If True, build proc_macro dependencies are
            included in the output list.
        package_name (str, optional): The package name of the set of dependencies to look up.
            Defaults to `native.package_name()` when unset.

    Returns:
        dict: The aliases of all associated packages
    """
    if package_name == None:
        package_name = native.package_name()

    # Determine the relevant maps to use
    all_aliases_maps = []
    if normal:
        all_aliases_maps.append(_NORMAL_ALIASES)
    if normal_dev:
        all_aliases_maps.append(_NORMAL_DEV_ALIASES)
    if proc_macro:
        all_aliases_maps.append(_PROC_MACRO_ALIASES)
    if proc_macro_dev:
        all_aliases_maps.append(_PROC_MACRO_DEV_ALIASES)
    if build:
        all_aliases_maps.append(_BUILD_ALIASES)
    if build_proc_macro:
        all_aliases_maps.append(_BUILD_PROC_MACRO_ALIASES)

    # Default to always using normal aliases
    if not all_aliases_maps:
        all_aliases_maps.append(_NORMAL_ALIASES)
        all_aliases_maps.append(_PROC_MACRO_ALIASES)

    aliases = _flatten_dependency_maps(all_aliases_maps).pop(package_name, None)

    if not aliases:
        return dict()

    common_items = aliases.pop(_COMMON_CONDITION, {}).items()

    # If there are only common items in the dictionary, immediately return them
    if not len(aliases.keys()) == 1:
        return dict(common_items)

    # Build a single select statement where each conditional has accounted for the
    # common set of aliases.
    crate_aliases = {"//conditions:default": dict(common_items)}
    for condition, deps in aliases.items():
        condition_triples = _CONDITIONS[condition]
        for triple in condition_triples:
            if triple in crate_aliases:
                crate_aliases[triple].update(deps)
            else:
                crate_aliases.update({triple: dict(deps.items() + common_items)})

    return select(crate_aliases)

###############################################################################
# WORKSPACE MEMBER DEPS AND ALIASES
###############################################################################

_NORMAL_DEPENDENCIES = {
    "third_party/tock": {
        _COMMON_CONDITION: {
            "ghash": "@tock_index__ghash-0.4.4//:ghash",
            "libm": "@tock_index__libm-0.2.8//:libm",
        },
    },
}

_NORMAL_ALIASES = {
    "third_party/tock": {
        _COMMON_CONDITION: {
        },
    },
}

_NORMAL_DEV_DEPENDENCIES = {
    "third_party/tock": {
    },
}

_NORMAL_DEV_ALIASES = {
    "third_party/tock": {
    },
}

_PROC_MACRO_DEPENDENCIES = {
    "third_party/tock": {
    },
}

_PROC_MACRO_ALIASES = {
    "third_party/tock": {
    },
}

_PROC_MACRO_DEV_DEPENDENCIES = {
    "third_party/tock": {
    },
}

_PROC_MACRO_DEV_ALIASES = {
    "third_party/tock": {
    },
}

_BUILD_DEPENDENCIES = {
    "third_party/tock": {
    },
}

_BUILD_ALIASES = {
    "third_party/tock": {
    },
}

_BUILD_PROC_MACRO_DEPENDENCIES = {
    "third_party/tock": {
    },
}

_BUILD_PROC_MACRO_ALIASES = {
    "third_party/tock": {
    },
}

_CONDITIONS = {
    "aarch64-apple-darwin": ["@rules_rust//rust/platform:aarch64-apple-darwin"],
    "aarch64-apple-ios": ["@rules_rust//rust/platform:aarch64-apple-ios"],
    "aarch64-apple-ios-sim": ["@rules_rust//rust/platform:aarch64-apple-ios-sim"],
    "aarch64-fuchsia": ["@rules_rust//rust/platform:aarch64-fuchsia"],
    "aarch64-linux-android": ["@rules_rust//rust/platform:aarch64-linux-android"],
    "aarch64-pc-windows-msvc": ["@rules_rust//rust/platform:aarch64-pc-windows-msvc"],
    "aarch64-unknown-linux-gnu": ["@rules_rust//rust/platform:aarch64-unknown-linux-gnu"],
    "arm-unknown-linux-gnueabi": ["@rules_rust//rust/platform:arm-unknown-linux-gnueabi"],
    "armv7-linux-androideabi": ["@rules_rust//rust/platform:armv7-linux-androideabi"],
    "armv7-unknown-linux-gnueabi": ["@rules_rust//rust/platform:armv7-unknown-linux-gnueabi"],
    "cfg(all(target_arch = \"aarch64\", target_os = \"linux\"))": ["@rules_rust//rust/platform:aarch64-unknown-linux-gnu"],
    "cfg(all(target_arch = \"aarch64\", target_vendor = \"apple\"))": ["@rules_rust//rust/platform:aarch64-apple-darwin", "@rules_rust//rust/platform:aarch64-apple-ios", "@rules_rust//rust/platform:aarch64-apple-ios-sim"],
    "cfg(all(target_arch = \"loongarch64\", target_os = \"linux\"))": [],
    "cfg(any(target_arch = \"aarch64\", target_arch = \"x86_64\", target_arch = \"x86\"))": ["@rules_rust//rust/platform:aarch64-apple-darwin", "@rules_rust//rust/platform:aarch64-apple-ios", "@rules_rust//rust/platform:aarch64-apple-ios-sim", "@rules_rust//rust/platform:aarch64-fuchsia", "@rules_rust//rust/platform:aarch64-linux-android", "@rules_rust//rust/platform:aarch64-pc-windows-msvc", "@rules_rust//rust/platform:aarch64-unknown-linux-gnu", "@rules_rust//rust/platform:i686-apple-darwin", "@rules_rust//rust/platform:i686-linux-android", "@rules_rust//rust/platform:i686-pc-windows-msvc", "@rules_rust//rust/platform:i686-unknown-freebsd", "@rules_rust//rust/platform:i686-unknown-linux-gnu", "@rules_rust//rust/platform:x86_64-apple-darwin", "@rules_rust//rust/platform:x86_64-apple-ios", "@rules_rust//rust/platform:x86_64-fuchsia", "@rules_rust//rust/platform:x86_64-linux-android", "@rules_rust//rust/platform:x86_64-pc-windows-msvc", "@rules_rust//rust/platform:x86_64-unknown-freebsd", "@rules_rust//rust/platform:x86_64-unknown-linux-gnu", "@rules_rust//rust/platform:x86_64-unknown-none"],
    "i686-apple-darwin": ["@rules_rust//rust/platform:i686-apple-darwin"],
    "i686-linux-android": ["@rules_rust//rust/platform:i686-linux-android"],
    "i686-pc-windows-msvc": ["@rules_rust//rust/platform:i686-pc-windows-msvc"],
    "i686-unknown-freebsd": ["@rules_rust//rust/platform:i686-unknown-freebsd"],
    "i686-unknown-linux-gnu": ["@rules_rust//rust/platform:i686-unknown-linux-gnu"],
    "powerpc-unknown-linux-gnu": ["@rules_rust//rust/platform:powerpc-unknown-linux-gnu"],
    "riscv32imc-unknown-none-elf": ["@rules_rust//rust/platform:riscv32imc-unknown-none-elf"],
    "riscv64gc-unknown-none-elf": ["@rules_rust//rust/platform:riscv64gc-unknown-none-elf"],
    "s390x-unknown-linux-gnu": ["@rules_rust//rust/platform:s390x-unknown-linux-gnu"],
    "thumbv7em-none-eabi": ["@rules_rust//rust/platform:thumbv7em-none-eabi"],
    "thumbv8m.main-none-eabi": ["@rules_rust//rust/platform:thumbv8m.main-none-eabi"],
    "wasm32-unknown-unknown": ["@rules_rust//rust/platform:wasm32-unknown-unknown"],
    "wasm32-wasi": ["@rules_rust//rust/platform:wasm32-wasi"],
    "x86_64-apple-darwin": ["@rules_rust//rust/platform:x86_64-apple-darwin"],
    "x86_64-apple-ios": ["@rules_rust//rust/platform:x86_64-apple-ios"],
    "x86_64-fuchsia": ["@rules_rust//rust/platform:x86_64-fuchsia"],
    "x86_64-linux-android": ["@rules_rust//rust/platform:x86_64-linux-android"],
    "x86_64-pc-windows-msvc": ["@rules_rust//rust/platform:x86_64-pc-windows-msvc"],
    "x86_64-unknown-freebsd": ["@rules_rust//rust/platform:x86_64-unknown-freebsd"],
    "x86_64-unknown-linux-gnu": ["@rules_rust//rust/platform:x86_64-unknown-linux-gnu"],
    "x86_64-unknown-none": ["@rules_rust//rust/platform:x86_64-unknown-none"],
}

###############################################################################

def crate_repositories():
    """A macro for defining repositories for all generated crates"""
    maybe(
        http_archive,
        name = "tock_index__cfg-if-1.0.0",
        sha256 = "baf1de4339761588bc0619e3cbc0120ee582ebb74b53b4efbf79117bd2da40fd",
        type = "tar.gz",
        urls = ["https://static.crates.io/crates/cfg-if/1.0.0/download"],
        strip_prefix = "cfg-if-1.0.0",
        build_file = Label("@lowrisc_opentitan//third_party/tock/crates:BUILD.cfg-if-1.0.0.bazel"),
    )

    maybe(
        http_archive,
        name = "tock_index__cpufeatures-0.2.12",
        sha256 = "53fe5e26ff1b7aef8bca9c6080520cfb8d9333c7568e1829cef191a9723e5504",
        type = "tar.gz",
        urls = ["https://static.crates.io/crates/cpufeatures/0.2.12/download"],
        strip_prefix = "cpufeatures-0.2.12",
        build_file = Label("@lowrisc_opentitan//third_party/tock/crates:BUILD.cpufeatures-0.2.12.bazel"),
    )

    maybe(
        http_archive,
        name = "tock_index__generic-array-0.14.7",
        sha256 = "85649ca51fd72272d7821adaf274ad91c288277713d9c18820d8499a7ff69e9a",
        type = "tar.gz",
        urls = ["https://static.crates.io/crates/generic-array/0.14.7/download"],
        strip_prefix = "generic-array-0.14.7",
        build_file = Label("@lowrisc_opentitan//third_party/tock/crates:BUILD.generic-array-0.14.7.bazel"),
    )

    maybe(
        http_archive,
        name = "tock_index__ghash-0.4.4",
        sha256 = "1583cc1656d7839fd3732b80cf4f38850336cdb9b8ded1cd399ca62958de3c99",
        type = "tar.gz",
        urls = ["https://static.crates.io/crates/ghash/0.4.4/download"],
        strip_prefix = "ghash-0.4.4",
        build_file = Label("@lowrisc_opentitan//third_party/tock/crates:BUILD.ghash-0.4.4.bazel"),
    )

    maybe(
        http_archive,
        name = "tock_index__libc-0.2.154",
        sha256 = "ae743338b92ff9146ce83992f766a31066a91a8c84a45e0e9f21e7cf6de6d346",
        type = "tar.gz",
        urls = ["https://static.crates.io/crates/libc/0.2.154/download"],
        strip_prefix = "libc-0.2.154",
        build_file = Label("@lowrisc_opentitan//third_party/tock/crates:BUILD.libc-0.2.154.bazel"),
    )

    maybe(
        http_archive,
        name = "tock_index__libm-0.2.8",
        sha256 = "4ec2a862134d2a7d32d7983ddcdd1c4923530833c9f2ea1a44fc5fa473989058",
        type = "tar.gz",
        urls = ["https://static.crates.io/crates/libm/0.2.8/download"],
        strip_prefix = "libm-0.2.8",
        build_file = Label("@lowrisc_opentitan//third_party/tock/crates:BUILD.libm-0.2.8.bazel"),
    )

    maybe(
        http_archive,
        name = "tock_index__opaque-debug-0.3.1",
        sha256 = "c08d65885ee38876c4f86fa503fb49d7b507c2b62552df7c70b2fce627e06381",
        type = "tar.gz",
        urls = ["https://static.crates.io/crates/opaque-debug/0.3.1/download"],
        strip_prefix = "opaque-debug-0.3.1",
        build_file = Label("@lowrisc_opentitan//third_party/tock/crates:BUILD.opaque-debug-0.3.1.bazel"),
    )

    maybe(
        http_archive,
        name = "tock_index__polyval-0.5.3",
        sha256 = "8419d2b623c7c0896ff2d5d96e2cb4ede590fed28fcc34934f4c33c036e620a1",
        type = "tar.gz",
        urls = ["https://static.crates.io/crates/polyval/0.5.3/download"],
        strip_prefix = "polyval-0.5.3",
        build_file = Label("@lowrisc_opentitan//third_party/tock/crates:BUILD.polyval-0.5.3.bazel"),
    )

    maybe(
        http_archive,
        name = "tock_index__subtle-2.4.1",
        sha256 = "6bdef32e8150c2a081110b42772ffe7d7c9032b606bc226c8260fd97e0976601",
        type = "tar.gz",
        urls = ["https://static.crates.io/crates/subtle/2.4.1/download"],
        strip_prefix = "subtle-2.4.1",
        build_file = Label("@lowrisc_opentitan//third_party/tock/crates:BUILD.subtle-2.4.1.bazel"),
    )

    maybe(
        http_archive,
        name = "tock_index__typenum-1.17.0",
        sha256 = "42ff0bf0c66b8238c6f3b578df37d0b7848e55df8577b3f74f92a69acceeb825",
        type = "tar.gz",
        urls = ["https://static.crates.io/crates/typenum/1.17.0/download"],
        strip_prefix = "typenum-1.17.0",
        build_file = Label("@lowrisc_opentitan//third_party/tock/crates:BUILD.typenum-1.17.0.bazel"),
    )

    maybe(
        http_archive,
        name = "tock_index__universal-hash-0.4.1",
        sha256 = "9f214e8f697e925001e66ec2c6e37a4ef93f0f78c2eed7814394e10c62025b05",
        type = "tar.gz",
        urls = ["https://static.crates.io/crates/universal-hash/0.4.1/download"],
        strip_prefix = "universal-hash-0.4.1",
        build_file = Label("@lowrisc_opentitan//third_party/tock/crates:BUILD.universal-hash-0.4.1.bazel"),
    )

    maybe(
        http_archive,
        name = "tock_index__version_check-0.9.4",
        sha256 = "49874b5167b65d7193b8aba1567f5c7d93d001cafc34600cee003eda787e483f",
        type = "tar.gz",
        urls = ["https://static.crates.io/crates/version_check/0.9.4/download"],
        strip_prefix = "version_check-0.9.4",
        build_file = Label("@lowrisc_opentitan//third_party/tock/crates:BUILD.version_check-0.9.4.bazel"),
    )
