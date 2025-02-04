// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#ifndef OPENTITAN_SW_DEVICE_SILICON_CREATOR_LIB_ATTESTATION_KEY_DIVERSIFIERS_H_
#define OPENTITAN_SW_DEVICE_SILICON_CREATOR_LIB_ATTESTATION_KEY_DIVERSIFIERS_H_

#include "sw/device/silicon_creator/lib/drivers/keymgr.h"

#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

// Attestation key diversifier constants.
extern const keymgr_diversification_t kUdsKeymgrDiversifier;
extern const keymgr_diversification_t kCdi0KeymgrDiversifier;
extern const keymgr_diversification_t kCdi1KeymgrDiversifier;
extern const keymgr_diversification_t kTpmEkKeymgrDiversifier;
extern const keymgr_diversification_t kTpmCekKeymgrDiversifier;
extern const keymgr_diversification_t kTpmCikKeymgrDiversifier;

#ifdef __cplusplus
}  // extern "C"
#endif  // __cplusplus

#endif  // OPENTITAN_SW_DEVICE_SILICON_CREATOR_LIB_ATTESTATION_KEY_DIVERSIFIERS_H_
