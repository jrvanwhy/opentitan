// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#include "sw/device/tests/penetrationtests/firmware/sca/ibex_sca.h"

#include "sw/device/lib/base/memory.h"
#include "sw/device/lib/base/status.h"
#include "sw/device/lib/dif/dif_keymgr.h"
#include "sw/device/lib/dif/dif_kmac.h"
#include "sw/device/lib/runtime/log.h"
#include "sw/device/lib/testing/keymgr_testutils.h"
#include "sw/device/lib/testing/test_framework/check.h"
#include "sw/device/lib/testing/test_framework/ottf_test_config.h"
#include "sw/device/lib/testing/test_framework/ujson_ottf.h"
#include "sw/device/lib/ujson/ujson.h"
#include "sw/device/sca/lib/prng.h"
#include "sw/device/sca/lib/sca.h"
#include "sw/device/tests/penetrationtests/firmware/lib/sca_lib.h"
#include "sw/device/tests/penetrationtests/json/ibex_sca_commands.h"

#include "hw/top_earlgrey/sw/autogen/top_earlgrey.h"

static dif_keymgr_t keymgr;
static dif_kmac_t kmac;

// NOP macros.
#define NOP1 "addi x0, x0, 0\n"
#define NOP10 NOP1 NOP1 NOP1 NOP1 NOP1 NOP1 NOP1 NOP1 NOP1 NOP1
#define NOP30 NOP10 NOP10 NOP10
#define NOP100 NOP10 NOP10 NOP10 NOP10 NOP10 NOP10 NOP10 NOP10 NOP10 NOP10

// Indicates whether the key manager is already configured for the test.
static bool key_manager_init;

// Buffer to allow the compiler to allocate a safe area in Main SRAM where
// we can do the write/read test without the risk of clobbering data
// used by the program.
OT_SECTION(".data")
static volatile uint32_t sram_main_buffer[8];
static volatile uint32_t sram_main_buffer_batch[256];

// Function to assign x5...x7 and x28...x31 the provided values val0...val6.
// Inline to avoid function calls for SCA measurements.
static inline void copy_to_registers(uint32_t val0, uint32_t val1,
                                     uint32_t val2, uint32_t val3,
                                     uint32_t val4, uint32_t val5,
                                     uint32_t val6) {
  asm volatile("mv %0, x5" : "=r"(val0));
  asm volatile("mv %0, x6" : "=r"(val1));
  asm volatile("mv %0, x7" : "=r"(val2));
  asm volatile("mv %0, x28" : "=r"(val3));
  asm volatile("mv %0, x29" : "=r"(val4));
  asm volatile("mv %0, x30" : "=r"(val5));
  asm volatile("mv %0, x31" : "=r"(val6));
}

// Generate Fixed vs Random (FvsR) array of values. The fixed value is provided
// by the user and the random values are generated by the PRNG provided in the
// SCA library.
static void generate_fvsr(size_t num_iterations, uint32_t fixed_data,
                          uint32_t values[]) {
  bool sample_fixed = true;
  for (size_t i = 0; i < num_iterations; i++) {
    if (sample_fixed) {
      values[i] = fixed_data;
    } else {
      values[i] = prng_rand_uint32();
    }
    sample_fixed = prng_rand_uint32() & 0x1;
  }
}

// Generate random values used by the test by calling the SCA PRNG.
static void generate_random(size_t num_iterations, uint32_t values[]) {
  for (size_t i = 0; i < num_iterations; i++) {
    values[i] = prng_rand_uint32();
  }
}

status_t handle_ibex_sca_tl_write_batch_fvsr_fix_address(ujson_t *uj) {
  // Get number of iterations and fixed data.
  ibex_sca_test_fvsr_t uj_data;
  TRY(ujson_deserialize_ibex_sca_test_fvsr_t(uj, &uj_data));
  TRY_CHECK(uj_data.num_iterations < 256);

  // Generate FvsR values.
  uint32_t values[256];
  generate_fvsr(uj_data.num_iterations, uj_data.fixed_data, values);

  // Get address of buffer located in SRAM.
  uintptr_t sram_main_buffer_addr = (uintptr_t)&sram_main_buffer_batch;
  mmio_region_t sram_region_main_addr =
      mmio_region_from_addr(sram_main_buffer_addr);

  // SCA code target.
  for (int it = 0; it < uj_data.num_iterations; it++) {
    sca_set_trigger_high();
    // Give the trigger time to rise.
    asm volatile(NOP30);
    // Write random data into SRAM at the first address.
    mmio_region_write32(sram_region_main_addr, 0, values[it]);
    sca_set_trigger_low();
    asm volatile(NOP30);
  }

  // Write back last value written into SRAM to validate generated data.
  ibex_sca_result_t uj_output;
  uj_output.result = values[uj_data.num_iterations - 1];
  RESP_OK(ujson_serialize_ibex_sca_result_t, uj, &uj_output);
  return OK_STATUS();
}

status_t handle_ibex_sca_tl_write_batch_fvsr(ujson_t *uj) {
  // Get number of iterations and fixed data.
  ibex_sca_test_fvsr_t uj_data;
  TRY(ujson_deserialize_ibex_sca_test_fvsr_t(uj, &uj_data));
  TRY_CHECK(uj_data.num_iterations < 256);

  // Generate FvsR values.
  uint32_t values[256];
  generate_fvsr(uj_data.num_iterations, uj_data.fixed_data, values);

  // Get address of buffer located in SRAM.
  uintptr_t sram_main_buffer_addr = (uintptr_t)&sram_main_buffer_batch;
  mmio_region_t sram_region_main_addr =
      mmio_region_from_addr(sram_main_buffer_addr);

  // SCA code target.
  for (int it = 0; it < uj_data.num_iterations; it++) {
    sca_set_trigger_high();
    // Give the trigger time to rise.
    asm volatile(NOP30);
    // Write random data into SRAM.
    mmio_region_write32(sram_region_main_addr, it * (ptrdiff_t)sizeof(uint32_t),
                        values[it]);
    sca_set_trigger_low();
    asm volatile(NOP30);
  }

  // Write back last value written into SRAM to validate generated data.
  ibex_sca_result_t uj_output;
  uj_output.result = values[uj_data.num_iterations - 1];
  RESP_OK(ujson_serialize_ibex_sca_result_t, uj, &uj_output);
  return OK_STATUS();
}

status_t handle_ibex_sca_tl_write_batch_random_fix_address(ujson_t *uj) {
  // Get number of iterations.
  ibex_sca_batch_t uj_data;
  TRY(ujson_deserialize_ibex_sca_batch_t(uj, &uj_data));
  TRY_CHECK(uj_data.num_iterations < 256);

  // Generate random values.
  uint32_t values[256];
  generate_random(uj_data.num_iterations, values);

  // Get address of buffer located in SRAM.
  uintptr_t sram_main_buffer_addr = (uintptr_t)&sram_main_buffer_batch;
  mmio_region_t sram_region_main_addr =
      mmio_region_from_addr(sram_main_buffer_addr);

  // SCA code target.
  for (int it = 0; it < uj_data.num_iterations; it++) {
    sca_set_trigger_high();
    // Give the trigger time to rise.
    asm volatile(NOP30);
    // Write random data into SRAM.
    mmio_region_write32(sram_region_main_addr, 0, values[it]);
    sca_set_trigger_low();
    asm volatile(NOP30);
  }

  // Write back last value written into SRAM to validate generated data.
  ibex_sca_result_t uj_output;
  uj_output.result = values[uj_data.num_iterations - 1];
  RESP_OK(ujson_serialize_ibex_sca_result_t, uj, &uj_output);
  return OK_STATUS();
}

status_t handle_ibex_sca_tl_write_batch_random(ujson_t *uj) {
  // Get number of iterations.
  ibex_sca_batch_t uj_data;
  TRY(ujson_deserialize_ibex_sca_batch_t(uj, &uj_data));
  TRY_CHECK(uj_data.num_iterations < 256);

  // Generate random values.
  uint32_t values[256];
  generate_random(uj_data.num_iterations, values);

  // Get address of buffer located in SRAM.
  uintptr_t sram_main_buffer_addr = (uintptr_t)&sram_main_buffer_batch;
  mmio_region_t sram_region_main_addr =
      mmio_region_from_addr(sram_main_buffer_addr);

  // SCA code target.
  for (int it = 0; it < uj_data.num_iterations; it++) {
    sca_set_trigger_high();
    // Give the trigger time to rise.
    asm volatile(NOP30);
    // Write random data into SRAM.
    mmio_region_write32(sram_region_main_addr, it * (ptrdiff_t)sizeof(uint32_t),
                        values[it]);
    sca_set_trigger_low();
    asm volatile(NOP30);
  }

  // Write back last value written into SRAM to validate generated data.
  ibex_sca_result_t uj_output;
  uj_output.result = values[uj_data.num_iterations - 1];
  RESP_OK(ujson_serialize_ibex_sca_result_t, uj, &uj_output);
  return OK_STATUS();
}

status_t handle_ibex_sca_key_sideloading(ujson_t *uj) {
  ibex_sca_salt_t uj_data;
  TRY(ujson_deserialize_ibex_sca_salt_t(uj, &uj_data));

  if (!key_manager_init) {
    // Initialize keymgr and advance to CreatorRootKey state.
    TRY(keymgr_testutils_startup(&keymgr, &kmac));

    // Generate identity at CreatorRootKey (to follow same sequence and reuse
    // chip_sw_keymgr_key_derivation_vseq.sv).
    TRY(keymgr_testutils_generate_identity(&keymgr));

    // Advance to OwnerIntermediateKey state.
    TRY(keymgr_testutils_advance_state(&keymgr, &kOwnerIntParams));
    TRY(keymgr_testutils_check_state(&keymgr,
                                     kDifKeymgrStateOwnerIntermediateKey));
    key_manager_init = true;
  }

  // Set the salt based on the input.
  dif_keymgr_versioned_key_params_t sideload_params = kKeyVersionedParams;
  for (int i = 0; i < 8; i++) {
    sideload_params.salt[i] = uj_data.salt[i];
  }

  // Trigger keymanager to create a new key based on the provided salt.
  sca_set_trigger_high();
  TRY(keymgr_testutils_generate_versioned_key(&keymgr, sideload_params));
  sca_set_trigger_low();

  // Read back generated key provided at the software interface.
  dif_keymgr_output_t key;
  TRY(dif_keymgr_read_output(&keymgr, &key));

  // Acknowledge test.
  ibex_sca_key_t uj_key;
  for (int i = 0; i < 8; i++) {
    uj_key.share0[i] = key.value[0][i];
    uj_key.share1[i] = key.value[1][i];
  }
  RESP_OK(ujson_serialize_ibex_sca_key_t, uj, &uj_key);
  return OK_STATUS();
}

status_t handle_ibex_sca_tl_write(ujson_t *uj) {
  // Get data to write into SRAM.
  ibex_sca_test_data_t uj_data;
  TRY(ujson_deserialize_ibex_sca_test_data_t(uj, &uj_data));

  // Get address of buffer located in SRAM.
  uintptr_t sram_main_buffer_addr = (uintptr_t)&sram_main_buffer;
  mmio_region_t sram_region_main_addr =
      mmio_region_from_addr(sram_main_buffer_addr);

  // SCA code target.
  sca_set_trigger_high();
  // Give the trigger time to rise.
  asm volatile(NOP30);
  // Write provided data into SRAM.
  for (int i = 0; i < 8; i++) {
    mmio_region_write32(sram_region_main_addr, i * (ptrdiff_t)sizeof(uint32_t),
                        uj_data.data[i]);
  }
  sca_set_trigger_low();

  // Acknowledge test.
  ibex_sca_result_t uj_output;
  uj_output.result = 0;
  RESP_OK(ujson_serialize_ibex_sca_result_t, uj, &uj_output);
  return OK_STATUS();
}

status_t handle_ibex_sca_tl_read_batch_fvsr_fix_address(ujson_t *uj) {
  // Get number of iterations and fixed data.
  ibex_sca_test_fvsr_t uj_data;
  TRY(ujson_deserialize_ibex_sca_test_fvsr_t(uj, &uj_data));
  TRY_CHECK(uj_data.num_iterations < 256);

  // Generate FvsR values.
  uint32_t values[256];
  generate_fvsr(uj_data.num_iterations, uj_data.fixed_data, values);

  // Get address of buffer located in SRAM.
  uintptr_t sram_main_buffer_addr = (uintptr_t)&sram_main_buffer_batch;
  mmio_region_t sram_region_main_addr =
      mmio_region_from_addr(sram_main_buffer_addr);

  uint32_t read_data[256];

  // SCA code target.
  // Fetch data from SRAM.
  for (size_t i = 0; i < uj_data.num_iterations; i++) {
    mmio_region_write32(sram_region_main_addr, 0, values[i]);
    asm volatile(NOP30);
    sca_set_trigger_high();
    // Give the trigger time to rise.
    asm volatile(NOP30);
    read_data[i] = mmio_region_read32(sram_region_main_addr, 0);
    sca_set_trigger_low();
  }

  // Write back last value read from SRAM to validate generated data.
  ibex_sca_result_t uj_output;
  uj_output.result = read_data[uj_data.num_iterations - 1];
  RESP_OK(ujson_serialize_ibex_sca_result_t, uj, &uj_output);
  return OK_STATUS();
}

status_t handle_ibex_sca_tl_read_batch_fvsr(ujson_t *uj) {
  // Get number of iterations and fixed data.
  ibex_sca_test_fvsr_t uj_data;
  TRY(ujson_deserialize_ibex_sca_test_fvsr_t(uj, &uj_data));
  TRY_CHECK(uj_data.num_iterations < 256);

  // Generate FvsR values.
  uint32_t values[256];
  generate_fvsr(uj_data.num_iterations, uj_data.fixed_data, values);

  // Get address of buffer located in SRAM.
  uintptr_t sram_main_buffer_addr = (uintptr_t)&sram_main_buffer_batch;
  mmio_region_t sram_region_main_addr =
      mmio_region_from_addr(sram_main_buffer_addr);

  // Write provided data into SRAM.
  for (int i = 0; i < uj_data.num_iterations; i++) {
    mmio_region_write32(sram_region_main_addr, i * (ptrdiff_t)sizeof(uint32_t),
                        values[i]);
  }

  uint32_t read_data[256];

  // SCA code target.
  // Fetch data from SRAM.
  for (int i = 0; i < uj_data.num_iterations; i++) {
    sca_set_trigger_high();
    // Give the trigger time to rise.
    asm volatile(NOP30);
    read_data[i] = mmio_region_read32(sram_region_main_addr,
                                      i * (ptrdiff_t)sizeof(uint32_t));
    sca_set_trigger_low();
    asm volatile(NOP30);
  }

  // Write back last value read from SRAM to validate generated data.
  ibex_sca_result_t uj_output;
  uj_output.result = read_data[uj_data.num_iterations - 1];
  RESP_OK(ujson_serialize_ibex_sca_result_t, uj, &uj_output);
  return OK_STATUS();
}

status_t handle_ibex_sca_tl_read_batch_random_fix_address(ujson_t *uj) {
  // Get number of iterations.
  ibex_sca_batch_t uj_data;
  TRY(ujson_deserialize_ibex_sca_batch_t(uj, &uj_data));
  TRY_CHECK(uj_data.num_iterations < 256);

  // Generate random values.
  uint32_t values[256];
  generate_random(uj_data.num_iterations, values);

  // Get address of buffer located in SRAM.
  uintptr_t sram_main_buffer_addr = (uintptr_t)&sram_main_buffer_batch;
  mmio_region_t sram_region_main_addr =
      mmio_region_from_addr(sram_main_buffer_addr);

  uint32_t read_data[256];
  // SCA code target.
  // Fetch data from SRAM.
  for (size_t i = 0; i < uj_data.num_iterations; i++) {
    mmio_region_write32(sram_region_main_addr, 0, values[i]);
    asm volatile(NOP30);
    sca_set_trigger_high();
    // Give the trigger time to rise.
    asm volatile(NOP30);
    read_data[i] = mmio_region_read32(sram_region_main_addr, 0);
    sca_set_trigger_low();
  }

  // Write back last value read from SRAM to validate generated data.
  ibex_sca_result_t uj_output;
  uj_output.result = read_data[uj_data.num_iterations - 1];
  RESP_OK(ujson_serialize_ibex_sca_result_t, uj, &uj_output);
  return OK_STATUS();
}

status_t handle_ibex_sca_tl_read_batch_random(ujson_t *uj) {
  // Get number of iterations.
  ibex_sca_batch_t uj_data;
  TRY(ujson_deserialize_ibex_sca_batch_t(uj, &uj_data));
  TRY_CHECK(uj_data.num_iterations < 256);

  // Generate random values.
  uint32_t values[256];
  generate_random(uj_data.num_iterations, values);

  // Get address of buffer located in SRAM.
  uintptr_t sram_main_buffer_addr = (uintptr_t)&sram_main_buffer_batch;
  mmio_region_t sram_region_main_addr =
      mmio_region_from_addr(sram_main_buffer_addr);

  // Write provided data into SRAM.
  for (int i = 0; i < uj_data.num_iterations; i++) {
    mmio_region_write32(sram_region_main_addr, i * (ptrdiff_t)sizeof(uint32_t),
                        values[i]);
  }

  uint32_t read_data[256];

  // SCA code target.

  // Fetch data from SRAM.
  for (int i = 0; i < uj_data.num_iterations; i++) {
    sca_set_trigger_high();
    // Give the trigger time to rise.
    asm volatile(NOP30);
    read_data[i] = mmio_region_read32(sram_region_main_addr,
                                      i * (ptrdiff_t)sizeof(uint32_t));
    sca_set_trigger_low();
    asm volatile(NOP30);
  }

  // Write back last value read from SRAM to validate generated data.
  ibex_sca_result_t uj_output;
  uj_output.result = read_data[uj_data.num_iterations - 1];
  RESP_OK(ujson_serialize_ibex_sca_result_t, uj, &uj_output);
  return OK_STATUS();
}

status_t handle_ibex_sca_tl_read(ujson_t *uj) {
  // Get data to write into SRAM.
  ibex_sca_test_data_t uj_data;
  TRY(ujson_deserialize_ibex_sca_test_data_t(uj, &uj_data));

  // Get address of buffer located in SRAM.
  uintptr_t sram_main_buffer_addr = (uintptr_t)&sram_main_buffer;
  mmio_region_t sram_region_main_addr =
      mmio_region_from_addr(sram_main_buffer_addr);

  // Write provided data into SRAM.
  for (int i = 0; i < 8; i++) {
    mmio_region_write32(sram_region_main_addr, i * (ptrdiff_t)sizeof(uint32_t),
                        uj_data.data[i]);
  }

  uint32_t read_data[8];

  // SCA code target.
  sca_set_trigger_high();
  // Give the trigger time to rise.
  asm volatile(NOP30);
  // Fetch data from SRAM.
  for (int i = 0; i < 8; i++) {
    read_data[i] = mmio_region_read32(sram_region_main_addr,
                                      i * (ptrdiff_t)sizeof(uint32_t));
  }
  sca_set_trigger_low();
  // Acknowledge test.
  ibex_sca_result_t uj_output;
  uj_output.result = 0;
  RESP_OK(ujson_serialize_ibex_sca_result_t, uj, &uj_output);
  return OK_STATUS();
}

status_t handle_ibex_sca_register_file_write_batch_fvsr(ujson_t *uj) {
  // Get number of iterations and fixed data.
  ibex_sca_test_fvsr_t uj_data;
  TRY(ujson_deserialize_ibex_sca_test_fvsr_t(uj, &uj_data));
  TRY_CHECK(uj_data.num_iterations < 256);

  // Generate FvsR values.
  uint32_t values[256];
  generate_fvsr(uj_data.num_iterations, uj_data.fixed_data, values);

  // SCA code target.
  for (size_t i = 0; i < uj_data.num_iterations; i++) {
    sca_set_trigger_high();
    // Give the trigger time to rise.
    asm volatile(NOP30);
    // Write provided data into register file.
    copy_to_registers(values[i], values[i], values[i], values[i], values[i],
                      values[i], values[i]);
    sca_set_trigger_low();
    asm volatile(NOP30);
  }

  // Write back last value written into the RF to validate generated data.
  ibex_sca_result_t uj_output;
  uj_output.result = values[uj_data.num_iterations - 1];
  RESP_OK(ujson_serialize_ibex_sca_result_t, uj, &uj_output);
  return OK_STATUS();
}

status_t handle_ibex_sca_register_file_write_batch_random(ujson_t *uj) {
  // Get number of iterations.
  ibex_sca_batch_t uj_data;
  TRY(ujson_deserialize_ibex_sca_batch_t(uj, &uj_data));
  TRY_CHECK(uj_data.num_iterations < 256);

  // Generate random values.
  uint32_t values[256];
  generate_random(uj_data.num_iterations, values);

  // SCA code target.
  for (size_t i = 0; i < uj_data.num_iterations; i++) {
    sca_set_trigger_high();
    // Give the trigger time to rise.
    asm volatile(NOP30);
    // Write provided data into register file.
    copy_to_registers(values[i], values[i], values[i], values[i], values[i],
                      values[i], values[i]);
    sca_set_trigger_low();
    asm volatile(NOP30);
  }

  // Write back last value written into the RF to validate generated data.
  ibex_sca_result_t uj_output;
  uj_output.result = values[uj_data.num_iterations - 1];
  RESP_OK(ujson_serialize_ibex_sca_result_t, uj, &uj_output);
  return OK_STATUS();
}

status_t handle_ibex_sca_register_file_write(ujson_t *uj) {
  // Get data to write into RF.
  ibex_sca_test_data_t uj_data;
  TRY(ujson_deserialize_ibex_sca_test_data_t(uj, &uj_data));

  // SCA code target.
  sca_set_trigger_high();
  // Give the trigger time to rise.
  asm volatile(NOP30);
  // Write provided data into register file.
  copy_to_registers(uj_data.data[0], uj_data.data[1], uj_data.data[2],
                    uj_data.data[3], uj_data.data[4], uj_data.data[5],
                    uj_data.data[6]);
  sca_set_trigger_low();

  // Acknowledge test.
  ibex_sca_result_t uj_output;
  uj_output.result = 0;
  RESP_OK(ujson_serialize_ibex_sca_result_t, uj, &uj_output);
  return OK_STATUS();
}

status_t handle_ibex_sca_register_file_read_batch_fvsr(ujson_t *uj) {
  // Get number of iterations and fixed data.
  ibex_sca_test_fvsr_t uj_data;
  TRY(ujson_deserialize_ibex_sca_test_fvsr_t(uj, &uj_data));
  TRY_CHECK(uj_data.num_iterations < 256);

  // Generate FvsR values.
  uint32_t values[256];
  generate_fvsr(uj_data.num_iterations, uj_data.fixed_data, values);

  for (size_t i = 0; i < uj_data.num_iterations; i++) {
    // Initialize temporary registers with reference values.
    copy_to_registers(0, 0, 0, values[i], values[i], values[i], values[i]);
    asm volatile(NOP30);
    // SCA code target.
    sca_set_trigger_high();
    // Give the trigger time to rise.
    asm volatile(NOP30);
    // Copy registers.
    asm volatile("mv x5, x28");
    asm volatile("mv x6, x29");
    asm volatile("mv x7, x30");
    sca_set_trigger_low();
  }

  // Write back last value written into the RF to validate generated data.
  ibex_sca_result_t uj_output;
  uj_output.result = values[uj_data.num_iterations - 1];
  RESP_OK(ujson_serialize_ibex_sca_result_t, uj, &uj_output);
  return OK_STATUS();
}

status_t handle_ibex_sca_register_file_read_batch_random(ujson_t *uj) {
  // Get number of iterations.
  ibex_sca_batch_t uj_data;
  TRY(ujson_deserialize_ibex_sca_batch_t(uj, &uj_data));
  TRY_CHECK(uj_data.num_iterations < 256);

  // Generate random values.
  uint32_t values[256];
  generate_random(uj_data.num_iterations, values);

  for (size_t i = 0; i < uj_data.num_iterations; i++) {
    // Initialize temporary registers with reference values.
    copy_to_registers(0, 0, 0, values[i], values[i], values[i], values[i]);
    asm volatile(NOP30);
    // SCA code target.
    sca_set_trigger_high();
    // Give the trigger time to rise.
    asm volatile(NOP30);
    // Copy registers.
    asm volatile("mv x5, x28");
    asm volatile("mv x6, x29");
    asm volatile("mv x7, x30");
    sca_set_trigger_low();
  }

  // Write back last value written into the RF to validate generated data.
  ibex_sca_result_t uj_output;
  uj_output.result = values[uj_data.num_iterations - 1];
  RESP_OK(ujson_serialize_ibex_sca_result_t, uj, &uj_output);
  return OK_STATUS();
}

status_t handle_ibex_sca_register_file_read(ujson_t *uj) {
  // Get data to write into RF.
  ibex_sca_test_data_t uj_data;
  TRY(ujson_deserialize_ibex_sca_test_data_t(uj, &uj_data));
  // Initialize temporary registers with reference values.
  copy_to_registers(uj_data.data[0], uj_data.data[1], uj_data.data[2],
                    uj_data.data[3], uj_data.data[4], uj_data.data[5], 0);

  // SCA code target.
  sca_set_trigger_high();
  // Give the trigger time to rise.
  asm volatile(NOP30);
  // Copy registers.
  asm volatile("mv x28, x5");
  asm volatile("mv x29, x6");
  asm volatile("mv x30, x7");
  sca_set_trigger_low();

  // Acknowledge test.
  ibex_sca_result_t uj_output;
  uj_output.result = 0;
  RESP_OK(ujson_serialize_ibex_sca_result_t, uj, &uj_output);
  return OK_STATUS();
}

status_t handle_ibex_sca_init(ujson_t *uj) {
  // Setup trigger and enable peripherals needed for the test.
  sca_select_trigger_type(kScaTriggerTypeSw);
  // As we are using the software defined trigger, the first argument of
  // sca_init is not needed. kScaTriggerSourceAes is selected as a placeholder.
  sca_init(kScaTriggerSourceAes, kScaPeripheralIoDiv4 | kScaPeripheralKmac);

  // Disable the instruction cache and dummy instructions for SCA.
  sca_configure_cpu();

  // Key manager not initialized for the handle_ibex_sca_key_sideloading test.
  key_manager_init = false;

  // Read the device ID and return it back to the host.
  TRY(sca_read_device_id(uj));

  return OK_STATUS();
}

status_t handle_ibex_sca(ujson_t *uj) {
  ibex_sca_subcommand_t cmd;
  TRY(ujson_deserialize_ibex_sca_subcommand_t(uj, &cmd));
  switch (cmd) {
    case kIbexScaSubcommandInit:
      return handle_ibex_sca_init(uj);
    case kIbexScaSubcommandRFRead:
      return handle_ibex_sca_register_file_read(uj);
    case kIbexScaSubcommandRFReadBatchRandom:
      return handle_ibex_sca_register_file_read_batch_random(uj);
    case kIbexScaSubcommandRFReadBatchFvsr:
      return handle_ibex_sca_register_file_read_batch_fvsr(uj);
    case kIbexScaSubcommandRFWrite:
      return handle_ibex_sca_register_file_write(uj);
    case kIbexScaSubcommandRFWriteBatchRandom:
      return handle_ibex_sca_register_file_write_batch_random(uj);
    case kIbexScaSubcommandRFWriteBatchFvsr:
      return handle_ibex_sca_register_file_write_batch_fvsr(uj);
    case kIbexScaSubcommandTLRead:
      return handle_ibex_sca_tl_read(uj);
    case kIbexScaSubcommandTLReadBatchRandom:
      return handle_ibex_sca_tl_read_batch_random(uj);
    case kIbexScaSubcommandTLReadBatchRandomFixAddress:
      return handle_ibex_sca_tl_read_batch_random_fix_address(uj);
    case kIbexScaSubcommandTLReadBatchFvsr:
      return handle_ibex_sca_tl_read_batch_fvsr(uj);
    case kIbexScaSubcommandTLReadBatchFvsrFixAddress:
      return handle_ibex_sca_tl_read_batch_fvsr_fix_address(uj);
    case kIbexScaSubcommandTLWrite:
      return handle_ibex_sca_tl_write(uj);
    case kIbexScaSubcommandKeySideloading:
      return handle_ibex_sca_key_sideloading(uj);
    case kIbexScaSubcommandTLWriteBatchRandom:
      return handle_ibex_sca_tl_write_batch_random(uj);
    case kIbexScaSubcommandTLWriteBatchRandomFixAddress:
      return handle_ibex_sca_tl_write_batch_random_fix_address(uj);
    case kIbexScaSubcommandTLWriteBatchFvsr:
      return handle_ibex_sca_tl_write_batch_fvsr(uj);
    case kIbexScaSubcommandTLWriteBatchFvsrFixAddress:
      return handle_ibex_sca_tl_write_batch_fvsr_fix_address(uj);
    default:
      LOG_ERROR("Unrecognized IBEX SCA subcommand: %d", cmd);
      return INVALID_ARGUMENT();
  }
  return OK_STATUS();
}
