/***************************************************************************//**
 * @file
 * @brief Top level application functions
 *******************************************************************************
 * # License
 * <b>Copyright 2020 Silicon Laboratories Inc. www.silabs.com</b>
 *******************************************************************************
 *
 * The licensor of this software is Silicon Laboratories Inc. Your use of this
 * software is governed by the terms of Silicon Labs Master Software License
 * Agreement (MSLA) available at
 * www.silabs.com/about-us/legal/master-software-license-agreement. This
 * software is distributed to you in Source Code format and is governed by the
 * sections of the MSLA applicable to Source Code.
 *
 ******************************************************************************/

#include "pasta_3_plain.h"

using namespace PASTA_3;

// A standard 64-bit prime for Zp Field evaluations
const uint64_t MODULUS = 0xFFFFFFFFFFC00001ULL;

// Secret key for PASTA needs 256 words
uint64_t test_key[256];

// Data blocks (Pasta processes blocks of 128 words)
uint64_t plaintext[128];
uint64_t ciphertext[128];

// Control flag
static bool test_completed = false;

/***************************************************************************//**
 * Initialize application.
 ******************************************************************************/
extern "C" void app_init(void)
{
  // Generate dummy test vector key and plaintext
  for (int i = 0; i < 256; i++) {
    test_key[i] = i + 1; 
  }
  for (int i = 0; i < 128; i++) {
    plaintext[i] = i * 2;
    ciphertext[i] = 0;
  }
}

/***************************************************************************//**
 * App ticking function.
 ******************************************************************************/
extern "C" void app_process_action(void)
{
  if (!test_completed) {
    // 1. Initialize Cipher context
    PASTA cipher(test_key, MODULUS);
    
    // 2. You can place your timer START function here
    
    // 3. Encrypt the block
    cipher.encrypt(plaintext, ciphertext, 128);
    
    // 4. You can place your timer STOP function here
    
    test_completed = true;
  }
}
