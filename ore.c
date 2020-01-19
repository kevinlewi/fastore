/**
 * Copyright (c) 2016, David J. Wu, Kevin Lewi
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND
 * FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
 * OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

#include "crypto.h"
#include "errors.h"
#include "ore.h"

#include <gmp.h>
#include <stdio.h>
#include <string.h>

/**
 * Checks if two ore_params structs are equal
 *
 * @param params1 The first set of parameters
 * @param params2 The second set of parameters
 *
 * @return 1 if they are equal, 0 otherwise
 */
static bool _eq_ore_params(ore_params params1, ore_params params2) {
  return (params1->initialized == params2->initialized) &&
         (params1->nbits == params2->nbits) &&
         (params1->out_blk_len == params2->out_blk_len);
}

/**
 * Checks if an ore_param struct is valid by ensuring that block length is at
 * least 2, and at most 8 * PRF_OUTPUT_BYTES
 *
 * @param params The parameters to check
 *
 * @return True if the parameters are valid, false otherwise
 */
static bool _is_valid_params(ore_params params) {
  // assuming binary representation
  if (!params->initialized) {
    return false;
  } else if (params->out_blk_len < 2) {
    return false;
  } else if (params->out_blk_len / 8 > PRF_OUTPUT_BYTES) {
    return false;
  }
  return true;
}

int init_ore_params(ore_params params, uint32_t nbits, uint32_t out_blk_len) {
  params->initialized = true;
  params->nbits = nbits;
  params->out_blk_len = out_blk_len;

  if (!_is_valid_params(params)) {
    return ERROR_PARAMS_INVALID;
  }

  return ERROR_NONE;
}

int ore_setup(ore_secret_key sk, ore_params params) {
  if (!_is_valid_params(params)) {
    return ERROR_PARAMS_INVALID;
  }

  int err = generate_prf_key(sk->key);
  if (err != ERROR_NONE) {
    return err;
  }

  memcpy(sk->params, params, sizeof(ore_params));

  sk->initialized = true;

  return ERROR_NONE;
}

int ore_cleanup(ore_secret_key sk) {
  memset(sk, 0, sizeof(ore_secret_key));

  return ERROR_NONE;
}

/**
 * Main function which performs the encryption of an input, storing the result
 * in a ciphertext.
 *
 * This function implements the encrypt algorithm for order revealing
 * encryption, using the secret key and input passed in and storing the
 * resulting ciphertext in ctxt.
 *
 * The secret key must be initialized (by a call to ore_setup) before calling
 * this function.
 *
 * @param ctxt   The ciphertext to store the encryption
 * @param sk     The secret key (which must have been initialized)
 * @param buf    The input in a byte array, encoded in little-endian
 * @param buflen The length of the byte array input
 *
 * @return ERROR_NONE on success
 */
static int _ore_encrypt_buf(ore_ciphertext ctxt, ore_secret_key sk, byte* buf,
    uint32_t buflen) {

  int i;

  // assumes little-endian encoding of message bits

  if(!sk->initialized) {
    return ERROR_SK_NOT_INITIALIZED;
  }

  if(!ctxt->initialized) {
    return ERROR_CTXT_NOT_INITIALIZED;
  }

  if (!_eq_ore_params(ctxt->params, sk->params)) {
    return ERROR_PARAMS_MISMATCH;
  }

  if (!_is_valid_params(ctxt->params)) {
    return ERROR_PARAMS_INVALID;
  }

// Currently, the AES implementation does not support encrypting values with
// more than 64 bits.
#ifdef USE_AES
  if (buflen > sizeof(uint64_t)) {
    return ERROR_UNSUPPORTED_OPERATION;
  }
#endif

  uint32_t nbits = ctxt->params->nbits;
  uint32_t out_blk_len = ctxt->params->out_blk_len;
  uint32_t nbytes_block = (out_blk_len + 7) / 8;

  // set block_mask to 2^out_blk_len - 1, corresponding to the least significant
  // (out_blk_len - 1) bits
  mpz_t block_mask;
  mpz_init(block_mask);
  mpz_setbit(block_mask, out_blk_len);
  mpz_sub_ui(block_mask, block_mask, 1);

  uint32_t nbytes = (nbits + 7) / 8;
#ifdef USE_AES
  byte prf_input_buf[PRF_INPUT_BYTES];
#else
  byte prf_input_buf[sizeof(uint32_t) + nbytes];
#endif
  memset(prf_input_buf, 0, sizeof(prf_input_buf));

  byte msgbuf[nbytes];
  byte prf_output_buf[PRF_OUTPUT_BYTES];

  // drop any extra bytes that have been provided
  if (buflen >= nbytes) {
    memcpy(msgbuf, buf, nbytes);
  } else {
    memcpy(msgbuf, buf, buflen);
  }

  mpz_t ctxt_val;
  mpz_init(ctxt_val);

  uint32_t *index = (uint32_t*) prf_input_buf;
  byte* value = &prf_input_buf[1];

  mpz_t ctxt_block;
  mpz_init(ctxt_block);

  uint32_t offset = (8 - (nbits % 8)) % 8;
  for (i = 0; i < nbits; i++) {
    // get the current bit of the message
    uint32_t byteind = nbytes - 1 - (i + offset) / 8;
    byte mask = msgbuf[byteind] & (1 << ((7 - (i + offset)) % 8));

    // evaluates the PRF on the prefix (starting with the empty string)
    prf_eval(prf_output_buf, sizeof(prf_output_buf), sk->key,
             prf_input_buf, sizeof(prf_input_buf));

    // convert PRF outputs to a ciphertext block and OR it into the
    // ciphertext
    mpz_import(ctxt_block, nbytes_block, 1, 1, -1, 0, prf_output_buf);
    if (mask > 0) {
      mpz_add_ui(ctxt_block, ctxt_block, 1);
    }
    mpz_and(ctxt_block, ctxt_block, block_mask);
    mpz_mul_2exp(ctxt_block, ctxt_block, (nbits - i - 1) * out_blk_len);
    mpz_ior(ctxt_val, ctxt_val, ctxt_block);

    // add the current bit of the message to the running prefix
    value[byteind] |= mask;

    // increment the index for the next iteration of the loop
    (*index)++;
  }

  size_t bytes_written;
  uint32_t expected_len = (nbits * out_blk_len + 7) / 8;

  mpz_export(ctxt->buf, &bytes_written, 1, 1, -1, 0, ctxt_val);
  if (bytes_written < expected_len) {
    memmove(ctxt->buf + (expected_len - bytes_written), ctxt->buf,
        bytes_written);
    memset(ctxt->buf, 0, expected_len - bytes_written);
  }
  mpz_clear(block_mask);
  mpz_clear(ctxt_val);
  mpz_clear(ctxt_block);

  return ERROR_NONE;
}

int ore_encrypt_ui(ore_ciphertext ctxt, ore_secret_key sk, uint64_t msg) {
  return _ore_encrypt_buf(ctxt, sk, (byte*) &msg, sizeof(msg));
}

int ore_compare(int* result_p, ore_ciphertext ctxt1, ore_ciphertext ctxt2) {
  if(!ctxt1->initialized || !ctxt2->initialized) {
    return ERROR_CTXT_NOT_INITIALIZED;
  }

  if (!_eq_ore_params(ctxt1->params, ctxt2->params)) {
    return ERROR_PARAMS_MISMATCH;
  }

  if (!_is_valid_params(ctxt1->params)) {
    return ERROR_PARAMS_INVALID;
  }

  uint32_t nbits = ctxt1->params->nbits;
  uint32_t out_blk_len = ctxt1->params->out_blk_len;
  uint32_t len = (nbits * out_blk_len + 7) / 8;

  mpz_t ctxt1_val;
  mpz_init(ctxt1_val);
  mpz_import(ctxt1_val, len, 1, 1, -1, 0, ctxt1->buf);

  mpz_t ctxt2_val;
  mpz_init(ctxt2_val);
  mpz_import(ctxt2_val, len, 1, 1, -1, 0, ctxt2->buf);

  // set the modulus to 2^out_blk_len
  mpz_t modulus;
  mpz_init(modulus);
  mpz_setbit(modulus, out_blk_len);

  // construct the block mask to 2^out_blk_len - 1 (and shift accordingly
  // to extract each of the ciphertext blocks)
  mpz_t block_mask;
  mpz_init(block_mask);
  mpz_sub_ui(block_mask, modulus, 1);
  mpz_mul_2exp(block_mask, block_mask, (nbits - 1) * out_blk_len);

  mpz_t tmp1;
  mpz_init(tmp1);

  mpz_t tmp2;
  mpz_init(tmp2);

  int i;
  int res = 0;
  for (i = 0; i < nbits; i++) {
    // extract the ith ciphertext block
    mpz_and(tmp1, ctxt1_val, block_mask);
    mpz_and(tmp2, ctxt2_val, block_mask);

    mpz_cdiv_q_2exp(tmp1, tmp1, (nbits - i - 1) * out_blk_len);
    mpz_cdiv_q_2exp(tmp2, tmp2, (nbits - i - 1) * out_blk_len);

    mpz_sub(tmp1, tmp1, tmp2);
    mpz_mod(tmp1, tmp1, modulus);

    int cmp = mpz_cmp_ui(tmp1, 0);
    if (cmp != 0) {
      cmp = mpz_cmp_ui(tmp1, 1);
      res = (cmp == 0) ? 1 : -1;
      break;
    }

    mpz_cdiv_q_2exp(block_mask, block_mask, out_blk_len);
  }

  mpz_clear(ctxt1_val);
  mpz_clear(ctxt2_val);
  mpz_clear(block_mask);
  mpz_clear(modulus);
  mpz_clear(tmp1);
  mpz_clear(tmp2);

  *result_p = res; // set result output
  return ERROR_NONE;
}

int init_ore_ciphertext(ore_ciphertext ctxt, ore_params params) {
  if (!_is_valid_params(params)) {
    return ERROR_PARAMS_INVALID;
  }

  if (ctxt == NULL || params == NULL) {
    return ERROR_NULL_POINTER;
  }

  uint32_t len = (params->nbits * params->out_blk_len + 7) / 8;
  ctxt->buf = malloc(len);
  if (ctxt->buf == NULL) {
    return ERROR_MEMORY_ALLOCATION;
  }
  memcpy(ctxt->params, params, sizeof(ore_params));

  ctxt->initialized = true;

  return ERROR_NONE;
}

int clear_ore_ciphertext(ore_ciphertext ctxt) {
  if (ctxt == NULL) {
    return ERROR_NONE;
  }

  uint32_t len = (ctxt->params->nbits * ctxt->params->out_blk_len + 7) / 8;
  memset(ctxt->buf, 0, len);
  free(ctxt->buf);

  memset(ctxt, 0, sizeof(ore_ciphertext));

  return ERROR_NONE;
}

int ore_ciphertext_size(ore_params params) {
  return (params->nbits * params->out_blk_len + 7) / 8;
}
