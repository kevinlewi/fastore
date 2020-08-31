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

#include "ore_blk.h"
#include "errors.h"
#include "flags.h"

#include <gmp.h>
#include <stdlib.h>
#include <string.h>

// Helper macro for error handling
static int _error_flag;
#define ERR_CHECK(x) if((_error_flag = x) != ERROR_NONE) { return _error_flag; }

// The ceiling function
#define CEIL(x, y) (((x) + (y) - 1) / (y))

// The ORE encryption scheme is randomized, so the randomness used for
// encryption is derived from an internal PRG (implemented using AES in
// counter mode). This is for demo purposes only. For concrete applications,
// it may be preferable to use a different source for the encryption
// randomness. Note that this implementation is NOT thread-safe, and is
// intended primarily for demo purposes.
static bool _prg_initialized = false;
static uint64_t _counter = 0;
static AES_KEY _prg_key;

// The maximum supported block length in bite (chosen primarily for efficiency
// reasons).
static const int MAX_BLOCK_LEN = 16;

/**
 * Checks if two ore_blk_params structs are equal
 *
 * @param params1 The first set of parameters
 * @param params2 The second set of parameters
 *
 * @return 1 if they are equal, 0 otherwise
 */
static bool _eq_ore_blk_params(ore_blk_params params1, ore_blk_params params2) {
  return (params1->initialized == params2->initialized) &&
         (params1->nbits == params2->nbits) &&
         (params1->block_len == params2->block_len);
}

/**
 * Checks if an ore_param struct is valid by ensuring that the
 * block length is non-zero and less than the maximum supported block
 * length (MAX_BLOCK_LEN).
 *
 * @param params The parameters to check
 *
 * @return true if the parameters are valid, false otherwise
 */
static bool _is_valid_params(ore_blk_params params) {
  if (!params->initialized) {
    return false;
  } else if (params->block_len == 0 || params->block_len > MAX_BLOCK_LEN) {
    return false;
  }

  return true;
}

/**
 * Seeds the internal PRG (used to derive the encryption randomness). The PRG
 * uses a AES in counter mode. To seed the PRG, a fresh AES key is sampled and
 * the counter is initialized to 0.
 */
static void _seed_prg() {
  generate_aes_key(&_prg_key);
  _counter = 0;
  _prg_initialized = true;
}

/**
 * Gets the next block (16 byts) of output from the PRG. The next block is
 * computed by invoking AES on the current value of the counter. The value of
 * the counter is updated afterwards. This PRG implementation is NOT thread-
 * safe, so this library should not be used as is in a multi-threaded
 * execution environment.
 *
 * @param out  Buffer that will hold the next block of the PRG
 *
 * @return ERROR_NONE on success and a corresponding error code on failure
 *         (see errors.h for the full list of possible error codes)
 */
static int _next_prg_block(block* out) {
  return aes_eval(out, &_prg_key, MAKE_BLOCK(0, _counter++));
}

int init_ore_blk_params(ore_blk_params params, uint32_t nbits, uint32_t block_len) {
  params->initialized = true;
  params->nbits = nbits;
  params->block_len = block_len;

  if (!_is_valid_params(params)) {
    return ERROR_PARAMS_INVALID;
  }

  return ERROR_NONE;
}

int ore_blk_setup(ore_blk_secret_key sk, ore_blk_params params) {
  if (!_is_valid_params(params)) {
    return ERROR_PARAMS_INVALID;
  }

  ERR_CHECK(generate_aes_key(&sk->prf_key));
  ERR_CHECK(generate_aes_key(&sk->prp_key));

  memcpy(sk->params, params, sizeof(ore_blk_params));

  sk->initialized = true;

  return ERROR_NONE;
}

int ore_blk_cleanup(ore_blk_secret_key sk) {
  memset(sk, 0, sizeof(ore_blk_secret_key));

  return ERROR_NONE;
}

#ifdef USE_AES_RO
  /**
   * Evaluates a keyed hash function on a particular value (used to construct
   * the right ciphertexts). This function uses AES to instantiate the random
   * oracle: H(k, x) = AES(x, k). This is sound, for instance, if we model
   * AES as an ideal cipher.
   *
   * @param out  An output buffer to store the output of the hash function
   *             (assumed to be of the correct size)
   * @param key  The key to the keyed hash function
   * @param val  The value to evaluate the hash function on
   *
   * @return ERROR_NONE on success and a corresponding error code on failure
   *         (see errors.h for the full list of possible error codes)
   */
  static inline int _eval_keyed_hash_aes_ro(uint8_t* out, const block key, const block val) {
    AES_KEY aes_key;
    setup_aes_key(&aes_key, (byte*) &val, sizeof(block));

    block output;
    ERR_CHECK(aes_eval(&output, &aes_key, key));

    *out = (*(uint8_t*) &output) & 1;

    return ERROR_NONE;
  }

  /**
   * Evaluates a keyed hash function on a single value using multiple keys
   * (used to construct the right ciphertexts). This function uses AES to
   * instantiate the particular random oracle: H(k, x) = lsb(AES(x, k)). Batch
   * evaluation of AES can be pipelined (assuming support for the AES-NI
   * instruction set), becuase the same value is used (x is reused across all
   * of the invocations).
   *
   * @param out      An output buffer to store the vector of outputs of the
   *                 hash function (assumed to be of the correct size)
   * @param nblocks  The number of hash function evaluations
   * @param keys     The vector of keys (of length nblocks) used to apply the
   *                 hash function
   * @param val      The value to evaluate the hash functions on
   *
   * @return ERROR_NONE on success and a corresponding error code on failure
   *         (see errors.h for the full list of possible error codes)
   */
  static inline int _eval_keyed_hash_batch_aes_ro(uint8_t* out, uint32_t nblocks,
                                                  const block* keys, const block val) {
    int i;
    AES_KEY aes_key;
    setup_aes_key(&aes_key, (byte*) &val, sizeof(block));

    block* outputs = malloc(nblocks * sizeof(block));
    ERR_CHECK(aes_eval_blocks(outputs, nblocks, &aes_key, keys));

    for (i = 0; i < nblocks; i++) {
      out[i] = (*(uint8_t*) &outputs[i]) & 1;
    }

    free(outputs);

    return ERROR_NONE;
  }
#else
  /**
   * Evaluates a keyed hash function on a particular value (used to construct
   * the right ciphertexts). This function uses SHA-256 to instantiate the
   * random oracle: H(k, x) = lsb(SHA-256(k || x)).
   *
   * @param out  An output buffer to store the output of the hash function
   *             (assumed to be of the correct size)
   * @param key  The key to the keyed hash function
   * @param val  The value to evaluate the hash function on
   *
   * @return ERROR_NONE on success and a corresponding error code on failure
   *         (see errors.h for the full list of possible error codes)
   */
  static inline int _eval_keyed_hash_sha256(uint8_t* out, const block key, const block val) {
    static byte inputbuf[AES_OUTPUT_BYTES + sizeof(block)];
    memcpy(inputbuf, &key, sizeof(block));
    memcpy(inputbuf + sizeof(block), &val, sizeof(block));

    byte dst[SHA256_OUTPUT_BYTES];
    ERR_CHECK(sha_256(dst, sizeof(dst), inputbuf, sizeof(inputbuf)));

    *out = dst[0] & 1;

    return ERROR_NONE;
  }
#endif

/**
 * Evaluates a keyed hash function on a particular value (used to construct
 * the right ciphertexts). The precise details are described in Section 3.1 of
 * the paper (https://eprint.iacr.org/2016/612.pdf). In the security analysis,
 * the hash function is modeled as a random oracle. We give two instantiations
 * based on different choices of the random oracle. The first is based on AES
 * (provably secure if we model AES as an ideal cipher) and the second is
 * based on the more traditional SHA-256. The choice of hash function can be
 * controlled by setting/unsetting the USE_AES_RO flag in flags.h.
 *
 * @param out  An output buffer to store the output of the hash function
 *             (assumed to be of the correct size)
 * @param key  The key to the keyed hash function
 * @param val  The value to evaluate the hash function on
 *
 * @return ERROR_NONE on success and a corresponding error code on failure
 *         (see errors.h for the full list of possible error codes)
 */
static inline int _eval_keyed_hash(uint8_t* out, const block key, const block val) {
  #ifdef USE_AES_RO
    return _eval_keyed_hash_aes_ro(out, key, val);
  #else
    return _eval_keyed_hash_sha256(out, key, val);
  #endif
}

/**
 * Evaluates a keyed hash function using multiple keys on the same block.
 * Using the AES-based random oracle instantiation together with AES-NI,
 * the batch version is faster (by pipelining the evaluations of the AES
 * round functions). With SHA-256, we just invoke the keyed hash separately
 * using each of the keys.
 *
 * @param out      An output buffer to store the vector of outputs of the hash
 *                 function (assumed to be of the correct size)
 * @param nblocks  The number of hash function evaluations
 * @param keys     The vector of keys (of length nblocks) used to apply the hash function
 * @param val      The value to evaluate the hash functions on
 *
 * @return ERROR_NONE on success and a corresponding error code on failure
 *         (see errors.h for the full list of possible error codes)
 */
static inline int _eval_keyed_hash_batch(uint8_t* out, uint32_t nblocks,
                                         const block* keys, const block val) {
  #ifdef USE_AES_RO
    return _eval_keyed_hash_batch_aes_ro(out, nblocks, keys, val);
  #else
    for (int i = 0; i < nblocks; i++) {
      ERR_CHECK(_eval_keyed_hash_sha256(&out[i], keys[i], val));
    }
    return ERROR_NONE;
  #endif
}

/**
  * Encrypts a single block of the ORE ciphertext using the small-domain ORE.
  * This algorithm is described in Section 3 of the paper
  * (https://eprint.iacr.org/2016/612.pdf). The output ciphertext consists of
  * a left ciphertext and a right ciphertext with the property that the right
  * ciphertext provides semantic security.
  *
  * @param comp_left   A buffer to hold the left ciphertext component
  * @param comp_right  A buffer to hold the right ciphertext component
  * @param sk          The secret key for the ORE scheme
  * @param nonce       The nonce used for encryption (should be unique for
  *                    each ciphertext)
  * @param block_ind   The index of the current block (used to construct a PRF
  *                    on variable-length inputs)
  * @param prefix      The prefix of the current block (used for key
  *                    derivation for encrypting the current block)
  * @param val         The value of the block to be encrypted (at the current
  *                    index)
  *
  * @return ERROR_NONE on success and a corresponding error code on failure
  *         (see errors.h for the full list of possible error codes)
  */
static int _ore_blk_encrypt_block(byte* comp_left, byte* comp_right, ore_blk_secret_key sk,
                                  block nonce, uint64_t block_ind, uint64_t prefix, uint64_t val) {
  int i;
  uint32_t block_len = sk->params->block_len;
  uint32_t nslots = 1 << block_len;

  // derive PRP key for this prefix
  block prp_key_buf;
  ERR_CHECK(aes_eval(&prp_key_buf, &sk->prp_key, MAKE_BLOCK(block_ind, prefix)));

  AES_KEY prp_key;
  ERR_CHECK(setup_aes_key(&prp_key, (byte*) &prp_key_buf, sizeof(block)));

  // construct left ciphertext (PRP evaluation on the value)
  uint64_t pix = 0;
  ERR_CHECK(prp_eval((byte*) &pix, &prp_key, (byte*) &val, block_len));

  block key;
  uint64_t prefix_shifted = prefix << block_len;
  ERR_CHECK(aes_eval(&key, &sk->prf_key, MAKE_BLOCK(block_ind, prefix_shifted | pix)));
  memcpy(comp_left, &key, sizeof(block));
  memcpy(comp_left + sizeof(block), &pix, CEIL(block_len, 8));

  // construct right ciphertext (encryption of comparison vector under keys
  // derived from PRF)
  block* inputs = malloc(sizeof(block) * nslots);
  block* keys   = malloc(sizeof(block) * nslots);
  for (i = 0; i < nslots; i++) {
    inputs[i] = MAKE_BLOCK(block_ind, prefix_shifted | i);
  }
  ERR_CHECK(aes_eval_blocks(keys, nslots, &sk->prf_key, inputs));

  uint64_t* pi_inv = malloc(sizeof(uint64_t) * nslots);
  ERR_CHECK(prp_inv_eval_all(pi_inv, &prp_key, block_len));

  mpz_t ctxt_block;
  mpz_init(ctxt_block);

  uint8_t* r = malloc(sizeof(uint8_t) * nslots);
  ERR_CHECK(_eval_keyed_hash_batch(r, nslots, keys, nonce));

  for (i = 0; i < nslots; i++) {
    uint8_t v = (pi_inv[i] <= val) ? 1 : 0;
    v ^= r[i];

    if (v == 1) {
      mpz_setbit(ctxt_block, i);
    }
  }

  uint64_t bytes_written;
  uint32_t expected_len = CEIL(nslots, 8);

  mpz_export(comp_right, &bytes_written, 1, 1, -1, 0, ctxt_block);
  if (bytes_written < expected_len) {
    memmove(comp_right + (expected_len - bytes_written), comp_right, bytes_written);
    memset(comp_right, 0, expected_len - bytes_written);
  }

  mpz_clear(ctxt_block);
  free(inputs);
  free(keys);
  free(pi_inv);
  free(r);

  return ERROR_NONE;
}

int ore_blk_encrypt_ui(ore_blk_ciphertext ctxt, ore_blk_secret_key sk, uint64_t msg) {
  if (!sk->initialized) {
    return ERROR_SK_NOT_INITIALIZED;
  }

  if (!ctxt->initialized) {
    return ERROR_CTXT_NOT_INITIALIZED;
  }

  if (!_eq_ore_blk_params(ctxt->params, sk->params)) {
    return ERROR_PARAMS_MISMATCH;
  }

  if (!_is_valid_params(ctxt->params)) {
    return ERROR_PARAMS_INVALID;
  }

  if (!_prg_initialized) {
    _seed_prg();
  }

  uint32_t nbits = ctxt->params->nbits;
  uint32_t block_len = ctxt->params->block_len;
  uint32_t nslots = 1 << block_len;
  uint32_t nblocks = CEIL(nbits, block_len);

  uint64_t block_mask = (1 << block_len) - 1;
  block_mask <<= (block_len * (nblocks - 1));

  // choose nonce
  block nonce;
  ERR_CHECK(_next_prg_block(&nonce));
  memcpy(ctxt->comp_right, &nonce, sizeof(block));

  // set up left and right pointers for each block
  byte* comp_left = ctxt->comp_left;
  byte* comp_right = ctxt->comp_right + sizeof(block);

  uint32_t len_left_block  = AES_BLOCK_LEN + CEIL(nbits, 8);
  uint32_t len_right_block = CEIL(nslots, 8);

  // process each block
  uint64_t prefix = 0;
  int i;
  for(i = 0; i < nblocks; i++) {
    uint64_t cur_block = msg & block_mask;
    cur_block >>= block_len * (nblocks - i - 1);

    block_mask >>= block_len;

    ERR_CHECK(_ore_blk_encrypt_block(comp_left, comp_right, sk, nonce, i, prefix, cur_block));

    // update prefix
    prefix <<= block_len;
    prefix |= cur_block;

    // update block pointers
    comp_left  += len_left_block;
    comp_right += len_right_block;
  }

  return ERROR_NONE;
}

int ore_blk_compare(int* result_p, ore_blk_ciphertext ctxt1, ore_blk_ciphertext ctxt2) {
  if (!ctxt1->initialized || !ctxt2->initialized) {
    return ERROR_CTXT_NOT_INITIALIZED;
  }

  if (!_eq_ore_blk_params(ctxt1->params, ctxt2->params)) {
    return ERROR_PARAMS_MISMATCH;
  }

  if (!_is_valid_params(ctxt1->params)) {
    return ERROR_PARAMS_INVALID;
  }

  uint32_t nbits = ctxt1->params->nbits;
  uint32_t block_len = ctxt1->params->block_len;
  uint32_t nslots = 1 << block_len;
  uint32_t nblocks = CEIL(nbits, block_len);

  block nonce = *(block*) ctxt2->comp_right;

  uint32_t offset_left = 0;
  uint32_t offset_right = sizeof(block);

  uint32_t len_left_block  = AES_BLOCK_LEN + CEIL(nbits, 8);
  uint32_t len_right_block = CEIL(nslots, 8);

  // compare each block
  bool is_equal = true;
  int i;
  for (i = 0; i < nblocks; i++) {
    if (memcmp(ctxt1->comp_left + offset_left, ctxt2->comp_left + offset_left, AES_BLOCK_LEN) != 0) {
      is_equal = false;
      break;
    }

    offset_left  += len_left_block;
    offset_right += len_right_block;
  }
  if (is_equal) {
    *result_p = 0;
    return ERROR_NONE;
  }

  uint64_t index = 0;
  memcpy(&index, ctxt1->comp_left + offset_left + AES_KEY_BYTES, CEIL(block_len, 8));

  mpz_t ctxt_block;
  mpz_init(ctxt_block);
  mpz_import(ctxt_block, CEIL(nslots, 8), 1, 1, -1, 0, ctxt2->comp_right + offset_right);

  uint8_t r;

  block key_block;
  memcpy(&key_block, ctxt1->comp_left + offset_left, sizeof(block));
  ERR_CHECK(_eval_keyed_hash(&r, key_block, nonce));
  uint8_t v = mpz_tstbit(ctxt_block, index) ^ r;

  *result_p = (v == 1) ? -1 : 1;

  mpz_clear(ctxt_block);

  return ERROR_NONE;
}

/**
 * Computes the length of a left ciphertext.
 *
 * @param params The parameters for the ORE scheme
 *
 * @return the length of a left ciphertext for the specific choice of
 *         parameters
 */
static inline int _ore_blk_ciphertext_len_left(ore_blk_params params) {
  uint32_t nblocks = CEIL(params->nbits, params->block_len);

  return (AES_BLOCK_LEN + CEIL(params->nbits, 8)) * nblocks;
}

/**
 * Computes the length of a right ciphertext.
 *
 * @param params The parameters for the ORE scheme
 *
 * @return the length of a right ciphertext for the specific choice of
 *         parameters
 */
static inline int _ore_blk_ciphertext_len_right(ore_blk_params params) {
  uint32_t block_len = params->block_len;
  uint32_t nslots = 1 << block_len;
  uint32_t nblocks = CEIL(params->nbits, block_len);

  return AES_BLOCK_LEN + CEIL(nslots, 8) * nblocks;
}

int init_ore_blk_ciphertext(ore_blk_ciphertext ctxt, ore_blk_params params) {
  if (!_is_valid_params(params)) {
    return ERROR_PARAMS_INVALID;
  }

  if (ctxt == NULL || params == NULL) {
    return ERROR_NULL_POINTER;
  }

  ctxt->comp_left = malloc(_ore_blk_ciphertext_len_left(params));
  if (ctxt->comp_left == NULL) {
    return ERROR_MEMORY_ALLOCATION;
  }

  ctxt->comp_right = malloc(_ore_blk_ciphertext_len_right(params));
  if (ctxt->comp_right == NULL) {
    return ERROR_MEMORY_ALLOCATION;
  }

  memcpy(ctxt->params, params, sizeof(ore_blk_params));

  ctxt->initialized = true;

  return ERROR_NONE;
}

int clear_ore_blk_ciphertext(ore_blk_ciphertext ctxt) {
  if (ctxt == NULL) {
    return ERROR_NONE;
  }

  if (!_is_valid_params(ctxt->params)) {
    return ERROR_PARAMS_INVALID;
  }

  memset(ctxt->comp_left, 0, _ore_blk_ciphertext_len_left(ctxt->params));
  free(ctxt->comp_left);

  memset(ctxt->comp_right, 0, _ore_blk_ciphertext_len_right(ctxt->params));
  free(ctxt->comp_right);

  memset(ctxt, 0, sizeof(ore_blk_ciphertext));

  return ERROR_NONE;
}

int ore_blk_ciphertext_size(ore_blk_params params) {
  return _ore_blk_ciphertext_len_left(params) + _ore_blk_ciphertext_len_right(params);
}
