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

#include <assert.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <stdbool.h>
#include <stdint.h>

// Helper macro for error handling
static int _error_flag;
#define ERR_CHECK(x) if((_error_flag = x) != ERROR_NONE) { return _error_flag; }

int generate_prf_key(prf_key key) {
#ifdef USE_AES
  return generate_aes_key(&key->key);
#else
  FILE* f = fopen("/dev/urandom", "r");
  if (f == NULL) {
    return ERROR_RANDOMNESS;
  }

  int bytes_read = fread(key->keybuf, 1, sizeof(key->keybuf), f);
  if (bytes_read != sizeof(key->keybuf)) {
    return ERROR_RANDOMNESS;
  }

  fclose(f);

  return ERROR_NONE;
#endif
}


int prf_eval(byte* dst, uint32_t dstlen, prf_key key, byte* src, uint32_t srclen) {
  if (dstlen != PRF_OUTPUT_BYTES) {
    return ERROR_DSTLEN_INVALID;
  }

#ifdef USE_AES
  if (srclen != PRF_INPUT_BYTES) {
    return ERROR_SRCLEN_INVALID;
  }
  block* dst_blk = (block*) dst;
  block* src_blk = (block*) src;

  return aes_eval(dst_blk, &key->key, *src_blk);
#else
  uint32_t outlen;
  HMAC(EVP_sha256(), key->keybuf, sizeof(key->keybuf), src, srclen, dst, &outlen);
  assert(outlen == dstlen);

  return ERROR_NONE;
#endif
}

int generate_aes_key(AES_KEY* key) {
  byte keybuf[AES_KEY_BYTES];

  FILE* f = fopen("/dev/urandom", "r");
  if (f == NULL) {
    return ERROR_RANDOMNESS;
  }

  int bytes_read = fread(keybuf, 1, AES_KEY_BYTES, f);
  if (bytes_read != AES_KEY_BYTES) {
    return ERROR_RANDOMNESS;
  }

  fclose(f);

  AES_128_Key_Expansion(keybuf, key);
  memset(keybuf, 0, sizeof(keybuf));

  return ERROR_NONE;
}

int setup_aes_key(AES_KEY* key, byte* buf, uint32_t buflen) {
  if (buflen != AES_KEY_BYTES) {
    return ERROR_PRF_KEYLEN_INVALID;
  }

  AES_128_Key_Expansion(buf, key);

  return ERROR_NONE;
}

/**
 * Evaluate one round of a Feistel network (with AES as the underlying PRF).
 * The input domain (nbits) can be at most 128 bits.
 *
 * @param dst_l    The output left block
 * @param dst_r    The output right block
 * @param key      The PRF key
 * @param src_l    The input left block
 * @param src_r    The input right block
 * @param nbits    The number of bits in the domain/range of the PRF
 *
 * @return ERROR_NONE on success and a corresponding error code on failure
 *         (see errors.h for the full list of possible error codes)
 */
static int _feistel_round(uint64_t* dst_l, uint64_t* dst_r, const AES_KEY* key,
                          uint64_t src_l, uint64_t src_r, uint32_t nbits) {
  *dst_l = src_r;

  block prf_in = MAKE_BLOCK((uint64_t) 0, src_r);

  block prf_out;
  aes_eval(&prf_out, key, prf_in);

  uint64_t r = *(uint64_t*) &prf_out;
  r %= ((uint64_t) 1) << (nbits / 2);

  *dst_r = src_l ^ r;

  return ERROR_NONE;
}

/**
 * Evaluate one round of a Feistel network (with AES as the underlying PRF) on
 * multiple blocks. This leverages pipelining in the AES-NI instruction set.
 *
 * @param dst_l    A vector of left blocks (output)
 * @param dst_r    A vector of right blocks (output)
 * @param nblocks  The number of blocks to evaluate on
 * @param key      The PRF key
 * @param src_l    A vector of left blocks (input)
 * @param src_r    A vector of right blocks (input)
 * @param nbits    The number of bits in the domain/range of the PRF
 *
 * @return ERROR_NONE on success and a corresponding error code on failure
 *         (see errors.h for the full list of possible error codes)
 */
static int _feistel_round_batch(uint64_t* dst_l, uint64_t* dst_r, uint32_t nblocks,
                                const AES_KEY* key, const uint64_t* src_l, const uint64_t* src_r,
                                uint32_t nbits) {
  int i;
  memcpy(dst_l, src_r, nblocks * sizeof(uint64_t));

  block* prf_inputs = malloc(nblocks * sizeof(block));
  block* prf_outputs = malloc(nblocks * sizeof(block));
  if (prf_inputs == NULL || prf_outputs == NULL) {
    return ERROR_MEMORY_ALLOCATION;
  }

  for (i = 0; i < nblocks; i++) {
    prf_inputs[i] = MAKE_BLOCK((uint64_t) 0, src_r[i]);
  }

  ERR_CHECK(aes_eval_blocks(prf_outputs, nblocks, key, prf_inputs));

  uint64_t mask = (((uint64_t) 1) << (nbits / 2)) - 1;
  for (i = 0; i < nblocks; i++) {
    uint64_t r = *(uint64_t*) &prf_outputs[i];
    dst_r[i] = src_l[i] ^ (r & mask);
  }

  free(prf_inputs);
  free(prf_outputs);

  return ERROR_NONE;
}

/**
 * Derives the round keys for a PRP constructed via a 3-round Feistel
 * network.
 *
 * @param prf_keys  An output vector thtat will hold three round keys for the
 *                  Feistel network
 * @param prp_key   The PRP key
 *
 * @return ERROR_NONE on success and a corresponding error code on failure
 *         (see errors.h for the full list of possible error codes)
 */
int _prp_key_expand(AES_KEY* prf_keys, const AES_KEY* prp_key) {
  int i;
  block feistel_keys[3];
  for (i = 0; i < 3; i++) {
    feistel_keys[i] = MAKE_BLOCK((uint64_t) 0, (uint64_t) i);
  }
  AES_ecb_encrypt_blks_3(feistel_keys, prp_key);

  for (i = 0; i < 3; i++) {
    AES_128_Key_Expansion((byte*) feistel_keys + i, prf_keys + i);
  }

  return ERROR_NONE;
}

/**
 * Takes an input value (to a PRP over a domain with nbits) and decomposes it
 * into two separate blocks, each with length nbits/2. The "left" and "right"
 * blocks are then used as inputs to a Feistel network that implements the PRP.
 *
 * @param val_l  The left output block (with nbits/2 bits)
 * @param val_r  The right output block (with nbits/2 bits)
 * @param src    The value to decompose (with nbits)
 * @param nbits  The number of bits in the domain (of the PRP)
 *
 * @return ERROR_NONE on success
 */
int _extract_blocks(uint64_t* val_l, uint64_t* val_r, const byte* src, uint32_t nbits) {
  uint64_t val = 0;
  memcpy(&val, src, (nbits + 7) / 8);

  uint32_t len = nbits / 2;
  uint64_t mask_r = ((((uint64_t) 1) << len) - 1);
  uint64_t mask_l = mask_r << len;

  *val_r = val & mask_r;
  *val_l = (val & mask_l) >> len;

  return ERROR_NONE;
}

/**
 * Implements a 3-round Feistel network (or inverse Feistel network) for PRP
 * evaluation. The underlying PRF is instantiated with AES (outputs truncated
 * to match the PRP domain size).
 *
 * @param dst    The destination buffer to write the output of the PRP
 *               (should be at least nbits long)
 * @param key    The PRP key
 * @param src    The source value (nbits long)
 * @param nbits  The number of bits in the domain of the PRP
 * @param inv    Whether to compute the inverse of the PRP or not
 *
 * @return ERROR_NONE on success and a corresponding error code on failure
 *         (see errors.h for the full list of possible error codes)
 */
static int _prp_eval_helper(byte* dst, const AES_KEY* key, const byte* src,
                            uint32_t nbits, bool inv) {
  int i;
  if (nbits % 2 != 0 || nbits > 64) {
    return ERROR_PRP_BITLEN_INVALID;
  }

  AES_KEY keys[3];
  ERR_CHECK(_prp_key_expand(keys, key));

  uint64_t val_l, val_r, val_l_new, val_r_new;

  ERR_CHECK(_extract_blocks(&val_l, &val_r, src, nbits));

  if (inv) {
    uint64_t tmp = val_l;
    val_l = val_r;
    val_r = tmp;
  }
  for (i = 0; i < 3; i++) {
    AES_KEY* round_key = inv ? &keys[2-i] : &keys[i];
    ERR_CHECK(_feistel_round(&val_l_new, &val_r_new, round_key, val_l, val_r, nbits));

    val_l = val_l_new;
    val_r = val_r_new;
  }

  if (inv) {
    uint64_t tmp = val_l;
    val_l = val_r;
    val_r = tmp;
  }
  uint64_t output = (val_l << (nbits / 2)) | val_r;
  memcpy(dst, &output, (nbits + 7) / 8);

  return ERROR_NONE;
}

int prp_eval(byte* dst, const AES_KEY* key, const byte* src, uint32_t nbits) {
  return _prp_eval_helper(dst, key, src, nbits, false);
}

int prp_inv_eval(byte* dst, const AES_KEY* key, const byte* src, uint32_t nbits) {
  return _prp_eval_helper(dst, key, src, nbits, true);
}

/**
 * Implements a 3-round Feistel network (or inverse Feistel network) for PRP
 * evaluation (on all of the inputs in the domain). The underlying PRF is
 * instantiated with AES (outputs truncated to match the PRP domain size).
 *
 * @param dst    The destination buffer to write the output of the PRP
 *               (should be at least nbits*2^nbits long)
 * @param key    The PRP key
 * @param nbits  The number of bits in the domain of the PRP
 * @param inv    Whether to compute the inverse of the PRP or not
 *
 * @return ERROR_NONE on success and a corresponding error code on failure
 *         (see errors.h for the full list of possible error codes)
 */
static int _prp_eval_all_helper(uint64_t* dst, const AES_KEY* key, uint32_t nbits, bool inv) {
  int i;

  if (nbits % 2 != 0 || nbits > 16) {
    return ERROR_PRP_BITLEN_INVALID;
  }

  AES_KEY keys[3];
  ERR_CHECK(_prp_key_expand(keys, key));

  uint32_t nblocks = 1 << nbits;
  uint64_t* val_l = malloc(nblocks * sizeof(uint64_t));
  uint64_t* val_r = malloc(nblocks * sizeof(uint64_t));

  if (val_l == NULL || val_r == NULL) {
    return ERROR_MEMORY_ALLOCATION;
  }

  for (i = 0; i < nblocks; i++) {
    _extract_blocks(&val_l[i], &val_r[i], (byte*) &i, nbits);
  }

  uint64_t* val_l_new = malloc(nblocks * sizeof(uint64_t));
  uint64_t* val_r_new = malloc(nblocks * sizeof(uint64_t));
  if (val_l_new == NULL || val_r_new == NULL) {
    return ERROR_MEMORY_ALLOCATION;
  }

  if (inv) {
    uint64_t* tmp = val_l;
    val_l = val_r;
    val_r = tmp;
  }

  for (i = 0; i < 3; i++) {
    AES_KEY *round_key = inv ? &keys[2-i] : &keys[i];
    ERR_CHECK(_feistel_round_batch(val_l_new, val_r_new, nblocks, round_key,
                                   val_l, val_r, nbits));

    memcpy(val_l, val_l_new, nblocks * sizeof(uint64_t));
    memcpy(val_r, val_r_new, nblocks * sizeof(uint64_t));
  }

  if (inv) {
    uint64_t* tmp = val_l;
    val_l = val_r;
    val_r = tmp;
  }

  for (i = 0; i < nblocks; i++) {
    dst[i] = (val_l[i] << (nbits / 2)) | val_r[i];
  }

  free(val_l);
  free(val_r);
  free(val_l_new);
  free(val_r_new);

  return ERROR_NONE;
}

int prp_eval_all(uint64_t* dst, const AES_KEY* key, uint32_t nbits) {
  return _prp_eval_all_helper(dst, key, nbits, false);
}

int prp_inv_eval_all(uint64_t* dst, const AES_KEY* key, uint32_t nbits) {
  return _prp_eval_all_helper(dst, key, nbits, true);
}

int sha_256(byte* dst, uint32_t dstlen, byte* src, uint32_t srclen) {
  if (dstlen != SHA256_OUTPUT_BYTES) {
    return ERROR_DSTLEN_INVALID;
  }

  SHA256_CTX ctx;
  SHA256_Init(&ctx);
  SHA256_Update(&ctx, src, srclen);
  SHA256_Final(dst, &ctx);

  return ERROR_NONE;
}
