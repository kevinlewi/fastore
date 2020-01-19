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

#include "errors.h"
#include "ore_blk.h"

#include <stdio.h>
#include <time.h>

static int _err;
#define ERR_CHECK(x) if((_err = x) != ERROR_NONE) { return _err; }

/**
 * Benchmarking code for ORE scheme. Measures time to encrypt random values
 * and time to compare ORE ciphertexts. The number of iterations is scaled
 * with the approximate run-time of each operation. Measurements taken for
 * wide range of bitlengths (n) and block sizes (k).
 */
int main(int argc, char** argv) {
  const uint32_t NBITS[]      = {8, 16, 24, 32, 48, 64};
  const uint32_t BLOCK_LEN[]  = {  2,   4,   6,   8, 10, 12, 14, 16};
  const uint32_t ENC_TRIALS[] = {400, 400, 300, 200, 80, 10,  4,  1};
  const uint32_t CMP_TRIALS[] = {200, 200, 200, 100, 50, 25, 10,  5};

#ifdef USE_AES_RO
  const uint32_t ENC_SCALE = 250;
  const uint32_t CMP_SCALE = 50000;
#else
  const uint32_t ENC_SCALE = 50;
  const uint32_t CMP_SCALE = 20000;
#endif

  uint32_t nbits_len = sizeof(NBITS) / sizeof(int);
  uint32_t nblock_len = sizeof(BLOCK_LEN) / sizeof(int);

#ifdef USE_AES_RO
  printf("Instantiating random oracle with AES-based construction\n\n");
#else
  printf("Instantiating random oracle with SHA256\n\n");
#endif
  printf("n = bit length of plaintext space\n");
  printf("k = block size (in bits)\n\n");
  printf("%2s %2s %8s %15s %15s %8s %15s %15s %15s\n",
         "n", "k", "iter", "enc avg (us)", "enc total (s)", "iter", "cmp avg (us)", "cmp total (s)", "len (bytes)");

  int i, j, k;
  for (i = 0; i < nbits_len; i++) {
    for (j = 0; j < nblock_len; j++) {
      if (BLOCK_LEN[j] > NBITS[i]) {
        continue;
      }

      ore_blk_params params;
      ERR_CHECK(init_ore_blk_params(params, NBITS[i], BLOCK_LEN[j]));

      ore_blk_secret_key sk;
      ERR_CHECK(ore_blk_setup(sk, params));

      ore_blk_ciphertext ctxt;
      ERR_CHECK(init_ore_blk_ciphertext(ctxt, params));

      uint32_t n_trials = ENC_TRIALS[j] * ENC_SCALE;
      clock_t start_time = clock();
      uint32_t enc_trials = 0;
      while(clock() - start_time < CLOCKS_PER_SEC) {
        for (k = 0; k < n_trials; k++) {
          ore_blk_encrypt_ui(ctxt, sk, rand());
        }
        enc_trials += n_trials;
      }
      double enc_time_elapsed = (double)(clock() - start_time) / CLOCKS_PER_SEC;
      double enc_time = enc_time_elapsed / enc_trials * 1000000;

      ore_blk_ciphertext ctxt2;
      ERR_CHECK(init_ore_blk_ciphertext(ctxt2, params));
      ore_blk_encrypt_ui(ctxt2, sk, rand());

      int res;

      uint32_t cmp_trials = 0;
      n_trials = CMP_TRIALS[j] * CMP_SCALE;
      start_time = clock();
      while(clock() - start_time < CLOCKS_PER_SEC) {
        for (k = 0; k < n_trials; k++) {
         ore_blk_compare(&res, ctxt, ctxt2);
        }
        cmp_trials += n_trials;
      }
      double cmp_time_elapsed = (double)(clock() - start_time) / CLOCKS_PER_SEC;
      double cmp_time = cmp_time_elapsed / n_trials * 1000000;

      printf("%2d %2d %8d %15.2f %15.2f %8d %15.2f %15.2f %15d\n",
             NBITS[i], BLOCK_LEN[j], enc_trials, enc_time, enc_time_elapsed,
             cmp_trials, cmp_time, cmp_time_elapsed, ore_blk_ciphertext_size(params));

      ERR_CHECK(clear_ore_blk_ciphertext(ctxt));
      ERR_CHECK(ore_blk_cleanup(sk));
    }
  }

  return 0;
}
