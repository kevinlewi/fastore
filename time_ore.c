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

#include "ore.h"
#include "errors.h"
#include "flags.h"

#include <stdio.h>
#include <time.h>

static int _err;
#define ERR_CHECK(x) if((_err = x) != ERROR_NONE) { return _err; }

/**
 * Benchmarking code for ORE scheme. Measures time to encrypt random values
 * and time to compare ORE ciphertexts. The number of iterations is scaled
 * with the approximate run-time of each operation. The block size for all
 * benchmarks is fixed at 2 (smallest possible).
 */
int main(int argc, char** argv) {
  const uint32_t NBITS[] = {8, 16, 24, 32, 48, 64};
  const uint32_t OUT_BLK_LEN = 2;
#ifdef USE_AES
  const int N_ENC_TRIALS = 2000000;
  const int N_CMP_TRIALS = 2000000;
#else
  const int N_ENC_TRIALS = 100000;
  const int N_CMP_TRIALS = 3000000;
#endif

  uint32_t nbits_len = sizeof(NBITS) / sizeof(int);

#ifdef USE_AES
  printf("Instantiating PRF with AES\n\n");
#else
  printf("Instantiating PRF with HMAC-SHA256\n\n");
#endif

  printf("n = bit length of plaintext space\n");
  printf("k = block size (in bits)\n\n");

  printf("%2s %2s %8s %15s %15s %8s %15s %15s %15s\n",
         "n", "k", "iter", "enc avg (us)", "enc total (s)", "iter", "cmp avg (us)", "cmp total (s)", "len (bytes)");

  int i, k;
  for (i = 0; i < nbits_len; i++) {
    ore_params params;
    ERR_CHECK(init_ore_params(params, NBITS[i], OUT_BLK_LEN));

    ore_secret_key sk;
    ERR_CHECK(ore_setup(sk, params));

    ore_ciphertext ctxt;
    ERR_CHECK(init_ore_ciphertext(ctxt, params));

    clock_t start_time = clock();
    int enc_trials = N_ENC_TRIALS / (i + 1);
    for (k = 0; k < enc_trials; k++) {
      ERR_CHECK(ore_encrypt_ui(ctxt, sk, rand()));
    }
    double enc_time_elapsed = (double)(clock() - start_time) / CLOCKS_PER_SEC;
    double enc_time = enc_time_elapsed / enc_trials * 1000000;

    int res;

    ore_ciphertext ctxt2;
    ERR_CHECK(init_ore_ciphertext(ctxt2, params));
    ore_encrypt_ui(ctxt, sk, rand());

    start_time = clock();
    for (k = 0; k < N_CMP_TRIALS; k++) {
      ore_compare(&res, ctxt, ctxt2);
    }
    double cmp_time_elapsed = (double)(clock() - start_time) / CLOCKS_PER_SEC;
    double cmp_time = cmp_time_elapsed / N_CMP_TRIALS * 1000000;

    printf("%2d %2d %8d %15.2f %15.2f %8d %15.2f %15.2f %15d\n",
         NBITS[i], OUT_BLK_LEN, enc_trials, enc_time, enc_time_elapsed,
         N_CMP_TRIALS, cmp_time, cmp_time_elapsed, ore_ciphertext_size(params));

    ERR_CHECK(clear_ore_ciphertext(ctxt));
    ERR_CHECK(ore_cleanup(sk));
  }

  return 0;
}
