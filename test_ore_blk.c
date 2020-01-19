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
#include "ore_blk.h"
#include "errors.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

static int _error;
#define ERR_CHECK(x) if((_error = x) != ERROR_NONE) { return _error; }

static const int N_TRIALS = 500;

/**
 * Generates two random 32-bit integers and encrypts them (with an 8-bit block size).
 *
 * The encrypted integers are chosen randomly.
 *
 * @return 0 on success, -1 on failure, and an error if it occurred during the
 * encryption or comparison phase
 */
static int check_ore_blk() {
  int nbits = 32;
  int block_len = 8;

  uint64_t n1 = rand() % (((uint64_t) 1) << nbits);
  uint64_t n2 = rand() % (((uint64_t) 1) << nbits);

  int cmp = (n1 < n2) ? -1 : 1;
  if (n1 == n2) {
    cmp = 0;
  }

  ore_blk_params params;
  ERR_CHECK(init_ore_blk_params(params, nbits, block_len));

  ore_blk_secret_key sk;
  ERR_CHECK(ore_blk_setup(sk, params));

  ore_blk_ciphertext ctxt1;
  ERR_CHECK(init_ore_blk_ciphertext(ctxt1, params));

  ore_blk_ciphertext ctxt2;
  ERR_CHECK(init_ore_blk_ciphertext(ctxt2, params));

  ERR_CHECK(ore_blk_encrypt_ui(ctxt1, sk, n1));
  ERR_CHECK(ore_blk_encrypt_ui(ctxt2, sk, n2));

  int ret = 0;
  int res;
  ERR_CHECK(ore_blk_compare(&res, ctxt1, ctxt2));
  if (res != cmp) {
    ret = -1;
  }

  ERR_CHECK(clear_ore_blk_ciphertext(ctxt1));
  ERR_CHECK(clear_ore_blk_ciphertext(ctxt2));

  return ret;
}

int main(int argc, char** argv) {
  srand((unsigned) time(NULL));

  printf("Testing ORE... ");
  fflush(stdout);

  int i;
  for (i = 0; i < N_TRIALS; i++) {
    if (check_ore_blk() != ERROR_NONE) {
      printf("FAIL\n");
      return -1;
    }
  }

  printf("PASS\n");
  return 0;
}
