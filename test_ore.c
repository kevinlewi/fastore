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

#include <stdint.h>
#include <stdio.h>

#define ERR_CHECK(x) if((err = x) != ERROR_NONE) { return err; }

/**
 * Generates two random 31-bit integers and encrypts them, checking to make sure
 * that the ciphertexts are compared correctly. The block length is
 * randomly chosen between 2 and 31.
 *
 * The encrypted integers are also chosen randomly.
 *
 * @return 0 on success, -1 on failure, and an error if it occurred during the
 * encryption or comparison phase
 */
static int check_ore() {
  int nbits = 31, out_blk_len = ((rand() % (nbits - 2)) + 2);

  uint64_t n1 = rand() % (1 << nbits);
  uint64_t n2 = rand() % (1 << nbits);

  int cmp = (n1 < n2) ? -1 : 1;
  if(n1 == n2) {
    cmp = 0;
  }

  int err;

  ore_params params;
  ERR_CHECK(init_ore_params(params, nbits, out_blk_len));

  ore_secret_key sk;
  ERR_CHECK(ore_setup(sk, params));

  ore_ciphertext ctxt1;
  ERR_CHECK(init_ore_ciphertext(ctxt1, params));

  ore_ciphertext ctxt2;
  ERR_CHECK(init_ore_ciphertext(ctxt2, params));

  ERR_CHECK(ore_encrypt_ui(ctxt1, sk, n1));
  ERR_CHECK(ore_encrypt_ui(ctxt2, sk, n2));

  int ret = 0;
  int res1, res2, res3, res4;
  ERR_CHECK(ore_compare(&res1, ctxt1, ctxt1));
  ERR_CHECK(ore_compare(&res2, ctxt1, ctxt2));
  ERR_CHECK(ore_compare(&res3, ctxt2, ctxt1));
  ERR_CHECK(ore_compare(&res4, ctxt2, ctxt2));

  if(res1 == 0 &&
      res2 == cmp &&
      res3 == (-1 * cmp) &&
      res4 == 0) {
    ret = 0; // success
  } else {
    ret = -1; // fail
  }

  ERR_CHECK(clear_ore_ciphertext(ctxt1));
  ERR_CHECK(clear_ore_ciphertext(ctxt2));
  ERR_CHECK(ore_cleanup(sk));

  return ret;
}

int main(int argc, char** argv) {
  srand((unsigned) time(NULL));

  printf("Testing ORE... ");
  fflush(stdout);

  int i;
  for(i = 0; i < 200; i++) {
    if(check_ore() != ERROR_NONE) {
      printf("FAIL\n");
      return -1;
    }
  }

  printf("PASS\n");
  return 0;
}
