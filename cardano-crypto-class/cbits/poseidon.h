/*
* Vendored from ocaml-bls12-381-hash (src/poseidon/poseidon.h)
* https://gitlab.com/nomadic-labs/cryptography/ocaml-bls12-381-hash
* at commit 495fc41d3ade773725cf82d6f17eb3c81aabeddb,
* unmodified apart from this added license header.
*
* MIT License
*
* Copyright (c) 2022 Nomadic Labs / cryptography
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in all
* copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE.
*
*/

#ifndef POSEIDON_H
#define POSEIDON_H

#include "blst.h"
#include <stdlib.h>
#include <string.h>

typedef struct poseidon_ctxt_s {
  // Containts the state, the MDS and the constants
  blst_fr *state;
  int nb_full_rounds;
  int nb_partial_rounds;
  int batch_size;
  int state_size;
} poseidon_ctxt_t;

int poseidon_compute_number_of_constants(int batch_size, int nb_partial_rounds,
                                         int nb_full_rounds, int width);

void poseidon_apply_permutation(poseidon_ctxt_t *ctxt);

blst_fr *poseidon_get_state_from_context(poseidon_ctxt_t *ctxt);

int poseidon_get_state_size_from_context(poseidon_ctxt_t *ctxt);

blst_fr *poseidon_get_mds_from_context(poseidon_ctxt_t *ctxt);

blst_fr *poseidon_get_round_constants_from_context(poseidon_ctxt_t *ctxt);

#endif
