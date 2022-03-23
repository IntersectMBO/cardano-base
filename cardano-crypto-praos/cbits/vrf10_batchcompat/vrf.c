/*
Slight modification of document ./../ietfdraft03/convert.c to follow the
latest version of the standard, using the updated "Elligator2" hash_to_curve
function. We reproduce the copyright notice.
Copyright (c) 2018 Algorand LLC
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#include "crypto_vrf_ietfdraft10.h"

size_t
crypto_vrf_ietfdraft10_publickeybytes(void)
{
    return crypto_vrf_ietfdraft10_PUBLICKEYBYTES;
}

size_t
crypto_vrf_ietfdraft10_secretkeybytes(void)
{
    return crypto_vrf_ietfdraft10_SECRETKEYBYTES;
}

size_t
crypto_vrf_ietfdraft10_seedbytes(void)
{
    return crypto_vrf_ietfdraft10_SEEDBYTES;
}

size_t
crypto_vrf_ietfdraft10_proofbytes_batchcompat(void)
{
    return crypto_vrf_ietfdraft10_PROOFBYTES_BATCHCOMPAT;
}

size_t
crypto_vrf_ietfdraft10_outputbytes(void)
{
    return crypto_vrf_ietfdraft10_OUTPUTBYTES;
}
