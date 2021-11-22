#include <ghcjs/rts.h>

function h$sodium_init() {
  _sodium_init();
}
var emscriptenHeap = { u8: HEAPU8 };

function h$sodium_malloc(size) {
  RETURN_UBX_TUP2(emscriptenHeap, _sodium_malloc(size));
}
function h$sodium_free(ptr) {
  _sodium_free(ptr);
}
function maybeCopyToEmscripten(d, o, len) {
  if(d.u8 == HEAPU8) {
    return { o: o, copyBack: function() {}, scrub: function() {}, free: function() {} };
  }
  else {
    oEmscripten = _malloc(len);
    for(var n = 0; n < len; n++) {
      HEAPU8[oEmscripten + n] = d.u8[o + n];
    }
    return {
      o: oEmscripten,
      copyBack: function() {
        for(var n = 0; n < len; n++) {
          d.u8[o + n] = HEAPU8[oEmscripten + n];
        }
      },
      scrub: function() {
        for(var n = 0; n < len; n++) {
          HEAPU8[oEmscripten + n] = 0;
        }
      },
      free: function() {
        _free(oEmscripten);
      }
    };
  }
}
function h$crypto_hash_sha256(out_d, out_o, in_d, in_o, inlen) {
  var out_ = maybeCopyToEmscripten(out_d, out_o, _crypto_hash_sha256_bytes());
  var in_ = maybeCopyToEmscripten(in_d, in_o, inlen);
  _crypto_hash_sha256(out_.o, in_.o, inlen);
  out_.copyBack();
  out_.scrub();
  out_.free();
  in_.scrub();
  in_.free();
}
function h$crypto_generichash_blake2b(out_d, out_o, outlen,
                               in_d, in_o, inlen, key_d, key_o, keylen) {
  var out_ = maybeCopyToEmscripten(out_d, out_o, outlen);
  var in_ = maybeCopyToEmscripten(in_d, in_o, inlen);
  var key_ = maybeCopyToEmscripten(key_d, key_o, keylen);
  _crypto_hash_sha256(out_.o, outlen, in_.o, inlen, key_.o, keylen);
  out_.copyBack();
  out_.scrub();
  out_.free();
  in_.scrub();
  in_.free();
  key_.scrub();
  key_.free();
}
