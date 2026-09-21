// Nuvio provider: UASerialsPro (uaserials.com)
// Hand-ported from the CloudStream Kotlin provider UASerialsProProvider.kt
// (https://github.com/CakesTwix/cloudstream-extensions-uk).
//
// Unlike the sibling sites in this family (Uakino, UAFlix, KlonTV, KinoTron),
// this one hides its player URL behind real AES-256-CBC encryption
// (PBKDF2-HMAC-SHA512, 999 iterations, fixed passphrase, NoPadding), not just
// XOR obfuscation. Nuvio's plugin sandbox has no crypto library available, so
// this file bundles a minimal pure-JS SHA-512 / HMAC / PBKDF2 / AES-256
// implementation, written from the algorithm specs and cross-checked byte-for-
// byte against the site's own CryptoJS output on real captured ciphertext
// (SHA-512("abc") also matches the official test vector). The passphrase and
// KDF parameters are read directly from the Kotlin source, which was itself
// presumably reverse-engineered from this site's bundled crypto-js usage.
//
// Nuvio only gives us a TMDB id, not a title, so this provider resolves the
// TMDB id to a title via the TMDB API, then runs it through UASerialsPro's own
// site search and picks the best textual match - inherently best-effort for a
// non-English catalog.
//
// Written as plain Promise chains (no async/await) since the Hermes plugin
// runtime does not run async/await in dynamically loaded providers.

var TMDB_API_KEY = '439c478a771f35c05022f9feabcca01c'; // shared community demo key; swap for your own free key from themoviedb.org if you get rate-limited
var BASE = 'https://uaserials.com';
var UA = 'Mozilla/5.0 (X11; Linux x86_64; rv:144.0) Gecko/20100101 Firefox/144.0'; // matches the Kotlin provider's custom UA for this site
var AES_PASSPHRASE = '297796CCB81D255125';
var PLAYER_REFERER = 'https://tortuga.tw/';

function fetchHtml(url, opts) {
  opts = opts || {};
  var headers = { 'User-Agent': UA };
  for (var k in (opts.headers || {})) headers[k] = opts.headers[k];
  return fetch(url, { headers: headers }).then(function (r) { return r.text(); });
}

function normalize(s) {
  return (s || '')
    .toLowerCase()
    .replace(/['"«»():,.!?_-]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function tokenScore(a, b) {
  var ta = normalize(a).split(' ').filter(Boolean);
  var tb = normalize(b).split(' ').filter(Boolean);
  if (!ta.length || !tb.length) return 0;
  var setB = {};
  tb.forEach(function (t) { setB[t] = true; });
  var hits = 0;
  ta.forEach(function (t) { if (setB[t]) hits++; });
  return hits / Math.max(ta.length, tb.length);
}

function stripTags(s) {
  return (s || '').replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();
}

function guessQuality(url) {
  var m = /([0-9]{3,4})p/.exec(url || '');
  return m ? m[1] + 'p' : '1080p';
}

// =====================================================================
// Pure-JS crypto: SHA-512, HMAC-SHA512, PBKDF2, AES-256-CBC (NoPadding).
// SHA-512 is implemented with 32-bit hi/lo word pairs rather than BigInt:
// Hermes (the RN JS engine Nuvio runs on) has no JIT and its BigInt path is
// considerably slower than plain number ops, and PBKDF2 here runs ~2000
// SHA-512 compressions per key derivation - a BigInt version risked being
// slow enough to hit Nuvio's provider timeout on-device even though it ran
// fine in a desktop browser. Verified against CryptoJS output on real
// captured ciphertext and against the official SHA-512("abc") test vector.
//
// The 64-bit rotate/shift/add helpers write into shared scratch variables
// (_rh/_rl) instead of returning a new [hi, lo] array: a real device report
// put a single stream lookup at 3+ minutes, and the array-per-operation
// version allocates on the order of 10 million short-lived arrays for one
// PBKDF2 call (999 iterations x ~2000 SHA-512 compressions x ~80 rounds x
// several ops each). A JIT (V8, in a desktop browser) can often optimize
// that allocation away; Hermes has no JIT and pays for every one of them,
// which is the likely reason it was so much slower on-device than in
// testing here. This shaved the same real key derivation from ~300ms to
// ~160ms in this browser alone - the gap from eliminating GC pressure
// should be considerably larger on a non-JIT engine.
// =====================================================================

var SHA512_K_HI = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2, 0xca273ece, 0xd186b8c7, 0xeada7dd6, 0xf57d4f7f, 0x06f067aa, 0x0a637dc5, 0x113f9804, 0x1b710b35, 0x28db77f5, 0x32caab7b, 0x3c9ebe0a, 0x431d67c4, 0x4cc5d4be, 0x597f299c, 0x5fcb6fab, 0x6c44198c];
var SHA512_K_LO = [0xd728ae22, 0x23ef65cd, 0xec4d3b2f, 0x8189dbbc, 0xf348b538, 0xb605d019, 0xaf194f9b, 0xda6d8118, 0xa3030242, 0x45706fbe, 0x4ee4b28c, 0xd5ffb4e2, 0xf27b896f, 0x3b1696b1, 0x25c71235, 0xcf692694, 0x9ef14ad2, 0x384f25e3, 0x8b8cd5b5, 0x77ac9c65, 0x592b0275, 0x6ea6e483, 0xbd41fbd4, 0x831153b5, 0xee66dfab, 0x2db43210, 0x98fb213f, 0xbeef0ee4, 0x3da88fc2, 0x930aa725, 0xe003826f, 0x0a0e6e70, 0x46d22ffc, 0x5c26c926, 0x5ac42aed, 0x9d95b3df, 0x8baf63de, 0x3c77b2a8, 0x47edaee6, 0x1482353b, 0x4cf10364, 0xbc423001, 0xd0f89791, 0x0654be30, 0xd6ef5218, 0x5565a910, 0x5771202a, 0x32bbd1b8, 0xb8d2d0c8, 0x5141ab53, 0xdf8eeb99, 0xe19b48a8, 0xc5c95a63, 0xe3418acb, 0x7763e373, 0xd6b2b8a3, 0x5defb2fc, 0x43172f60, 0xa1f0ab72, 0x1a6439ec, 0x23631e28, 0xde82bde9, 0xb2c67915, 0xe372532b, 0xea26619c, 0x21c0c207, 0xcde0eb1e, 0xee6ed178, 0x72176fba, 0xa2c898a6, 0xbef90dae, 0x131c471b, 0x23047d84, 0x40c72493, 0x15c9bebc, 0x9c100d4c, 0xcb3e42b6, 0xfc657e2a, 0x3ad6faec, 0x4a475817];
var SHA512_H0_HI = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
var SHA512_H0_LO = [0xf3bcc908, 0x84caa73b, 0xfe94f82b, 0x5f1d36f1, 0xade682d1, 0x2b3e6c1f, 0xfb41bd6b, 0x137e2179];

// Scratch registers written by every 64-bit helper below instead of allocating a [hi, lo]
// result array. Safe because each call site reads _rh/_rl into local vars immediately, before
// any nested call can overwrite them.
var _rh = 0, _rl = 0;
function rotr_(hi, lo, n) {
  if (n === 0) { _rh = hi >>> 0; _rl = lo >>> 0; }
  else if (n < 32) { _rh = ((hi >>> n) | (lo << (32 - n))) >>> 0; _rl = ((lo >>> n) | (hi << (32 - n))) >>> 0; }
  else if (n === 32) { _rh = lo >>> 0; _rl = hi >>> 0; }
  else { var m = n - 32; _rh = ((lo >>> m) | (hi << (32 - m))) >>> 0; _rl = ((hi >>> m) | (lo << (32 - m))) >>> 0; }
}
function shr_(hi, lo, n) {
  if (n === 0) { _rh = hi >>> 0; _rl = lo >>> 0; }
  else if (n < 32) { _rh = (hi >>> n) >>> 0; _rl = ((lo >>> n) | (hi << (32 - n))) >>> 0; }
  else { _rh = 0; _rl = (hi >>> (n - 32)) >>> 0; }
}
function add_(ah, al, bh, bl) {
  var lo = (al >>> 0) + (bl >>> 0);
  var carry = lo > 0xffffffff ? 1 : 0;
  _rl = lo >>> 0;
  _rh = ((ah >>> 0) + (bh >>> 0) + carry) >>> 0;
}

function sha512(bytes) {
  var ml = bytes.length * 8;
  var msg = Array.from(bytes);
  msg.push(0x80);
  while (msg.length % 128 !== 112) msg.push(0);
  for (var i = 0; i < 12; i++) msg.push(0); // upper 96 bits of length: always 0 for our message sizes
  msg.push((ml >>> 24) & 0xff, (ml >>> 16) & 0xff, (ml >>> 8) & 0xff, ml & 0xff);

  var Hhi = SHA512_H0_HI.slice(), Hlo = SHA512_H0_LO.slice();
  var whi = new Array(80), wlo = new Array(80);

  for (var b = 0; b < msg.length / 128; b++) {
    for (var t = 0; t < 16; t++) {
      var off = b * 128 + t * 8;
      whi[t] = ((msg[off] << 24) | (msg[off + 1] << 16) | (msg[off + 2] << 8) | msg[off + 3]) >>> 0;
      wlo[t] = ((msg[off + 4] << 24) | (msg[off + 5] << 16) | (msg[off + 6] << 8) | msg[off + 7]) >>> 0;
    }
    for (var t2 = 16; t2 < 80; t2++) {
      rotr_(whi[t2 - 15], wlo[t2 - 15], 1); var a15h = _rh, a15l = _rl;
      rotr_(whi[t2 - 15], wlo[t2 - 15], 8); var xh = (a15h ^ _rh) >>> 0, xl = (a15l ^ _rl) >>> 0;
      shr_(whi[t2 - 15], wlo[t2 - 15], 7); var s0h = (xh ^ _rh) >>> 0, s0l = (xl ^ _rl) >>> 0;

      rotr_(whi[t2 - 2], wlo[t2 - 2], 19); var a2h = _rh, a2l = _rl;
      rotr_(whi[t2 - 2], wlo[t2 - 2], 61); var yh = (a2h ^ _rh) >>> 0, yl = (a2l ^ _rl) >>> 0;
      shr_(whi[t2 - 2], wlo[t2 - 2], 6); var s1h = (yh ^ _rh) >>> 0, s1l = (yl ^ _rl) >>> 0;

      add_(whi[t2 - 16], wlo[t2 - 16], s0h, s0l); var sumh = _rh, suml = _rl;
      add_(sumh, suml, whi[t2 - 7], wlo[t2 - 7]); sumh = _rh; suml = _rl;
      add_(sumh, suml, s1h, s1l); whi[t2] = _rh; wlo[t2] = _rl;
    }
    var ah = Hhi[0], al = Hlo[0], bh = Hhi[1], bl = Hlo[1], ch = Hhi[2], cl = Hlo[2], dh = Hhi[3], dl = Hlo[3];
    var eh = Hhi[4], el = Hlo[4], fh = Hhi[5], fl = Hlo[5], gh = Hhi[6], gl = Hlo[6], hh = Hhi[7], hl = Hlo[7];
    for (var t3 = 0; t3 < 80; t3++) {
      rotr_(eh, el, 14); var e14h = _rh, e14l = _rl;
      rotr_(eh, el, 18); var s1ah = (e14h ^ _rh) >>> 0, s1al = (e14l ^ _rl) >>> 0;
      rotr_(eh, el, 41); var S1h = (s1ah ^ _rh) >>> 0, S1l = (s1al ^ _rl) >>> 0;

      var Chh = ((eh & fh) ^ ((~eh) & gh)) >>> 0;
      var Chl = ((el & fl) ^ ((~el) & gl)) >>> 0;

      add_(hh, hl, S1h, S1l); var t1h = _rh, t1l = _rl;
      add_(t1h, t1l, Chh, Chl); t1h = _rh; t1l = _rl;
      add_(t1h, t1l, SHA512_K_HI[t3], SHA512_K_LO[t3]); t1h = _rh; t1l = _rl;
      add_(t1h, t1l, whi[t3], wlo[t3]); var temp1h = _rh, temp1l = _rl;

      rotr_(ah, al, 28); var a28h = _rh, a28l = _rl;
      rotr_(ah, al, 34); var s0ah = (a28h ^ _rh) >>> 0, s0al = (a28l ^ _rl) >>> 0;
      rotr_(ah, al, 39); var S0h = (s0ah ^ _rh) >>> 0, S0l = (s0al ^ _rl) >>> 0;

      var Majh = ((ah & bh) ^ (ah & ch) ^ (bh & ch)) >>> 0;
      var Majl = ((al & bl) ^ (al & cl) ^ (bl & cl)) >>> 0;

      add_(S0h, S0l, Majh, Majl); var temp2h = _rh, temp2l = _rl;

      hh = gh; hl = gl; gh = fh; gl = fl; fh = eh; fl = el;
      add_(dh, dl, temp1h, temp1l); eh = _rh; el = _rl;
      dh = ch; dl = cl; ch = bh; cl = bl; bh = ah; bl = al;
      add_(temp1h, temp1l, temp2h, temp2l); ah = _rh; al = _rl;
    }
    add_(Hhi[0], Hlo[0], ah, al); Hhi[0] = _rh; Hlo[0] = _rl;
    add_(Hhi[1], Hlo[1], bh, bl); Hhi[1] = _rh; Hlo[1] = _rl;
    add_(Hhi[2], Hlo[2], ch, cl); Hhi[2] = _rh; Hlo[2] = _rl;
    add_(Hhi[3], Hlo[3], dh, dl); Hhi[3] = _rh; Hlo[3] = _rl;
    add_(Hhi[4], Hlo[4], eh, el); Hhi[4] = _rh; Hlo[4] = _rl;
    add_(Hhi[5], Hlo[5], fh, fl); Hhi[5] = _rh; Hlo[5] = _rl;
    add_(Hhi[6], Hlo[6], gh, gl); Hhi[6] = _rh; Hlo[6] = _rl;
    add_(Hhi[7], Hlo[7], hh, hl); Hhi[7] = _rh; Hlo[7] = _rl;
  }
  var out = new Uint8Array(64);
  for (var i2 = 0; i2 < 8; i2++) {
    out[i2 * 8] = (Hhi[i2] >>> 24) & 0xff; out[i2 * 8 + 1] = (Hhi[i2] >>> 16) & 0xff;
    out[i2 * 8 + 2] = (Hhi[i2] >>> 8) & 0xff; out[i2 * 8 + 3] = Hhi[i2] & 0xff;
    out[i2 * 8 + 4] = (Hlo[i2] >>> 24) & 0xff; out[i2 * 8 + 5] = (Hlo[i2] >>> 16) & 0xff;
    out[i2 * 8 + 6] = (Hlo[i2] >>> 8) & 0xff; out[i2 * 8 + 7] = Hlo[i2] & 0xff;
  }
  return out;
}

function concatBytes() {
  var total = 0;
  for (var i = 0; i < arguments.length; i++) total += arguments[i].length;
  var out = new Uint8Array(total);
  var off = 0;
  for (var j = 0; j < arguments.length; j++) { out.set(arguments[j], off); off += arguments[j].length; }
  return out;
}

function hmacSha512(keyBytes, msgBytes) {
  var blockSize = 128;
  var key = keyBytes;
  if (key.length > blockSize) key = sha512(key);
  if (key.length < blockSize) { var k2 = new Uint8Array(blockSize); k2.set(key); key = k2; }
  var opad = new Uint8Array(blockSize), ipad = new Uint8Array(blockSize);
  for (var i = 0; i < blockSize; i++) { opad[i] = key[i] ^ 0x5c; ipad[i] = key[i] ^ 0x36; }
  var inner = sha512(concatBytes(ipad, msgBytes));
  return sha512(concatBytes(opad, inner));
}

function pbkdf2HmacSha512(passBytes, saltBytes, iterations, keyLenBytes) {
  var hLen = 64;
  var numBlocks = Math.ceil(keyLenBytes / hLen);
  var out = new Uint8Array(numBlocks * hLen);
  for (var blockIndex = 1; blockIndex <= numBlocks; blockIndex++) {
    var intBlock = new Uint8Array(4);
    intBlock[0] = (blockIndex >>> 24) & 0xff;
    intBlock[1] = (blockIndex >>> 16) & 0xff;
    intBlock[2] = (blockIndex >>> 8) & 0xff;
    intBlock[3] = blockIndex & 0xff;
    var u = hmacSha512(passBytes, concatBytes(saltBytes, intBlock));
    var t = u.slice();
    for (var iter = 1; iter < iterations; iter++) {
      u = hmacSha512(passBytes, u);
      for (var i = 0; i < t.length; i++) t[i] ^= u[i];
    }
    out.set(t, (blockIndex - 1) * hLen);
  }
  return out.slice(0, keyLenBytes);
}

var AES_SBOX = [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16];
var AES_INV_SBOX = new Array(256);
for (var _i = 0; _i < 256; _i++) AES_INV_SBOX[AES_SBOX[_i]] = _i;
var AES_RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d];

function gmul(a, b) {
  var p = 0;
  for (var i = 0; i < 8; i++) {
    if (b & 1) p ^= a;
    var hi = a & 0x80;
    a = (a << 1) & 0xff;
    if (hi) a ^= 0x1b;
    b >>= 1;
  }
  return p & 0xff;
}

function aesKeyExpansion256(key) {
  var Nk = 8, Nr = 14, Nb = 4;
  var w = new Array(Nb * (Nr + 1));
  for (var i = 0; i < Nk; i++) w[i] = [key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]];
  for (var i2 = Nk; i2 < Nb * (Nr + 1); i2++) {
    var temp = w[i2 - 1].slice();
    if (i2 % Nk === 0) {
      temp = [temp[1], temp[2], temp[3], temp[0]].map(function (b) { return AES_SBOX[b]; });
      temp[0] ^= AES_RCON[i2 / Nk - 1];
    } else if (Nk > 6 && i2 % Nk === 4) {
      temp = temp.map(function (b) { return AES_SBOX[b]; });
    }
    w[i2] = w[i2 - Nk].map(function (b, idx) { return b ^ temp[idx]; });
  }
  return w;
}

function aesAddRoundKey(state, w, round) {
  for (var c = 0; c < 4; c++) for (var r = 0; r < 4; r++) state[r][c] ^= w[round * 4 + c][r];
}
function aesInvSubBytes(state) { for (var r = 0; r < 4; r++) for (var c = 0; c < 4; c++) state[r][c] = AES_INV_SBOX[state[r][c]]; }
function aesInvShiftRows(state) {
  for (var r = 1; r < 4; r++) {
    var row = state[r].slice();
    for (var c = 0; c < 4; c++) state[r][c] = row[(c - r + 4) % 4];
  }
}
function aesInvMixColumns(state) {
  for (var c = 0; c < 4; c++) {
    var a0 = state[0][c], a1 = state[1][c], a2 = state[2][c], a3 = state[3][c];
    state[0][c] = gmul(a0, 14) ^ gmul(a1, 11) ^ gmul(a2, 13) ^ gmul(a3, 9);
    state[1][c] = gmul(a0, 9) ^ gmul(a1, 14) ^ gmul(a2, 11) ^ gmul(a3, 13);
    state[2][c] = gmul(a0, 13) ^ gmul(a1, 9) ^ gmul(a2, 14) ^ gmul(a3, 11);
    state[3][c] = gmul(a0, 11) ^ gmul(a1, 13) ^ gmul(a2, 9) ^ gmul(a3, 14);
  }
}

function aes256DecryptBlock(block16, w) {
  var Nr = 14;
  var state = [[0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0]];
  for (var i = 0; i < 16; i++) state[i % 4][Math.floor(i / 4)] = block16[i];
  aesAddRoundKey(state, w, Nr);
  for (var round = Nr - 1; round >= 1; round--) {
    aesInvShiftRows(state);
    aesInvSubBytes(state);
    aesAddRoundKey(state, w, round);
    aesInvMixColumns(state);
  }
  aesInvShiftRows(state);
  aesInvSubBytes(state);
  aesAddRoundKey(state, w, 0);
  var out = new Uint8Array(16);
  for (var i2 = 0; i2 < 16; i2++) out[i2] = state[i2 % 4][Math.floor(i2 / 4)];
  return out;
}

function aes256CbcDecryptNoPadding(cipherBytes, key32, iv16) {
  var w = aesKeyExpansion256(key32);
  var out = new Uint8Array(cipherBytes.length);
  var prev = iv16;
  for (var off = 0; off < cipherBytes.length; off += 16) {
    var block = cipherBytes.slice(off, off + 16);
    var decrypted = aes256DecryptBlock(block, w);
    for (var i = 0; i < 16; i++) out[off + i] = decrypted[i] ^ prev[i];
    prev = block;
  }
  return out;
}

function hexToBytes(hex) {
  var b = new Uint8Array(hex.length / 2);
  for (var i = 0; i < b.length; i++) b[i] = parseInt(hex.substr(i * 2, 2), 16);
  return b;
}
function b64ToBytes(b64) {
  var chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  var clean = (b64 || '').replace(/[^A-Za-z0-9+/]/g, '');
  var bytes = []; var buffer = 0, bits = 0;
  for (var i = 0; i < clean.length; i++) {
    var val = chars.indexOf(clean.charAt(i));
    if (val === -1) continue;
    buffer = (buffer << 6) | val; bits += 6;
    if (bits >= 8) { bits -= 8; bytes.push((buffer >> bits) & 0xFF); }
  }
  return new Uint8Array(bytes);
}

// Hand-rolled UTF-8 codec: TextEncoder/TextDecoder are Web APIs, not core JS - they are
// not guaranteed to exist in Hermes/React Native without an explicit polyfill. A missing
// TextEncoder would throw immediately on every call, which looks identical to a provider
// that silently returns nothing (both get swallowed by the outer catch in getStreams).
function utf8Encode(str) {
  var bytes = [];
  for (var i = 0; i < str.length; i++) {
    var code = str.charCodeAt(i);
    if (code < 0x80) {
      bytes.push(code);
    } else if (code < 0x800) {
      bytes.push(0xc0 | (code >> 6), 0x80 | (code & 0x3f));
    } else if (code >= 0xd800 && code <= 0xdbff && i + 1 < str.length) {
      var next = str.charCodeAt(i + 1);
      if (next >= 0xdc00 && next <= 0xdfff) {
        var cp = 0x10000 + ((code - 0xd800) << 10) + (next - 0xdc00);
        bytes.push(0xf0 | (cp >> 18), 0x80 | ((cp >> 12) & 0x3f), 0x80 | ((cp >> 6) & 0x3f), 0x80 | (cp & 0x3f));
        i++;
      } else {
        bytes.push(0xe0 | (code >> 12), 0x80 | ((code >> 6) & 0x3f), 0x80 | (code & 0x3f));
      }
    } else {
      bytes.push(0xe0 | (code >> 12), 0x80 | ((code >> 6) & 0x3f), 0x80 | (code & 0x3f));
    }
  }
  return new Uint8Array(bytes);
}
function utf8Decode(bytes) {
  var out = '';
  var i = 0;
  while (i < bytes.length) {
    var b0 = bytes[i];
    if (b0 < 0x80) { out += String.fromCharCode(b0); i++; }
    else if ((b0 & 0xe0) === 0xc0 && i + 1 < bytes.length) {
      out += String.fromCharCode(((b0 & 0x1f) << 6) | (bytes[i + 1] & 0x3f)); i += 2;
    } else if ((b0 & 0xf0) === 0xe0 && i + 2 < bytes.length) {
      out += String.fromCharCode(((b0 & 0x0f) << 12) | ((bytes[i + 1] & 0x3f) << 6) | (bytes[i + 2] & 0x3f)); i += 3;
    } else if ((b0 & 0xf8) === 0xf0 && i + 3 < bytes.length) {
      var cp = ((b0 & 0x07) << 18) | ((bytes[i + 1] & 0x3f) << 12) | ((bytes[i + 2] & 0x3f) << 6) | (bytes[i + 3] & 0x3f);
      cp -= 0x10000;
      out += String.fromCharCode(0xd800 + (cp >> 10), 0xdc00 + (cp & 0x3ff)); i += 4;
    } else { i++; } // invalid byte, skip (mirrors {fatal:false} lenient behavior)
  }
  return out;
}

// Site's own AES payload: {ciphertext (base64), iv (hex), salt (hex)} -> decrypted plaintext.
function decryptAesTag(aesData) {
  var key32 = pbkdf2HmacSha512(utf8Encode(AES_PASSPHRASE), hexToBytes(aesData.salt), 999, 32);
  var plainBytes = aes256CbcDecryptNoPadding(b64ToBytes(aesData.ciphertext), key32, hexToBytes(aesData.iv));
  var text = utf8Decode(plainBytes);
  // AES/CBC/NoPadding leaves trailing raw padding bytes after the real JSON; trim to the last ']'.
  var lastBracket = text.lastIndexOf(']');
  return lastBracket !== -1 ? text.slice(0, lastBracket + 1) : text;
}

// --- TMDB lookup -------------------------------------------------------

function getTmdbInfo(tmdbId, mediaType) {
  var kind = mediaType === 'tv' ? 'tv' : 'movie';
  var url = 'https://api.themoviedb.org/3/' + kind + '/' + tmdbId + '?api_key=' + TMDB_API_KEY + '&language=uk-UA';
  return fetch(url).then(function (r) { return r.json(); }).then(function (data) {
    var title = kind === 'tv' ? (data.name || data.original_name) : (data.title || data.original_title);
    var originalTitle = kind === 'tv' ? data.original_name : data.original_title;
    var dateStr = kind === 'tv' ? data.first_air_date : data.release_date;
    return {
      title: title,
      originalTitle: originalTitle,
      year: dateStr ? parseInt(dateStr.slice(0, 4), 10) : null
    };
  });
}

// --- Site search -------------------------------------------------------
// Confirmed live: <a class="uas-card" href="..."><span class="uas-card__poster">...
// <span class="uas-card__year">2024</span></span><span class="uas-card__body">
// <span class="uas-card__title">Title</span><span class="uas-card__orig"><mark>...</mark>Orig Title</span>...</a>

function parseSearchResults(html) {
  var results = [];
  var re = /<a([^>]*)>([\s\S]*?)<\/a>/g;
  var m;
  while ((m = re.exec(html))) {
    var attrs = m[1];
    if (!/class="[^"]*\buas-card\b[^"]*"/.test(attrs)) continue;
    var hrefMatch = /href="([^"]+)"/.exec(attrs);
    if (!hrefMatch) continue;
    var titleMatch = /class="uas-card__title"[^>]*>([\s\S]*?)<\/span>/.exec(m[2]);
    var origMatch = /class="uas-card__orig"[^>]*>([\s\S]*?)<\/span>/.exec(m[2]);
    var yearMatch = /class="uas-card__year"[^>]*>([\s\S]*?)<\/span>/.exec(m[2]);
    var title = stripTags(titleMatch ? titleMatch[1] : '');
    var origTitle = stripTags(origMatch ? origMatch[1] : '');
    var year = yearMatch ? parseInt(stripTags(yearMatch[1]), 10) : null;
    if (title) results.push({ href: hrefMatch[1], title: title, origTitle: origTitle, year: year || null });
  }
  return results;
}

function searchUASerials(query) {
  var url = BASE + '/search/' + encodeURIComponent(query) + '/';
  return fetchHtml(url).then(parseSearchResults);
}

// Two failure modes this guards against, both confirmed against real search results:
// 1. A title with no Ukrainian TMDB translation (title===originalTitle, e.g. "War") searches in
//    English against a Ukrainian-titled catalog, so token overlap is ~0 for the correct result
//    too - an exact year match is accepted as a substitute signal.
// 2. A short/generic title (e.g. "Senna") can match a completely different production that
//    happens to share the exact title - a confirmed year *mismatch* hard-rejects the candidate
//    even when the title itself scores perfectly.
function pickBestMatch(results, tmdbInfo) {
  var candidates = results.filter(function (r) {
    return !(tmdbInfo.year && r.year && r.year !== tmdbInfo.year);
  });
  var best = null;
  var bestScore = -1;
  candidates.forEach(function (r) {
    var score = Math.max(
      tokenScore(r.title, tmdbInfo.title), tokenScore(r.title, tmdbInfo.originalTitle),
      tokenScore(r.origTitle, tmdbInfo.title), tokenScore(r.origTitle, tmdbInfo.originalTitle)
    );
    var yearBonus = (tmdbInfo.year && r.year && r.year === tmdbInfo.year) ? 0.3 : 0;
    var combined = score + yearBonus;
    if (combined > bestScore) {
      bestScore = combined;
      best = r;
    }
  });
  if (!best) return null;
  var titleScore = Math.max(
    tokenScore(best.title, tmdbInfo.title), tokenScore(best.title, tmdbInfo.originalTitle),
    tokenScore(best.origTitle, tmdbInfo.title), tokenScore(best.origTitle, tmdbInfo.originalTitle)
  );
  var yearMatch = tmdbInfo.year && best.year && best.year === tmdbInfo.year;
  return (titleScore >= 0.4 || yearMatch) ? best : null;
}

// --- Player resolution -------------------------------------------------
// <player-control data-tag1='{"ciphertext":"...","iv":"...","salt":"..."}'> decrypts to
// [{"tabName":"Плеєр","url":"https://tortuga.tw/vod/<id>"}, {"tabName":"Трейлер","url":"..."}]
// (confirmed live). The player page then has file:"..." - either a direct m3u8 (movie) or a
// Tortuga-XOR-encoded blob that itself decodes to either an m3u8 (movie) or a JSON array of
// seasons -> episodes (TV), where each episode.file is "{Name}url(subtitle:...);{Name2}url2(...)".

function extractPlayerTabs(html) {
  var m = /data-tag1='([^']*)'/.exec(html);
  if (!m) return null;
  var aesData;
  try { aesData = JSON.parse(m[1]); } catch (e) { return null; }
  var decrypted = decryptAesTag(aesData);
  try { return JSON.parse(decrypted); } catch (e) { return null; }
}

function pickPlayerUrl(tabs) {
  if (!tabs || !tabs.length) return null;
  var preferred = tabs.filter(function (t) { return (t.tabName || '').indexOf('Плеєр') !== -1; })[0];
  return (preferred || tabs[0]).url || null;
}

function base64ToBytesXor(b64) {
  var chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  var clean = (b64 || '').replace(/[^A-Za-z0-9+/]/g, '');
  var bytes = []; var buffer = 0, bits = 0;
  for (var i = 0; i < clean.length; i++) {
    var val = chars.indexOf(clean.charAt(i));
    if (val === -1) continue;
    buffer = (buffer << 6) | val; bits += 6;
    if (bits >= 8) { bits -= 8; bytes.push((buffer >> bits) & 0xFF); }
  }
  return bytes;
}

// Tortuga XOR obfuscation: first byte is a salt, remaining bytes XOR-ed with (salt + 7*i + 13) % 256.
// The recovered bytes are UTF-8 text (dub names embedded in TV episode data can be Cyrillic), so
// they must go through utf8Decode - String.fromCharCode(byte) per raw byte produces a "binary"
// string where multi-byte UTF-8 sequences never get recombined, which JSON.parse still accepts
// (structurally valid JSON) but leaves non-ASCII string *values* mangled. Confirmed against a
// real captured dub name ("ТакТребаПродакшн"): the old per-byte version reproduced the exact
// mojibake seen in the app; decoding through utf8Decode fixes it.
function tortugaDecode(encoded) {
  var clean = (encoded || '').trim().replace(/=+$/, '');
  if (!clean) return null;
  var bytes = base64ToBytesXor(clean);
  if (bytes.length < 2) return null;
  var salt = bytes[0];
  var out = new Uint8Array(bytes.length - 1);
  for (var i = 1; i < bytes.length; i++) {
    var key = (salt + 7 * (i - 1) + 13) % 256;
    out[i - 1] = bytes[i] ^ key;
  }
  return utf8Decode(out);
}

function extractFileField(html) {
  var m = /file\s*:\s*['"]([^'",]+?)['"]/.exec(html);
  return m ? m[1] : null;
}

function parseTrackString(fileStr, dubName) {
  var streams = [];
  fileStr.split(';').forEach(function (track) {
    if (!track) return;
    var subMatch = /\(subtitle:(.*)\)$/.exec(track);
    var clean = subMatch ? track.slice(0, subMatch.index) : track;
    var braceEnd = clean.indexOf('}');
    var name = clean.charAt(0) === '{' && braceEnd !== -1 ? clean.slice(1, braceEnd) : (dubName || 'Плеєр');
    var url = braceEnd !== -1 ? clean.slice(braceEnd + 1) : clean;
    if (url) {
      streams.push({
        name: name,
        title: 'UASerialsPro ' + name + ' ' + guessQuality(url),
        url: url,
        quality: guessQuality(url),
        headers: { Referer: PLAYER_REFERER }
      });
    }
  });
  return streams;
}

function resolveFromPlayerUrl(playerUrl, season, episode) {
  return fetchHtml(playerUrl, { headers: { Referer: BASE } }).then(function (html) {
    var raw = extractFileField(html);
    if (!raw) return [];
    var decoded = raw.indexOf('http') === 0 ? raw : tortugaDecode(raw);
    if (!decoded) return [];
    if (decoded.charAt(0) !== '[') {
      // Movie: a single direct stream.
      return [{
        name: 'UASerialsPro',
        title: 'UASerialsPro ' + guessQuality(decoded),
        url: decoded,
        quality: guessQuality(decoded),
        headers: { Referer: PLAYER_REFERER }
      }];
    }
    var seasons;
    try { seasons = JSON.parse(decoded); } catch (e) { return []; }
    if (!Array.isArray(seasons)) return [];
    var streams = [];
    seasons.forEach(function (s) {
      var sNum = parseInt(s.number || s.season, 10);
      if (season != null && sNum !== season) return;
      (s.folder || []).forEach(function (ep) {
        var eNum = parseInt(ep.number, 10);
        if (episode != null && eNum !== episode) return;
        streams.push.apply(streams, parseTrackString(ep.file || '', ep.title));
      });
    });
    return streams;
  });
}

// --- Entry point -----------------------------------------------------------

function getStreams(tmdbId, mediaType, season, episode) {
  return getTmdbInfo(tmdbId, mediaType).then(function (info) {
    if (!info.title) return [];
    return searchUASerials(info.title).then(function (results) {
      if (results.length || !info.originalTitle || info.originalTitle === info.title) return results;
      return searchUASerials(info.originalTitle);
    }).then(function (results) {
      var match = pickBestMatch(results, info);
      if (!match) return [];
      return fetchHtml(match.href).then(function (html) {
        var tabs = extractPlayerTabs(html);
        var playerUrl = pickPlayerUrl(tabs);
        if (!playerUrl) return [];
        var targetSeason = mediaType === 'tv' && season ? season : null;
        var targetEpisode = mediaType === 'tv' && episode ? episode : null;
        return resolveFromPlayerUrl(playerUrl, targetSeason, targetEpisode);
      });
    });
  }).catch(function () {
    return [];
  });
}

module.exports = { getStreams: getStreams };
