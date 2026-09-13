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
// Verified against CryptoJS output on real captured ciphertext and against
// the official SHA-512("abc") test vector before shipping.
// =====================================================================

var MASK64 = (1n << 64n) - 1n;
function rotr64(x, n) { return ((x >> n) | (x << (64n - n))) & MASK64; }
function shr64(x, n) { return x >> n; }

var SHA512_K = ['428a2f98d728ae22', '7137449123ef65cd', 'b5c0fbcfec4d3b2f', 'e9b5dba58189dbbc', '3956c25bf348b538', '59f111f1b605d019', '923f82a4af194f9b', 'ab1c5ed5da6d8118', 'd807aa98a3030242', '12835b0145706fbe', '243185be4ee4b28c', '550c7dc3d5ffb4e2', '72be5d74f27b896f', '80deb1fe3b1696b1', '9bdc06a725c71235', 'c19bf174cf692694', 'e49b69c19ef14ad2', 'efbe4786384f25e3', '0fc19dc68b8cd5b5', '240ca1cc77ac9c65', '2de92c6f592b0275', '4a7484aa6ea6e483', '5cb0a9dcbd41fbd4', '76f988da831153b5', '983e5152ee66dfab', 'a831c66d2db43210', 'b00327c898fb213f', 'bf597fc7beef0ee4', 'c6e00bf33da88fc2', 'd5a79147930aa725', '06ca6351e003826f', '142929670a0e6e70', '27b70a8546d22ffc', '2e1b21385c26c926', '4d2c6dfc5ac42aed', '53380d139d95b3df', '650a73548baf63de', '766a0abb3c77b2a8', '81c2c92e47edaee6', '92722c851482353b', 'a2bfe8a14cf10364', 'a81a664bbc423001', 'c24b8b70d0f89791', 'c76c51a30654be30', 'd192e819d6ef5218', 'd69906245565a910', 'f40e35855771202a', '106aa07032bbd1b8', '19a4c116b8d2d0c8', '1e376c085141ab53', '2748774cdf8eeb99', '34b0bcb5e19b48a8', '391c0cb3c5c95a63', '4ed8aa4ae3418acb', '5b9cca4f7763e373', '682e6ff3d6b2b8a3', '748f82ee5defb2fc', '78a5636f43172f60', '84c87814a1f0ab72', '8cc702081a6439ec', '90befffa23631e28', 'a4506cebde82bde9', 'bef9a3f7b2c67915', 'c67178f2e372532b', 'ca273eceea26619c', 'd186b8c721c0c207', 'eada7dd6cde0eb1e', 'f57d4f7fee6ed178', '06f067aa72176fba', '0a637dc5a2c898a6', '113f9804bef90dae', '1b710b35131c471b', '28db77f523047d84', '32caab7b40c72493', '3c9ebe0a15c9bebc', '431d67c49c100d4c', '4cc5d4becb3e42b6', '597f299cfc657e2a', '5fcb6fab3ad6faec', '6c44198c4a475817'].map(function (h) { return BigInt('0x' + h); });
var SHA512_H0 = ['6a09e667f3bcc908', 'bb67ae8584caa73b', '3c6ef372fe94f82b', 'a54ff53a5f1d36f1', '510e527fade682d1', '9b05688c2b3e6c1f', '1f83d9abfb41bd6b', '5be0cd19137e2179'].map(function (h) { return BigInt('0x' + h); });

function sha512(bytes) {
  var ml = BigInt(bytes.length) * 8n;
  var msg = Array.from(bytes);
  msg.push(0x80);
  while (msg.length % 128 !== 112) msg.push(0);
  for (var i = 0; i < 8; i++) msg.push(0); // upper 64 bits of length: always 0 for our message sizes
  for (var i = 7; i >= 0; i--) msg.push(Number((ml >> BigInt(i * 8)) & 0xffn));

  var H = SHA512_H0.slice();
  for (var b = 0; b < msg.length / 128; b++) {
    var w = new Array(80);
    for (var t = 0; t < 16; t++) {
      var word = 0n;
      for (var i2 = 0; i2 < 8; i2++) word = (word << 8n) | BigInt(msg[b * 128 + t * 8 + i2]);
      w[t] = word;
    }
    for (var t2 = 16; t2 < 80; t2++) {
      var s0 = rotr64(w[t2 - 15], 1n) ^ rotr64(w[t2 - 15], 8n) ^ shr64(w[t2 - 15], 7n);
      var s1 = rotr64(w[t2 - 2], 19n) ^ rotr64(w[t2 - 2], 61n) ^ shr64(w[t2 - 2], 6n);
      w[t2] = (w[t2 - 16] + s0 + w[t2 - 7] + s1) & MASK64;
    }
    var a = H[0], bb = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], h = H[7];
    for (var t3 = 0; t3 < 80; t3++) {
      var S1 = rotr64(e, 14n) ^ rotr64(e, 18n) ^ rotr64(e, 41n);
      var ch = (e & f) ^ ((~e) & g);
      var temp1 = (h + S1 + (ch & MASK64) + SHA512_K[t3] + w[t3]) & MASK64;
      var S0 = rotr64(a, 28n) ^ rotr64(a, 34n) ^ rotr64(a, 39n);
      var maj = (a & bb) ^ (a & c) ^ (bb & c);
      var temp2 = (S0 + (maj & MASK64)) & MASK64;
      h = g; g = f; f = e; e = (d + temp1) & MASK64; d = c; c = bb; bb = a; a = (temp1 + temp2) & MASK64;
    }
    H[0] = (H[0] + a) & MASK64; H[1] = (H[1] + bb) & MASK64; H[2] = (H[2] + c) & MASK64; H[3] = (H[3] + d) & MASK64;
    H[4] = (H[4] + e) & MASK64; H[5] = (H[5] + f) & MASK64; H[6] = (H[6] + g) & MASK64; H[7] = (H[7] + h) & MASK64;
  }
  var out = new Uint8Array(64);
  for (var i3 = 0; i3 < 8; i3++) {
    var v = H[i3];
    for (var j = 7; j >= 0; j--) { out[i3 * 8 + j] = Number(v & 0xffn); v >>= 8n; }
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

// Site's own AES payload: {ciphertext (base64), iv (hex), salt (hex)} -> decrypted plaintext.
function decryptAesTag(aesData) {
  var key32 = pbkdf2HmacSha512(new TextEncoder().encode(AES_PASSPHRASE), hexToBytes(aesData.salt), 999, 32);
  var plainBytes = aes256CbcDecryptNoPadding(b64ToBytes(aesData.ciphertext), key32, hexToBytes(aesData.iv));
  var text = new TextDecoder('utf-8', { fatal: false }).decode(plainBytes);
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
// Confirmed live: <a class="uas-card" href="..."><span class="uas-card__title">Title</span>
// <span class="uas-card__orig"><mark>...</mark>Orig Title</span>...</a>

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
    var title = stripTags(titleMatch ? titleMatch[1] : '');
    var origTitle = stripTags(origMatch ? origMatch[1] : '');
    if (title) results.push({ href: hrefMatch[1], title: title, origTitle: origTitle });
  }
  return results;
}

function searchUASerials(query) {
  var url = BASE + '/search/' + encodeURIComponent(query) + '/';
  return fetchHtml(url).then(parseSearchResults);
}

function pickBestMatch(results, tmdbInfo) {
  var best = null;
  var bestScore = 0;
  results.forEach(function (r) {
    var score = Math.max(
      tokenScore(r.title, tmdbInfo.title), tokenScore(r.title, tmdbInfo.originalTitle),
      tokenScore(r.origTitle, tmdbInfo.title), tokenScore(r.origTitle, tmdbInfo.originalTitle)
    );
    if (score > bestScore) {
      bestScore = score;
      best = r;
    }
  });
  return bestScore >= 0.4 ? best : null;
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
function tortugaDecode(encoded) {
  var clean = (encoded || '').trim().replace(/=+$/, '');
  if (!clean) return null;
  var bytes = base64ToBytesXor(clean);
  if (bytes.length < 2) return null;
  var salt = bytes[0];
  var chars = [];
  for (var i = 1; i < bytes.length; i++) {
    var key = (salt + 7 * (i - 1) + 13) % 256;
    chars.push(String.fromCharCode(bytes[i] ^ key));
  }
  return chars.join('');
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
