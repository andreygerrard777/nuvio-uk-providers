// Nuvio provider: HDRezka (rezka.ag and other mirrors sharing the same backend)
//
// Built from scratch against real captured traffic (HAR), not ported from a CloudStream
// Kotlin source - CakesTwix's repo has no Rezka provider. Confirmed live on rezka.ag:
//  - Every domain sits behind Anubis (a proof-of-work gate, not a CAPTCHA): a client without
//    the techaro.lol-anubis-auth cookie gets a "Проверяем, что вы не бот!" page instead of
//    content. Earlier HARs looked clean only because the browser already held that cookie.
//    The challenge is sha256(randomData + nonce) starting with `difficulty` hex zeros
//    (difficulty 2 seen live = ~256 hashes), solved below in pure JS since Hermes has no
//    WebCrypto, then submitted to pass-challenge exactly as Anubis's own main.mjs does.
//  - Stream URLs come back as plain, unobfuscated "[quality]url or url2 or url3,[quality]..."
//    text - no base64/XOR/AES step needed on this domain (unlike some older Rezka forks).
//  - "premium" qualities (1080p Ultra, 4K) and even translators the site itself flags
//    premium_content:1 still come back with fully working URLs in the same unauthenticated
//    response - the premium lock on rezka.ag is UI-only, not enforced server-side.
//  - Per-translator season availability (e.g. an unofficial dub only covering season 2) is
//    reported by the server itself via action=get_episodes's "seasons" field - not guessed.
//
// Multiple domains, one file: DOMAINS below is tried in order, and whichever one answers the
// search call (Anubis solved if needed) is reused for the rest of that lookup. Both entries were
// verified end-to-end by running this exact file against the live sites (movie + series, with
// and without a native cookie jar). Add further mirrors only after the same kind of check, since
// a differently-built mirror could answer the search yet fail every later step.
//
// Written as plain Promise chains (no async/await) since the Hermes plugin runtime does not
// run async/await in dynamically loaded providers.

var TMDB_API_KEY = '439c478a771f35c05022f9feabcca01c'; // shared community demo key; swap for your own free key from themoviedb.org if you get rate-limited
var DOMAINS = ['rezka.ag', 'rezka-tv.org'];
var UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36';

function baseHeaders(domain) {
  return {
    'User-Agent': UA,
    'Accept-Language': 'ru-RU,ru;q=0.9,uk;q=0.8,en;q=0.7',
    'Referer': 'https://' + domain + '/',
    'Origin': 'https://' + domain
  };
}

function ajaxHeaders(domain) {
  return Object.assign(
    { 'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8', 'X-Requested-With': 'XMLHttpRequest' },
    baseHeaders(domain)
  );
}

function fetchWithTimeout(url, opts, ms) {
  return Promise.race([
    fetch(url, opts),
    new Promise(function (_, reject) { setTimeout(function () { reject(new Error('timeout')); }, ms || 8000); })
  ]);
}

// --- Cookies -----------------------------------------------------------------
// Anubis needs its cookie-verification cookie echoed back on pass-challenge, and the resulting
// auth cookie on every request after. Runtimes differ in a way that matters here: React Native
// on Android keeps cookies in a native jar that overrides any hand-set Cookie header, while
// other fetch implementations have no jar but let the hand-set header through - and in some,
// a hand-set header *suppresses* the jar, which would drop the auth cookie the jar just got.
// So cookies are always recorded here, but only sent by hand once the native jar has been shown
// not to work for this domain (_cookieMode 'manual'); see throughAnubis(). Module-level, so a
// solved challenge is reused across lookups for as long as Nuvio keeps this provider loaded.

var _jar = {};
var _cookieMode = {};

function storeCookies(domain, res) {
  var raw = res && res.headers && res.headers.get ? res.headers.get('set-cookie') : null;
  if (!raw) return;
  var jar = _jar[domain] || (_jar[domain] = {});
  // Multiple Set-Cookie headers arrive comma-joined; "Expires=Tue, 22 Sep ..." also has a comma,
  // so only split where the next token looks like the start of a new "name=" pair.
  raw.split(/,\s*(?=[^;,=\s]+=)/).forEach(function (part) {
    var kv = part.split(';')[0];
    var eq = kv.indexOf('=');
    if (eq <= 0) return;
    var name = kv.slice(0, eq).trim();
    var value = kv.slice(eq + 1).trim();
    if (value) jar[name] = value; else delete jar[name];
  });
}

function cookieHeader(domain) {
  var jar = _jar[domain] || {};
  return Object.keys(jar).map(function (k) { return k + '=' + jar[k]; }).join('; ');
}

function request(domain, url, opts, ms) {
  opts = opts || {};
  var headers = Object.assign({}, opts.headers);
  var ck = _cookieMode[domain] === 'manual' ? cookieHeader(domain) : '';
  if (ck) headers.Cookie = ck;
  return fetchWithTimeout(url, Object.assign({}, opts, { headers: headers }), ms).then(function (res) {
    storeCookies(domain, res);
    return res.text().then(function (text) { return { status: res.status, text: text }; });
  });
}

// --- SHA-256 (ASCII input only - Anubis hashes a hex string plus a decimal nonce) ----------
// Verified against the FIPS "abc" / empty / 56-byte vectors and against a real captured
// challenge (randomData from the HAR + nonce 105 -> the exact response hash the browser sent).

var K256 = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
];
var W256 = new Array(64);

function sha256Ascii(str) {
  var len = str.length;
  var nWords = (((len + 8) >> 6) + 1) * 16;
  var m = new Array(nWords);
  var i;
  for (i = 0; i < nWords; i++) m[i] = 0;
  for (i = 0; i < len; i++) m[i >> 2] |= (str.charCodeAt(i) & 0xff) << (24 - (i & 3) * 8);
  m[len >> 2] |= 0x80 << (24 - (len & 3) * 8);
  m[nWords - 1] = len * 8;
  var h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a;
  var h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;
  for (var off = 0; off < nWords; off += 16) {
    var t;
    for (t = 0; t < 16; t++) W256[t] = m[off + t] | 0;
    for (t = 16; t < 64; t++) {
      var x = W256[t - 15], y = W256[t - 2];
      var s0 = ((x >>> 7) | (x << 25)) ^ ((x >>> 18) | (x << 14)) ^ (x >>> 3);
      var s1 = ((y >>> 17) | (y << 15)) ^ ((y >>> 19) | (y << 13)) ^ (y >>> 10);
      W256[t] = (W256[t - 16] + s0 + W256[t - 7] + s1) | 0;
    }
    var a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;
    for (t = 0; t < 64; t++) {
      var S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
      var ch = (e & f) ^ (~e & g);
      var T1 = (h + S1 + ch + K256[t] + W256[t]) | 0;
      var S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
      var maj = (a & b) ^ (a & c) ^ (b & c);
      var T2 = (S0 + maj) | 0;
      h = g; g = f; f = e; e = (d + T1) | 0; d = c; c = b; b = a; a = (T1 + T2) | 0;
    }
    h0 = (h0 + a) | 0; h1 = (h1 + b) | 0; h2 = (h2 + c) | 0; h3 = (h3 + d) | 0;
    h4 = (h4 + e) | 0; h5 = (h5 + f) | 0; h6 = (h6 + g) | 0; h7 = (h7 + h) | 0;
  }
  return [h0, h1, h2, h3, h4, h5, h6, h7];
}

function wordsToHex(w) {
  var s = '';
  for (var i = 0; i < w.length; i++) s += ('00000000' + (w[i] >>> 0).toString(16)).slice(-8);
  return s;
}

function hasLeadingZeroNibbles(w, n) {
  for (var i = 0; i < n; i++) {
    if (((w[i >> 3] >>> (28 - (i & 7) * 4)) & 0xf) !== 0) return false;
  }
  return true;
}

// --- Anubis --------------------------------------------------------------------

function parseAnubisChallenge(html) {
  var m = /<script id="anubis_challenge" type="application\/json">([\s\S]*?)<\/script>/.exec(html || '');
  if (!m) return null;
  try { return JSON.parse(m[1]); } catch (e) { return null; }
}

// "fast" and "slow" are the same algorithm in Anubis's own client (main.mjs maps both to one
// function). Difficulty is capped so a site cranking it up can't pin the device for minutes.
function solveAnubis(ch) {
  var rules = ch.rules || {};
  var c = ch.challenge || {};
  var d = rules.difficulty;
  if ((rules.algorithm !== 'fast' && rules.algorithm !== 'slow') || !c.randomData || !c.id || !(d >= 0 && d <= 5)) return null;
  var started = Date.now();
  var max = Math.pow(16, d) * 32;
  for (var nonce = 0; nonce < max; nonce++) {
    var w = sha256Ascii(c.randomData + nonce);
    if (hasLeadingZeroNibbles(w, d)) {
      return { id: c.id, response: wordsToHex(w), nonce: nonce, elapsed: Date.now() - started };
    }
  }
  return null;
}

function passAnubis(domain, html) {
  var ch = parseAnubisChallenge(html);
  var sol = ch && solveAnubis(ch);
  if (!sol) return Promise.reject(new Error('anubis: unsolvable challenge'));
  var url = 'https://' + domain + '/.within.website/x/cmd/anubis/api/pass-challenge' +
    '?id=' + encodeURIComponent(sol.id) +
    '&response=' + sol.response +
    '&nonce=' + sol.nonce +
    '&redir=' + encodeURIComponent('https://' + domain + '/') +
    '&elapsedTime=' + sol.elapsed;
  // redirect:'manual' so the 302 carrying the auth Set-Cookie reaches storeCookies(); runtimes
  // that ignore it just follow to the homepage, where a native cookie jar (if any) has it.
  var opts = { headers: baseHeaders(domain), redirect: 'manual' };
  return request(domain, url, opts, 10000).then(function (r) {
    // A real browser session in the HAR got one transient 503 here before the 302 - retry once.
    return r.status >= 500 ? request(domain, url, opts, 10000) : r;
  });
}

// Runs a request; if Anubis answers instead of the site, solves the challenge and retries.
// First attempt trusts the runtime's native cookie jar (no hand-set Cookie header at all). If
// the retry is still challenged, the jar evidently didn't carry the auth cookie, so the domain
// switches to manual cookies and a fresh challenge (each one is single-use) is solved again.
function throughAnubis(domain, doRequest) {
  function stillChallenged(r) { return !!parseAnubisChallenge(r.text); }
  return doRequest().then(function (r) {
    if (!stillChallenged(r)) return r;
    if (_cookieMode[domain] === 'manual') {
      return passAnubis(domain, r.text).then(doRequest).then(function (r2) {
        if (stillChallenged(r2)) throw new Error('anubis: still challenged after pass');
        return r2;
      });
    }
    return passAnubis(domain, r.text).then(doRequest).then(function (r2) {
      if (!stillChallenged(r2)) { _cookieMode[domain] = 'native'; return r2; }
      _cookieMode[domain] = 'manual';
      return passAnubis(domain, r2.text).then(doRequest).then(function (r3) {
        if (stillChallenged(r3)) throw new Error('anubis: still challenged after pass');
        return r3;
      });
    });
  });
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

// --- TMDB lookup -----------------------------------------------------------
// ru-RU rather than uk-UA: Rezka's catalog is Russian-language, so matching against the
// Russian TMDB title gives far better token overlap than the Ukrainian one would here.

function getTmdbInfo(tmdbId, mediaType) {
  var kind = mediaType === 'tv' ? 'tv' : 'movie';
  var url = 'https://api.themoviedb.org/3/' + kind + '/' + tmdbId + '?api_key=' + TMDB_API_KEY + '&language=ru-RU';
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

// --- Search ------------------------------------------------------------
// Confirmed markup: <li><a href="URL"><span class="enty">Title</span> (Paren)<span class=
// "rating">...</span></a></li>, where Paren is e.g. "The Matrix, 1999", "Your Friends and
// Neighbors, сериал, 2025 - ...", or just "1999" for a Russian-original title. The year is the
// first comma-led 4-digit group (so "Blade Runner 2049, 2017" keeps 2049 in the title), and
// trailing all-Cyrillic segments like ", сериал" are content-type tags, not part of the title.

function parseSearchResults(html) {
  var out = [];
  var re = /<li><a href="([^"]+)"><span class="enty">([^<]*)<\/span>\s*\(([^)]*)\)/g;
  var m;
  while ((m = re.exec(html))) {
    var paren = m[3];
    var yearMatch = /(?:^|,\s*)((?:19|20)\d{2})\b/.exec(paren);
    var year = yearMatch ? parseInt(yearMatch[1], 10) : null;
    var head = yearMatch ? paren.slice(0, yearMatch.index) : paren;
    var origTitle = head.replace(/(,\s*[а-яёіїєґ\s-]+)+$/i, '').trim();
    out.push({ href: m[1], title: m[2].trim(), origTitle: origTitle, year: year });
  }
  return out;
}

function searchOnDomain(domain, query) {
  return throughAnubis(domain, function () {
    return request(domain, 'https://' + domain + '/engine/ajax/search.php', {
      method: 'POST',
      headers: ajaxHeaders(domain),
      body: 'q=' + encodeURIComponent(query)
    }, 8000);
  }).then(function (r) {
    if (r.status >= 400) throw new Error('search failed: ' + r.status);
    return parseSearchResults(r.text);
  });
}

// Tries DOMAINS in order; a domain that times out, errors, or serves a bot-challenge page is
// skipped in favor of the next one. The domain that wins is reused for every later request in
// this lookup (page fetch + get_cdn_series), so a mirror is never re-probed mid-flow.
function withWorkingDomain(query) {
  var i = 0;
  function tryNext() {
    if (i >= DOMAINS.length) return Promise.resolve(null);
    var domain = DOMAINS[i++];
    return searchOnDomain(domain, query)
      .then(function (results) { return { domain: domain, results: results }; })
      .catch(function () { return tryNext(); });
  }
  return tryNext();
}

function pickBestMatch(results, tmdbInfo) {
  var best = null;
  var bestScore = -1;
  results.forEach(function (r) {
    var score = Math.max(
      tokenScore(r.title, tmdbInfo.title), tokenScore(r.title, tmdbInfo.originalTitle),
      tokenScore(r.origTitle, tmdbInfo.title), tokenScore(r.origTitle, tmdbInfo.originalTitle)
    );
    var yearBonus = (tmdbInfo.year && r.year && r.year === tmdbInfo.year) ? 0.3 : 0;
    var combined = score + yearBonus;
    if (combined > bestScore) { bestScore = combined; best = r; }
  });
  if (!best) return null;
  var titleScore = Math.max(
    tokenScore(best.title, tmdbInfo.title), tokenScore(best.title, tmdbInfo.originalTitle),
    tokenScore(best.origTitle, tmdbInfo.title), tokenScore(best.origTitle, tmdbInfo.originalTitle)
  );
  var yearMatch = tmdbInfo.year && best.year && best.year === tmdbInfo.year;
  return (titleScore >= 0.4 || yearMatch) ? best : null;
}

// --- Content page: translator list + favs token -----------------------------
// Three live markups seen for the same site (the served template varies per session), so every
// value is pulled from the tag's attributes independently (order-agnostic, as learned from a
// uakino.js bug) and nothing is assumed present:
//   <li title="Name" class="b-translator__item" data-id=.. data-translator_id=..>Name</li>
//   <li><a title="Name" class="b-translator__items" data-id=.. data-translator_id=..
//        data-director="1" href=..>Name <span>(реж. версия)</span></a></li>
//   <li><a title="Name" class="b-translator__items" data-translator_id=.. href=..>Name
//        <img title="Украинский" src=".../flags/ua.png"></a></li>      <- no data-id at all
// The content id therefore falls back to the page's player bootstrap call, then the URL slug.
// title="" is the label (inner text can hold nested tags); a flag icon's language is appended,
// since two entries can otherwise share one name (e.g. "HDrezka Studio" in two languages).

function attr(attrs, name) {
  var m = new RegExp('\\b' + name + '="([^"]*)"').exec(attrs);
  return m ? m[1] : '';
}

function pageContentId(html, url) {
  var boot = /sof\.tv\.initCDN(?:Movies|Series)Events\(\s*(\d+)/.exec(html);
  if (boot) return boot[1];
  var slug = /\/(\d+)-[^\/]*\.html/.exec(url || '');
  return slug ? slug[1] : '';
}

function parseTranslators(html, url) {
  var out = [];
  var seen = {};
  var pageId = pageContentId(html, url);
  var re = /<(?:li|a)\b([^>]*\bb-translator__items?\b[^>]*)>([\s\S]*?)<\/(?:a|li)>/g;
  var m;
  while ((m = re.exec(html))) {
    var attrs = m[1];
    var flag = /<img[^>]+title="([^"]+)"/.exec(m[2]);
    var name = attr(attrs, 'title').trim() || 'Rezka';
    var t = {
      id: attr(attrs, 'data-id') || pageId,
      translatorId: attr(attrs, 'data-translator_id'),
      camrip: attr(attrs, 'data-camrip') || '0',
      ads: attr(attrs, 'data-ads') || '0',
      director: attr(attrs, 'data-director') || '0',
      label: flag ? name + ' (' + flag[1] + ')' : name
    };
    if (!t.id || !t.translatorId) continue;
    var key = t.translatorId + '|' + t.director;
    if (seen[key]) continue;
    seen[key] = true;
    out.push(t);
  }
  if (out.length) return out;
  // A title with a single dub has no translator list at all - the only copy of its ids is the
  // player bootstrap call: initCDNMoviesEvents(981, 56, 0, 0, 0, 'rezka.ag', ...) for films
  // (id, translator, camrip, ads, director) or initCDNSeriesEvents(78091, 376, 2, 10, false, ...)
  // for series (id, translator, season, episode, ...).
  var boot = /sof\.tv\.initCDN(Movies|Series)Events\(\s*(\d+)\s*,\s*(\d+)\s*,\s*([^,]*),\s*([^,]*),\s*([^,]*),/.exec(html);
  if (boot) {
    var isMovie = boot[1] === 'Movies';
    var flagArg = function (v) { return /^\s*1\s*$/.test(v) ? '1' : '0'; };
    out.push({
      id: boot[2], translatorId: boot[3],
      camrip: isMovie ? flagArg(boot[4]) : '0', ads: isMovie ? flagArg(boot[5]) : '0', director: isMovie ? flagArg(boot[6]) : '0',
      label: 'Rezka'
    });
  }
  return out;
}

function resolveContentPage(domain, url) {
  return throughAnubis(domain, function () {
    return request(domain, url, { headers: baseHeaders(domain) }, 10000);
  }).then(function (r) {
    var html = r.text;
    var favsMatch = /<input[^>]+id="ctrl_favs"[^>]+value="([^"]*)"/.exec(html);
    return { translators: parseTranslators(html, url), favs: favsMatch ? favsMatch[1] : '' };
  });
}

// --- get_cdn_series calls ---------------------------------------------------

function postForm(domain, params) {
  var body = Object.keys(params).map(function (k) {
    return k + '=' + encodeURIComponent(params[k]);
  }).join('&');
  return throughAnubis(domain, function () {
    return request(domain, 'https://' + domain + '/ajax/get_cdn_series/?t=' + Date.now(), {
      method: 'POST',
      headers: ajaxHeaders(domain),
      body: body
    }, 10000);
  }).then(function (r) {
    var data;
    try { data = JSON.parse(r.text); } catch (e) { return null; }
    return (data && data.success) ? data : null;
  }).catch(function () { return null; });
}

// Input like "[360p]urlA or urlB or urlC,[480p]url...,[<span class=\"pjs-prem-quality\">4K
// <img .../></span>]url". Quality labels never contain "[" and the url group runs up to the
// next "," that starts a new "[label]" (or end of string), so this stays robust without a
// full HTML parser.
function parseQualityList(raw) {
  var out = [];
  var re = /\[([^\]]*)\]([^\[]+?)(?=,\[|$)/g;
  var m;
  while ((m = re.exec(raw || ''))) {
    var label = m[1].replace(/<[^>]+>/g, '').trim();
    var urls = m[2].split(' or ').map(function (u) { return u.trim(); }).filter(Boolean);
    if (label && urls.length) out.push({ quality: label, url: urls[0] });
  }
  return out;
}

function buildStreams(domain, translatorLabel, qualityList) {
  return qualityList.map(function (q) {
    return {
      name: 'Rezka - ' + translatorLabel,
      title: translatorLabel + ' ' + q.quality,
      url: q.url,
      quality: q.quality,
      headers: { Referer: 'https://' + domain + '/', Origin: 'https://' + domain }
    };
  });
}

function flatten(lists) {
  return lists.reduce(function (acc, l) { return acc.concat(l); }, []);
}

// --- Movie flow: one get_movie call per translator/dub -----------------------

function resolveMovie(domain, page) {
  if (!page.translators.length) return Promise.resolve([]);
  return Promise.all(page.translators.map(function (t) {
    return postForm(domain, {
      id: t.id, translator_id: t.translatorId, is_camrip: t.camrip, is_ads: t.ads, is_director: t.director,
      favs: page.favs, action: 'get_movie'
    }).then(function (data) {
      if (!data || !data.url) return [];
      return buildStreams(domain, t.label, parseQualityList(data.url));
    });
  })).then(flatten);
}

// --- Series flow: get_episodes (which season(s) exist for this dub) then get_stream --------
// Confirmed live: an unofficial dub covering only season 2 comes back from get_episodes with
// "seasons":"<li ... data-tab_id=\"2\">Сезон 2</li>" and nothing for season 1 - so the season
// check below is exactly what the real site itself enforces per translator, not a guess.

function seasonAvailable(seasonsHtml, season) {
  var re = /data-tab_id="(\d+)"/g;
  var m;
  while ((m = re.exec(seasonsHtml || ''))) {
    if (parseInt(m[1], 10) === season) return true;
  }
  return false;
}

function resolveSeries(domain, page, season, episode) {
  if (!page.translators.length) return Promise.resolve([]);
  return Promise.all(page.translators.map(function (t) {
    return postForm(domain, { id: t.id, translator_id: t.translatorId, favs: page.favs, action: 'get_episodes' })
      .then(function (epData) {
        if (!epData || !seasonAvailable(epData.seasons, season)) return [];
        return postForm(domain, {
          id: t.id, translator_id: t.translatorId, season: season, episode: episode,
          favs: page.favs, action: 'get_stream'
        }).then(function (streamData) {
          if (!streamData || !streamData.url) return [];
          return buildStreams(domain, t.label, parseQualityList(streamData.url));
        });
      });
  })).then(flatten);
}

// --- Entry point -------------------------------------------------------------

function getStreams(tmdbId, mediaType, season, episode) {
  return getTmdbInfo(tmdbId, mediaType).then(function (info) {
    if (!info.title) return [];
    return withWorkingDomain(info.title).then(function (found) {
      if (found && found.results.length) return found;
      if (info.originalTitle && info.originalTitle !== info.title) return withWorkingDomain(info.originalTitle);
      return found;
    }).then(function (found) {
      if (!found) return [];
      var match = pickBestMatch(found.results, info);
      if (!match) return [];
      return resolveContentPage(found.domain, match.href).then(function (page) {
        if (mediaType === 'tv' && season && episode) return resolveSeries(found.domain, page, season, episode);
        return resolveMovie(found.domain, page);
      });
    });
  }).catch(function () {
    return [];
  });
}

module.exports = { getStreams: getStreams };
