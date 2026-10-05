// Nuvio provider: HDRezka (rezka.ag, fallback mirror rezka-tv.org)
//
// JS twin of the native .cs3 plugin (nuvio-rezka), for Nuvio clients that only run JS
// scrapers (Nuvio Mobile on phones/tablets). Behaviour verified live against the site:
//  - Every mirror sits behind Anubis, a proof-of-work gate (not a CAPTCHA): sha256(randomData +
//    nonce) must start with `difficulty` hex zeros (2 seen live, ~256 hashes). Solved below in
//    pure JS since the plugin runtimes have no WebCrypto.
//  - Stream lists come back as plain "[quality]url or url2,[quality]..." text, no decryption.
//  - Without a subscription the quality labels are overstated by one rung ("1080p" is a 1280x720
//    file, "720p" is 854x480 ...), and every premium label (1080p Ultra, 2K, 4K) points to one
//    60-second "buy premium" clip. So premium entries are dropped, the real resolution is read
//    from the mp4 header once per lookup, and each dub yields its single best link (720p for
//    guests). Whole dubs can be premium-only (premium_content: 1, every label -> a stub): skipped.
//
// Written as plain Promise chains (no async/await) so it also runs on runtimes that do not
// support async functions in dynamically loaded providers.

var TMDB_API_KEY = '439c478a771f35c05022f9feabcca01c'; // shared community demo key; swap for your own free key from themoviedb.org if you get rate-limited
var DOMAINS = ['rezka.ag', 'rezka-tv.org'];
// Anubis on Rezka (like its default policy) only challenges clients that claim to be a browser
// ("Mozilla/..."). Nuvio Mobile follows the pass-challenge 302 itself and has no cookie jar, so
// the auth cookie would be lost; identifying as what the request really is - Nuvio's OkHttp
// client - gets the pages directly. The Anubis solver below stays as a fallback.
var UA = 'okhttp/4.12.0';
var PARALLEL = 6;             // the site answers 503 when hammered harder than this
var BUDGET_MS = 40000;        // stop asking for more dubs after this; Nuvio drops everything at 60 s
var DEFAULT_OFFSET = 1;       // label overstatement measured on every title checked live
var LADDER = [240, 360, 480, 720, 1080, 1440, 2160];
var RETRYABLE = { 429: 1, 500: 1, 502: 1, 503: 1, 504: 1 };

// When Nuvio's provider test (always The Matrix, TMDB 603) finds no streams, the trace is returned
// as one entry per step, so the failing step is visible on the device. Never in normal lookups.
var DEBUG_TMDB_ID = '603';
var DEBUG = false;
var _trace = [];
var _started = 0;

function trace(step) {
  _trace.push(step);
  if (_trace.length > 40) _trace.shift();
}

function log(msg) {
  trace(msg);
  try { console.log('[Rezka] ' + msg); } catch (e) { /* no console */ }
}

function delay(ms) {
  return new Promise(function (resolve) { setTimeout(resolve, ms); });
}

function baseHeaders(domain) {
  return {
    'User-Agent': UA,
    'Accept-Language': 'ru-RU,ru;q=0.9,uk;q=0.8,en;q=0.7',
    'Referer': 'https://' + domain + '/'
  };
}

function ajaxHeaders(domain, referer) {
  return Object.assign(baseHeaders(domain), {
    'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
    'X-Requested-With': 'XMLHttpRequest',
    'Origin': 'https://' + domain,
    'Referer': referer || 'https://' + domain + '/'
  });
}

// No per-request timer race: in Nuvio Mobile setTimeout is a host-side sleep that clearTimeout
// cannot cancel, so every request would leave a 10 s sleep pending. The host HTTP client has its
// own timeouts and the whole plugin call is capped at 60 s.
function fetchWithTimeout(url, opts) {
  return fetch(url, opts);
}

// --- Cookies -----------------------------------------------------------------
// Anubis needs its verification cookie echoed back on pass-challenge, and the resulting auth
// cookie on every request after. Some runtimes keep a native cookie jar (and a hand-set Cookie
// header can suppress it); Nuvio Mobile has none but passes Set-Cookie through. So cookies are
// always recorded here and only sent by hand once the native jar has been shown not to work for
// this domain (_cookieMode 'manual'); see throughAnubis().

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

function requestOnce(domain, url, opts, ms) {
  opts = opts || {};
  var headers = Object.assign({}, opts.headers);
  var ck = _cookieMode[domain] === 'manual' ? cookieHeader(domain) : '';
  if (ck) headers.Cookie = ck;
  var what = /search\.php/.test(url) ? 'search' : /pass-challenge/.test(url) ? 'pass'
    : /get_cdn_series/.test(url) ? 'ajax' : 'get';
  return fetchWithTimeout(url, Object.assign({}, opts, { headers: headers }), ms).then(function (res) {
    storeCookies(domain, res);
    return res.text().then(function (text) {
      text = text || '';
      trace(what + ':' + res.status + (isChallenge(text) ? 'A' : '') + (ck ? 'c' : '') + (res.headers && res.headers.get && res.headers.get('set-cookie') ? 's' : ''));
      return { status: res.status, text: text };
    });
  }, function (e) {
    trace(what + ':ERR ' + (e && e.message ? String(e.message).slice(0, 60) : e));
    throw e;
  });
}

// Retries the statuses the site uses when it is busy, with a growing pause.
function request(domain, url, opts, ms) {
  function attempt(n) {
    return requestOnce(domain, url, opts, ms).then(function (r) {
      if (RETRYABLE[r.status] && n < 2) return delay(700 * (n + 1)).then(function () { return attempt(n + 1); });
      return r;
    });
  }
  return attempt(0);
}

// --- SHA-256 (ASCII input only - Anubis hashes a hex string plus a decimal nonce) ----------
// Verified against the FIPS "abc" / empty / 56-byte vectors and a real captured challenge.

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

function isChallenge(html) {
  return !!html && (html.indexOf('anubis_challenge') >= 0 || html.indexOf('/.within.website/x/cmd/anubis/') >= 0);
}

function parseAnubisChallenge(html) {
  var m = /<script id="anubis_challenge" type="application\/json">([\s\S]*?)<\/script>/.exec(html || '');
  if (!m) return null;
  try { return JSON.parse(m[1]); } catch (e) { return null; }
}

// "fast" and "slow" are the same algorithm in Anubis's own client. Difficulty is capped so a
// site cranking it up cannot pin the device for minutes.
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

// Solves the challenge the gated response carried (it is bound to the verification cookie that
// response set) or, when it had none, a fresh one from the home page.
function passAnubis(domain, html) {
  var home = 'https://' + domain + '/';
  var source = parseAnubisChallenge(html)
    ? Promise.resolve(html)
    : request(domain, home, { headers: baseHeaders(domain) }, 10000).then(function (r) { return r.text; });
  return source.then(function (body) {
    var ch = parseAnubisChallenge(body);
    if (!ch) return null; // home page not gated (anymore): just retry the original request
    var sol = solveAnubis(ch);
    if (!sol) throw new Error('anubis: unsolvable challenge');
    var url = home + '.within.website/x/cmd/anubis/api/pass-challenge' +
      '?id=' + encodeURIComponent(sol.id) +
      '&response=' + sol.response +
      '&nonce=' + sol.nonce +
      '&redir=' + encodeURIComponent(home) +
      '&elapsedTime=' + sol.elapsed;
    // redirect:'manual' so the 302 carrying the auth Set-Cookie reaches storeCookies().
    // requestOnce: a rejected pass is not "busy", retrying the same single-use answer is pointless.
    return requestOnce(domain, url, { headers: baseHeaders(domain), redirect: 'manual' }, 10000).then(function (r) {
      if (r.status >= 400) throw new Error('anubis: pass rejected ' + r.status);
      return r;
    });
  });
}

// Runs a request; if Anubis answers instead of the site, solves the challenge and retries.
// The first pass trusts the runtime's native cookie jar. If the pass is rejected (no
// verification cookie reached it) or the retry is still challenged, there evidently is no
// working jar, so the domain switches to manual cookies and a fresh (single-use) challenge is
// solved again. Nuvio Mobile has no jar at all and always ends up in manual mode.
function throughAnubis(domain, doRequest) {
  function gated(r) { return isChallenge(r.text); }
  function cycle(r, passesLeft) {
    if (!gated(r)) {
      if (!_cookieMode[domain]) _cookieMode[domain] = 'native';
      return r;
    }
    if (passesLeft <= 0) throw new Error('anubis: still challenged after pass');
    var wasManual = _cookieMode[domain] === 'manual';
    return passAnubis(domain, r.text).then(function () {
      return doRequest();
    }, function (e) {
      if (wasManual) throw e;
      _cookieMode[domain] = 'manual';
      return doRequest(); // gated again, now carrying the cookies recorded so far
    }).then(function (r2) {
      if (gated(r2)) _cookieMode[domain] = 'manual';
      return cycle(r2, passesLeft - 1);
    });
  }
  return doRequest().then(function (r) { return cycle(r, 3); });
}

// --- Text helpers ---------------------------------------------------------------

function decodeEntities(s) {
  return (s || '')
    .replace(/&quot;/g, '"').replace(/&#0?39;/g, "'").replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&nbsp;/g, ' ');
}

function normalize(s) {
  return (s || '')
    .toLowerCase()
    .replace(/ё/g, 'е')
    .replace(/['"«»():,.!?_\-–—\/]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function tokenScore(a, b) {
  var na = normalize(a), nb = normalize(b);
  if (!na || !nb) return 0;
  if (na === nb) return 1;
  var ta = na.split(' '), tb = nb.split(' ');
  var setB = {};
  tb.forEach(function (t) { setB[t] = true; });
  var hits = 0;
  ta.forEach(function (t) { if (setB[t]) hits++; });
  return hits / Math.max(ta.length, tb.length);
}

// --- TMDB lookup -----------------------------------------------------------
// ru-RU: Rezka's catalog is Russian-language, so the Russian title matches best; the original
// title covers the rest.

function getTmdbInfo(tmdbId, mediaType) {
  var kind = mediaType === 'tv' ? 'tv' : 'movie';
  var url = 'https://api.themoviedb.org/3/' + kind + '/' + tmdbId + '?api_key=' + TMDB_API_KEY + '&language=ru-RU';
  return fetchWithTimeout(url, {}, 10000).then(function (r) { return r.json(); }).then(function (data) {
    data = data || {};
    var title = kind === 'tv' ? (data.name || data.original_name) : (data.title || data.original_title);
    var dateStr = kind === 'tv' ? data.first_air_date : data.release_date;
    return {
      title: title,
      originalTitle: kind === 'tv' ? data.original_name : data.original_title,
      year: dateStr ? parseInt(dateStr.slice(0, 4), 10) : null
    };
  });
}

// --- Search ------------------------------------------------------------
// Live markup: <li><a href="URL"><span class="enty">Title</span> (Paren)<span class="rating">,
// where Paren is "The Matrix, 1999", "Breaking Bad, сериал, 2008-2013", "Rick and Morty,
// мультфильм, 2013 - ..." or just "2019" for a Russian-original title. The year is the first
// comma-led 4-digit group ("Blade Runner 2049, 2017" keeps 2049 in the title).

function parseSearchResults(html, domain) {
  var out = [];
  var seen = {};
  var re = /<li><a href="([^"]+)"><span class="enty">([^<]*)<\/span>\s*\(([^)]*)\)/g;
  var m;
  while ((m = re.exec(html || ''))) {
    var href = m[1];
    var host = /^https?:\/\/([^\/]+)/.exec(href);
    if (host && host[1] !== domain) {
      if (DOMAINS.indexOf(host[1]) < 0) continue;           // foreign site
      href = href.replace(host[1], domain);                  // stay on the mirror whose gate we passed
    } else if (!host) {
      href = 'https://' + domain + (href.charAt(0) === '/' ? '' : '/') + href;
    }
    if (!/\.html$/.test(href) || seen[href]) continue;
    seen[href] = true;
    var local = decodeEntities(m[2]).trim();
    var paren = decodeEntities(m[3]);
    var yearMatch = /(?:^|,\s*)((?:19|20)\d{2})\b/.exec(paren);
    var year = yearMatch ? parseInt(yearMatch[1], 10) : null;
    var head = yearMatch ? paren.slice(0, yearMatch.index) : '';
    var original = head.replace(/(,\s*[а-яёіїєґ\s-]+)+$/i, '').trim();
    var kind = /\/series\//.test(href) ? 'tv'
      : /\/films\//.test(href) ? 'movie'
      : (/сериал/i.test(paren) || /(?:19|20)\d{2}\s*-\s*(?:(?:19|20)\d{2}|\.\.\.)/.test(paren)) ? 'tv'
      : null; // cartoon/anime with one year: film or ongoing show, unknown until the page
    var names = original.split(' / ').concat(local.split(' / '))
      .map(function (s) { return s.trim(); }).filter(Boolean);
    out.push({ href: href, title: local, names: names, year: year, kind: kind });
  }
  return out;
}

function searchOnDomain(domain, query) {
  return throughAnubis(domain, function () {
    return request(domain, 'https://' + domain + '/engine/ajax/search.php', {
      method: 'POST',
      headers: ajaxHeaders(domain),
      body: 'q=' + encodeURIComponent(query)
    }, 10000);
  }).then(function (r) {
    // Status 0 = no connection at all (blocked host, DNS): try the next mirror.
    if (r.status < 200 || r.status >= 400) throw new Error('search failed: ' + r.status);
    return parseSearchResults(r.text, domain);
  });
}

// Tries DOMAINS in order; the first one that answers (even with 0 hits) wins.
function searchAnyDomain(query) {
  var i = 0;
  function tryNext() {
    if (i >= DOMAINS.length) return Promise.resolve(null);
    var domain = DOMAINS[i++];
    return searchOnDomain(domain, query)
      .then(function (results) { return { domain: domain, results: results }; })
      .catch(function (e) { log('search on ' + domain + ' failed: ' + (e && e.message)); return tryNext(); });
  }
  return tryNext();
}

function pickBestMatch(results, info, mediaType) {
  var wanted = mediaType === 'tv' ? 'tv' : 'movie';
  var candidates = [info.title, info.originalTitle].filter(Boolean);
  var best = null, bestScore = -1;
  results.forEach(function (r) {
    if (info.year && r.year && Math.abs(info.year - r.year) > 1) return;
    var titleScore = 0;
    r.names.forEach(function (n) {
      candidates.forEach(function (c) { titleScore = Math.max(titleScore, tokenScore(n, c)); });
    });
    if (r.kind && r.kind !== wanted && titleScore < 0.95) return;
    var yearExact = !!(info.year && r.year === info.year);
    if (!(titleScore >= 0.5 || (titleScore >= 0.3 && yearExact))) return;
    var score = titleScore + (yearExact ? 0.3 : 0) + (r.kind === wanted ? 0.05 : 0);
    if (score > bestScore) { bestScore = score; best = r; }
  });
  return best;
}

// --- Content page: translator list + favs token -----------------------------
// Live markups (template varies per session), parsed attribute-order-agnostic:
//   <li title="Name" class="b-translator__item" data-id=.. data-translator_id=..>Name</li>
//   <a title="Name" class="b-translator__items" data-translator_id=.. href=..>Name
//        <img title="Украинский" src=".../flags/ua.png"></a>                <- no data-id
// The content id falls back to the player bootstrap call, then the URL slug.

function attr(attrs, name) {
  var m = new RegExp('\\b' + name + '="([^"]*)"').exec(attrs);
  return m ? m[1] : '';
}

var BOOT = /sof\.tv\.initCDN(Movies|Series)Events\(\s*(\d+)\s*,\s*(\d+)(?:\s*,\s*([^,)]*))?(?:\s*,\s*([^,)]*))?(?:\s*,\s*([^,)]*))?/;

function isUkrainian(label) {
  return /укра|ukrain/i.test(label || '');
}

function parseTranslators(html, url) {
  var out = [];
  var seen = {};
  var boot = BOOT.exec(html);
  var slug = /\/(\d+)-[^\/]*\.html/.exec(url || '');
  var pageId = boot ? boot[2] : (slug ? slug[1] : '');
  var flagArg = function (v) { return /^\s*1\s*$/.test(v || '') ? '1' : '0'; };
  var re = /<(?:li|a)\b([^>]*\bb-translator__items?\b[^>]*)>([\s\S]*?)<\/(?:a|li)>/g;
  var m;
  while ((m = re.exec(html))) {
    var attrs = m[1];
    var flag = /<img[^>]+title="([^"]+)"[^>]*>/.exec(m[2]) || /<img[^>]+>/.exec(m[2]);
    var flagTitle = flag && flag[1] ? decodeEntities(flag[1]).trim() : '';
    var name = decodeEntities(attr(attrs, 'title')).trim() || 'Rezka';
    var label = flagTitle && name.toLowerCase().indexOf(flagTitle.toLowerCase()) < 0 ? name + ' (' + flagTitle + ')' : name;
    var t = {
      id: attr(attrs, 'data-id') || pageId,
      translatorId: attr(attrs, 'data-translator_id'),
      camrip: flagArg(attr(attrs, 'data-camrip')),
      ads: flagArg(attr(attrs, 'data-ads')),
      director: flagArg(attr(attrs, 'data-director')),
      label: label,
      ukrainian: (flag && /\/flags\/ua/.test(flag[0])) || isUkrainian(label)
    };
    if (!t.id || !t.translatorId) continue;
    var key = t.translatorId + '|' + t.director;
    if (seen[key]) continue;
    seen[key] = true;
    out.push(t);
  }
  // A title with a single dub has no translator list; the player bootstrap holds its ids:
  // initCDNMoviesEvents(id, translator, camrip, ads, director, ...) for films,
  // initCDNSeriesEvents(id, translator, season, episode, ...) for series.
  if (!out.length && boot) {
    var isMovie = boot[1] === 'Movies';
    out.push({
      id: boot[2], translatorId: boot[3],
      camrip: isMovie ? flagArg(boot[4]) : '0', ads: isMovie ? flagArg(boot[5]) : '0', director: isMovie ? flagArg(boot[6]) : '0',
      label: 'Rezka', ukrainian: false
    });
  }
  // Ukrainian dubs first; otherwise the site's own order (its default dub leads). Stable sort.
  return out.map(function (t, i) { return { t: t, i: i }; })
    .sort(function (a, b) { return (b.t.ukrainian - a.t.ukrainian) || (a.i - b.i); })
    .map(function (x) { return x.t; });
}

function parsePage(html, url, domain) {
  var favs = /<input[^>]+id="ctrl_favs"[^>]+value="([^"]*)"/.exec(html) || /<input[^>]+value="([^"]*)"[^>]+id="ctrl_favs"/.exec(html);
  return {
    domain: domain,
    url: url,
    translators: parseTranslators(html, url),
    favs: favs ? favs[1] : '',
    isSeries: /initCDNSeriesEvents/.test(html) || html.indexOf('simple-episodes-tabs') >= 0
  };
}

// Mirrors share one backend and URL layout: a page the search mirror fails to serve is fetched
// from the others, and its ajax calls then follow the mirror that answered.
function resolveContentPage(domain, url) {
  var path = url.replace(/^https?:\/\/[^\/]+/, '');
  var order = [domain].concat(DOMAINS.filter(function (d) { return d !== domain; }));
  var i = 0;
  function tryNext(lastError) {
    if (i >= order.length) return Promise.reject(lastError || new Error('page unavailable'));
    var d = order[i++];
    var pageUrl = 'https://' + d + path;
    return throughAnubis(d, function () {
      return request(d, pageUrl, { headers: baseHeaders(d) }, 12000);
    }).then(function (r) {
      if (r.status < 200 || r.status >= 300) throw new Error('page status ' + r.status);
      return parsePage(r.text, pageUrl, d);
    }).catch(function (e) {
      log('page on ' + d + ' failed: ' + (e && e.message));
      return tryNext(e);
    });
  }
  return tryNext(null);
}

// --- get_cdn_series calls ---------------------------------------------------

function postForm(page, params) {
  var domain = page.domain;
  params.favs = page.favs;
  var body = Object.keys(params).map(function (k) {
    return k + '=' + encodeURIComponent(params[k]);
  }).join('&');
  return throughAnubis(domain, function () {
    return request(domain, 'https://' + domain + '/ajax/get_cdn_series/?t=' + Date.now(), {
      method: 'POST',
      headers: ajaxHeaders(domain, page.url),
      body: body
    }, 12000);
  }).then(function (r) {
    var data;
    try { data = JSON.parse(r.text); } catch (e) { return null; }
    return (data && data.success) ? data : null;
  }).catch(function (e) {
    log('ajax failed: ' + (e && e.message));
    return null;
  });
}

function labelQuality(label) {
  if (/4K/i.test(label)) return 2160;
  if (/2K/i.test(label)) return 1440;
  var m = /\d{3,4}/.exec(label);
  return m ? parseInt(m[0], 10) : 0;
}

// "[360p]urlA.m3u8 or urlA.mp4,[480p]url,...,[<span class="pjs-prem-quality">4K<img/></span>]url".
// Premium entries are dropped (they all point to the same "buy premium" clip).
function parseQualityList(raw) {
  var out = [];
  var seen = {};
  var re = /\[([^\]]*)\]([^\[]+?)(?=,\[|$)/g;
  var m;
  while ((m = re.exec(typeof raw === 'string' ? raw : ''))) {
    if (/prem/i.test(m[1])) continue;
    var label = m[1].replace(/<[^>]+>/g, '').trim();
    var urls = m[2].split(' or ').map(function (u) { return u.trim(); }).filter(function (u) { return /^https?:\/\//.test(u); });
    if (!label || !urls.length || seen[urls[0]]) continue;
    seen[urls[0]] = true;
    var mp4 = urls.filter(function (u) { return /\.mp4$/.test(u.split('?')[0]); })[0] || null;
    out.push({ quality: labelQuality(label), url: urls[0], urls: urls, mp4: mp4 });
  }
  return out;
}

// "[Русский]https://…vtt,[Українська]https://…vtt"; subtitle_lns maps names to codes ("ua", "ru").
function parseSubtitles(raw, lns) {
  if (typeof raw !== 'string' || !raw) return [];
  var out = [];
  var re = /\[([^\]]+)\](https?:\/\/[^,\[\s]+)/g;
  var m;
  while ((m = re.exec(raw))) {
    var name = decodeEntities(m[1]).trim();
    var code = (lns && typeof lns === 'object' && lns[name]) || '';
    if (code === 'ua') code = 'uk';
    out.push({ url: m[2], language: code || name, name: name });
  }
  return out;
}

// --- Real quality ------------------------------------------------------------

function qualityOfWidth(w) {
  if (w >= 3000) return 2160;
  if (w >= 2200) return 1440;
  if (w >= 1700) return 1080;
  if (w >= 1100) return 720;
  if (w >= 800) return 480;
  if (w >= 560) return 360;
  return 240;
}

// Largest track width among the "tkhd" boxes of an mp4 head (16.16 fixed, last 8 bytes of the box).
function mp4Width(bytes) {
  var best = 0;
  function int32(at) { return ((bytes[at] << 24) | (bytes[at + 1] << 16) | (bytes[at + 2] << 8) | bytes[at + 3]) >>> 0; }
  for (var i = 4; i + 4 <= bytes.length; i++) {
    if (bytes[i] === 0x74 && bytes[i + 1] === 0x6b && bytes[i + 2] === 0x68 && bytes[i + 3] === 0x64) { // "tkhd"
      var size = int32(i - 4);
      var end = i - 4 + size;
      if (size >= 84 && size <= 200 && end <= bytes.length) {
        var w = int32(end - 8) >>> 16;
        if (w > best) best = w;
      }
    }
  }
  return best || null;
}

function labelOffset(labeled, actual) {
  var from = LADDER.indexOf(labeled), to = LADDER.indexOf(actual);
  if (from < 0 || to < 0) return 0;
  return Math.max(0, Math.min(3, from - to));
}

function realQuality(labeled, offset) {
  var i = LADDER.indexOf(labeled);
  return (i < 0 || offset <= 0) ? labeled : LADDER[Math.max(0, i - offset)];
}

// Reads the first 64 KiB of the best-labelled mp4 once per lookup; DEFAULT_OFFSET on any failure.
function measureOffset(qualities) {
  trace('measure');
  var top = qualities.slice().sort(function (a, b) { return b.quality - a.quality; })[0];
  if (!top || !top.mp4) return Promise.resolve(DEFAULT_OFFSET);
  return fetchWithTimeout(top.mp4, { headers: { 'User-Agent': UA, 'Range': 'bytes=0-65535' } }, 8000)
    .then(function (res) {
      if (res.status !== 200 && res.status !== 206) return DEFAULT_OFFSET;
      return res.arrayBuffer().then(function (buf) {
        var w = mp4Width(new Uint8Array(buf));
        trace('mp4:' + res.status + ' w=' + w);
        return w ? labelOffset(top.quality, qualityOfWidth(w)) : DEFAULT_OFFSET;
      });
    })
    .catch(function () { return DEFAULT_OFFSET; });
}

// --- Streams -------------------------------------------------------------------

function mapLimit(items, limit, fn) {
  var results = new Array(items.length);
  var next = 0;
  function worker() {
    if (next >= items.length) return Promise.resolve();
    var i = next++;
    return Promise.resolve().then(function () { return fn(items[i], i); })
      .then(function (r) { results[i] = r; }, function () { results[i] = null; })
      .then(worker);
  }
  var workers = [];
  for (var w = 0; w < Math.min(limit, items.length); w++) workers.push(worker());
  return Promise.all(workers).then(function () { return results; });
}

// A whole dub can be premium-only: the server then flags premium_content and every label points
// to one 60-second "buy premium" clip. Such dubs are skipped, and never used to measure quality.
function isPremiumOnly(data, qualities) {
  if (String(data && data.premium_content) === '1') return true;
  var files = {};
  qualities.forEach(function (q) { files[(q.mp4 || q.url).split(':hls:')[0]] = true; });
  return qualities.length > 1 && Object.keys(files).length === 1;
}

// Each quality comes with mirror URLs: HLS on prx*-cogent.ukrtelcdn.net, HLS on voidboost, then
// the same file as plain mp4 on both. Measured live: the ukrtelcdn manifests are packaged on the
// fly and answered 502 in ~10% of tries, voidboost in none of 89, at the same speed. Checking a
// mirror costs ~1.5 s per dub (that packaging), so voidboost HLS is simply preferred.
function preferredUrl(urls) {
  for (var i = 0; i < urls.length; i++) {
    if (/voidboost/.test(urls[i]) && /\.m3u8$/.test(urls[i].split('?')[0])) return urls[i];
  }
  return urls[0];
}

function buildStreams(page, t, data, offsetPromise) {
  var qualities = parseQualityList(data && data.url);
  if (!qualities.length || isPremiumOnly(data, qualities)) return Promise.resolve([]);
  var subtitles = parseSubtitles(data.subtitle, data.subtitle_lns);
  return offsetPromise(qualities).then(function (offset) {
    // One link per dub, its best real quality: lower rungs of the same dub only bloat the list.
    var best = qualities.slice().sort(function (a, b) { return b.quality - a.quality; })[0];
    return Promise.resolve(preferredUrl(best.urls)).then(function (url) {
      var quality = realQuality(best.quality, offset);
      // Nuvio's source card shows `name` (falling back to `title`) and sorts a provider's
      // cards alphabetically by it, so the dub goes into `name`, and Ukrainian dubs get a "(UA)"
      // prefix: "(" sorts before every letter, keeping them on top. The group header already
      // says HDRezka.
      var label = t.ukrainian ? '(UA) ' + t.label.replace(/\s*\((Украинский|Український)\)\s*$/i, '') : t.label;
      var stream = {
        name: label,
        title: t.label + ' · ' + quality + 'p',
        url: url,
        quality: quality + 'p',
        headers: { 'Referer': 'https://' + page.domain + '/', 'User-Agent': UA }
      };
      if (t.ukrainian) stream.language = 'UA';
      if (subtitles.length) stream.subtitles = subtitles;
      return [stream];
    });
  });
}

function resolveStreams(page, season, episode) {
  if (!page.translators.length) return Promise.resolve([]);
  // The label offset is measured once, by whichever dub answers first; the rest reuse it.
  var measured = null;
  function offsetPromise(qualities) {
    if (!measured) measured = measureOffset(qualities);
    return measured;
  }
  var series = page.isSeries && season && episode;
  return mapLimit(page.translators, PARALLEL, function (t) {
    // Slow network or a runtime that runs requests one by one (Nuvio TV): keep what is found.
    if (Date.now() - _started > BUDGET_MS) { trace('budget: skipped ' + t.label); return []; }
    var params = series
      ? { id: t.id, translator_id: t.translatorId, season: season, episode: episode, action: 'get_stream' }
      : { id: t.id, translator_id: t.translatorId, is_camrip: t.camrip, is_ads: t.ads, is_director: t.director, action: 'get_movie' };
    return postForm(page, params).then(function (data) {
      return data ? buildStreams(page, t, data, offsetPromise) : [];
    });
  }).then(function (lists) {
    return lists.reduce(function (acc, l) { return l ? acc.concat(l) : acc; }, []);
  });
}

// --- Entry point -------------------------------------------------------------

function diagnose(streams) {
  if (!DEBUG || (streams && streams.length)) return streams || [];
  // One short entry per step: Nuvio shows a single line per result, so a long title is cut off.
  return _trace.map(function (step, i) {
    return {
      name: 'HDRezka',
      title: (i < 10 ? '0' : '') + i + ' ' + String(step).slice(0, 70),
      url: 'https://rezka.ag/#debug-' + i,
      quality: 'debug'
    };
  });
}

function getStreams(tmdbId, mediaType, season, episode) {
  _trace = [];
  _started = Date.now();
  DEBUG = String(tmdbId) === DEBUG_TMDB_ID;
  trace('v2.3.0 ' + mediaType + ' ' + tmdbId);
  return getTmdbInfo(tmdbId, mediaType).then(function (info) {
    trace('tmdb ' + info.year + ' ' + info.originalTitle);
    if (!info.title) return [];
    var queries = [info.title];
    if (info.originalTitle && info.originalTitle !== info.title) queries.push(info.originalTitle);
    var q = 0;
    function searchNext() {
      if (q >= queries.length) return Promise.resolve(null);
      var query = queries[q++];
      return searchAnyDomain(query).then(function (found) {
        var match = found && pickBestMatch(found.results, info, mediaType);
        trace('found ' + (found ? found.domain + ' n=' + found.results.length : 'none') + ' ' + (match ? match.href.replace(/^https?:\/\/[^\/]+/, '').slice(0, 40) : 'nomatch'));
        if (match) return { domain: found.domain, match: match };
        return searchNext();
      });
    }
    return searchNext().then(function (hit) {
      if (!hit) { log('no match for ' + info.title + ' (' + info.year + ')'); return []; }
      return resolveContentPage(hit.domain, hit.match.href).then(function (page) {
        trace('page ' + page.domain + ' dubs=' + page.translators.length + ' ser=' + page.isSeries + ' favs=' + !!page.favs);
        return resolveStreams(page, season, episode);
      });
    });
  }).catch(function (e) {
    log('failed: ' + (e && e.message));
    return [];
  }).then(diagnose);
}

module.exports = { getStreams: getStreams };
