// Nuvio provider: Uakino (uakino.best)
// Hand-ported from the CloudStream Kotlin provider UakinoProvider.kt / UakinoParsing.kt
// (https://github.com/CakesTwix/cloudstream-extensions-uk).
//
// !!! KNOWN RISK: as of the port date, uakino.best returns a Cloudflare "Managed Challenge"
// ("Just a moment...") page to plain HTTP requests (verified from this environment, on both
// the homepage and the search endpoint). A bare fetch() with no JS execution cannot solve
// that challenge. Real end-user devices on residential/mobile IPs may or may not get
// challenged (Cloudflare risk-scores by IP reputation, and datacenter IPs get hit hardest),
// so this needs to be verified for real in the Nuvio Plugin Tester on an actual device before
// relying on it. If it's consistently challenged there too, this provider cannot work without
// a browser-based solver, which is outside what a Nuvio JS provider can do.
//
// Nuvio only gives us a TMDB id, not a title, so this provider resolves the TMDB id to a
// title via the TMDB API, then runs it through Uakino's own site search and picks the best
// textual match. That matching step is inherently best-effort for a non-English catalog.
//
// Written as plain Promise chains (no async/await) since the Hermes plugin runtime does not
// run async/await in dynamically loaded providers.

var TMDB_API_KEY = '439c478a771f35c05022f9feabcca01c'; // shared community demo key; swap for your own free key from themoviedb.org if you get rate-limited
var BASE = 'https://uakino.best';
var UA = 'Mozilla/5.0 (Linux; Android 15; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.7778.215 Mobile Safari/537.36';

function baseHeaders(referer) {
  return {
    'User-Agent': UA,
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'uk-UA,uk;q=0.9,en-US;q=0.8,en;q=0.7',
    'Referer': referer || BASE
  };
}

function ajaxHeaders() {
  return { Referer: BASE, 'X-Requested-With': 'XMLHttpRequest', 'User-Agent': UA };
}

function fetchHtml(url, headers) {
  return fetch(url, { headers: headers || baseHeaders() }).then(function (r) { return r.text(); });
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

function guessQuality(url) {
  var m = /([0-9]{3,4})p/.exec(url || '');
  return m ? m[1] + 'p' : '1080p';
}

var BLACKLIST_RE = /\/(news|franchise)\//;

// --- Minimal base64 decoder (no atob assumption in the plugin sandbox) -----

function base64ToBytes(b64) {
  var chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  var clean = (b64 || '').replace(/[^A-Za-z0-9+/]/g, '');
  var bytes = [];
  var buffer = 0, bits = 0;
  for (var i = 0; i < clean.length; i++) {
    var val = chars.indexOf(clean.charAt(i));
    if (val === -1) continue;
    buffer = (buffer << 6) | val;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      bytes.push((buffer >> bits) & 0xFF);
    }
  }
  return bytes;
}

// Tortuga player obfuscation: first byte is a salt, remaining bytes are
// XOR-ed with (salt + 7*i + 13) % 256. Ported from decodeUakinoTortuga (Kotlin).
function decodeTortuga(encoded) {
  var clean = (encoded || '').replace(/\s/g, '').replace(/=+$/, '');
  if (!clean) return null;
  var bytes = base64ToBytes(clean);
  if (bytes.length < 2) return null;
  var salt = bytes[0];
  var chars = [];
  for (var i = 1; i < bytes.length; i++) {
    var key = (salt + 7 * (i - 1) + 13) % 256;
    chars.push(String.fromCharCode(bytes[i] ^ key));
  }
  var str = chars.join('');
  return (str.indexOf('http://') === 0 || str.indexOf('https://') === 0) ? str : null;
}

function resolveStreamUrl(rawUrl) {
  var value = (rawUrl || '').trim();
  if (!value) return null;
  if (value.indexOf('http://') === 0 || value.indexOf('https://') === 0) return value;
  return decodeTortuga(value);
}

function normalizePlayerUrl(rawUrl) {
  if (rawUrl.indexOf('//') === 0) return 'https:' + rawUrl;
  if (rawUrl.indexOf('http://') === 0) return 'https://' + rawUrl.slice('http://'.length);
  return rawUrl;
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

// --- Site search ---------------------------------------------------------
// Mirrors `div.movie-item.short-item` -> `a.movie-title, a.full-movie` from the Kotlin selectors.

function parseSearchResults(html) {
  var results = [];
  var re = /<a[^>]*class="[^"]*(?:movie-title|full-movie)[^"]*"[^>]*href="([^"]+)"[^>]*>([^<]*)<\/a>/g;
  var m;
  while ((m = re.exec(html))) {
    if (BLACKLIST_RE.test(m[1])) continue;
    var title = m[2].trim();
    if (title) results.push({ href: m[1], title: title });
  }
  return results;
}

function searchUakino(query) {
  var body = 'do=search&subaction=search&story=' + encodeURIComponent(query).replace(/%20/g, '+');
  return fetch(BASE + '/ua/', {
    method: 'POST',
    headers: Object.assign({ 'Content-Type': 'application/x-www-form-urlencoded' }, baseHeaders())
  , body: body
  }).then(function (r) { return r.text(); }).then(parseSearchResults);
}

function pickBestMatch(results, tmdbInfo) {
  var best = null;
  var bestScore = 0;
  results.forEach(function (r) {
    var score = Math.max(tokenScore(r.title, tmdbInfo.title), tokenScore(r.title, tmdbInfo.originalTitle));
    if (score > bestScore) {
      bestScore = score;
      best = r;
    }
  });
  return bestScore >= 0.4 ? best : null;
}

// --- Player extraction -----------------------------------------------------
// Mirrors extractPlayerJs(): concatenate <script> bodies, pull `file:"..."` (prefer .m3u8),
// resolve via Tortuga XOR if it isn't already a plain URL.

function extractScripts(html) {
  var out = [];
  var re = /<script[^>]*>([\s\S]*?)<\/script>/g;
  var m;
  while ((m = re.exec(html))) out.push(m[1]);
  return out.join('\n');
}

function extractPlayerStream(playerUrl, sourceName) {
  return fetchHtml(playerUrl, baseHeaders(BASE)).then(function (html) {
    var scriptData = extractScripts(html);
    var fileMatches = [];
    var re = /file\s*:\s*['"]([^'",]+?)['"]/g;
    var m;
    while ((m = re.exec(scriptData))) fileMatches.push(m[1]);
    var raw = fileMatches.filter(function (f) { return f.indexOf('.m3u8') !== -1; })[0] || fileMatches[0];
    if (!raw) return null;
    var streamUrl = resolveStreamUrl(raw);
    if (!streamUrl) return null;
    var refererHost = (/^https?:\/\/[^/]+/.exec(playerUrl) || [BASE])[0] + '/';
    return {
      name: sourceName || 'Uakino',
      title: 'Uakino ' + guessQuality(streamUrl),
      url: streamUrl,
      quality: guessQuality(streamUrl),
      headers: { Referer: refererHost }
    };
  });
}

// --- Movie flow: detail page -> iframe#pre --------------------------------

function resolveMovie(detailUrl) {
  return fetchHtml(detailUrl, baseHeaders()).then(function (html) {
    var m = /id=["']pre["'][\s\S]{0,200}?<iframe[^>]+src="([^"]+)"/.exec(html) ||
      /<iframe[^>]+id=["']pre["'][^>]+src="([^"]+)"/.exec(html);
    if (!m) return [];
    return extractPlayerStream(normalizePlayerUrl(m[1]), 'Uakino').then(function (s) { return s ? [s] : []; });
  });
}

// --- TV flow: multi-season nav -> playlists ajax -> episode li -----------

function findNewsId(html, url) {
  var m = /class="[^"]*playlists-ajax[^"]*"[^>]*data-news_id="([^"]+)"/.exec(html);
  if (m) return m[1];
  var slug = url.split('/').filter(Boolean).pop() || '';
  return slug.split('-')[0];
}

function pickSeasonPage(html, season) {
  var results = [];
  var re2 = /class="seasons"[\s\S]*?<\/ul>/;
  var block = (re2.exec(html) || [html])[0];
  var anchorRe = /<a[^>]+href="([^"]+)"[^>]*>([^<]*)<\/a>/g;
  var m;
  while ((m = anchorRe.exec(block))) results.push({ href: m[1], label: m[2] });
  if (!results.length) return null;
  var match = results.filter(function (r) {
    var n = (/\d+/.exec(r.label) || [])[0];
    return n && parseInt(n, 10) === season;
  })[0];
  return match ? match.href : (season === 1 ? null : undefined);
}

function fetchEpisodeList(newsId) {
  var url = BASE + '/engine/ajax/playlists.php?news_id=' + newsId + '&xfield=playlist&time=' + Date.now();
  return fetch(url, { headers: ajaxHeaders() }).then(function (r) { return r.json(); }).catch(function () { return null; });
}

function parseEpisodeItems(html) {
  var items = [];
  var re = /<li[^>]*data-file="([^"]*)"[^>]*(?:data-voice="([^"]*)")?[^>]*>([^<]*)<\/li>/g;
  var m;
  while ((m = re.exec(html))) {
    items.push({ file: m[1], voice: m[2] || '', label: (m[3] || '').trim() });
  }
  // data-voice may appear before data-file depending on markup order; retry the other order too.
  if (!items.length) {
    re = /<li[^>]*data-voice="([^"]*)"[^>]*data-file="([^"]*)"[^>]*>([^<]*)<\/li>/g;
    while ((m = re.exec(html))) items.push({ file: m[2], voice: m[1] || '', label: (m[3] || '').trim() });
  }
  return items;
}

function resolveTv(detailUrl, season, episode) {
  return fetchHtml(detailUrl, baseHeaders()).then(function (html) {
    var seasonHref = pickSeasonPage(html, season);
    if (seasonHref === undefined) return []; // season list exists but requested season wasn't found
    if (seasonHref && seasonHref !== detailUrl) {
      return fetchHtml(seasonHref, baseHeaders()).then(function (seasonHtml) {
        return loadEpisodesFor(seasonHref, seasonHtml, episode);
      });
    }
    return loadEpisodesFor(detailUrl, html, episode);
  });
}

function loadEpisodesFor(pageUrl, html, episode) {
  var newsId = findNewsId(html, pageUrl);
  if (!newsId) return [];
  return fetchEpisodeList(newsId).then(function (data) {
    if (!data || !data.success) return [];
    var items = parseEpisodeItems(String(data.response || ''));
    var target = items.filter(function (it) {
      var n = (/\d+/.exec(it.label) || [])[0];
      return n && parseInt(n, 10) === episode;
    });
    if (!target.length) return [];
    return Promise.all(target.map(function (it) {
      var playerUrl = normalizePlayerUrl(it.file.trim());
      return extractPlayerStream(playerUrl, it.voice || 'Uakino');
    })).then(function (streams) { return streams.filter(Boolean); });
  });
}

// --- Entry point -----------------------------------------------------------

function getStreams(tmdbId, mediaType, season, episode) {
  return getTmdbInfo(tmdbId, mediaType).then(function (info) {
    if (!info.title) return [];
    return searchUakino(info.title).then(function (results) {
      if (results.length || !info.originalTitle || info.originalTitle === info.title) return results;
      return searchUakino(info.originalTitle);
    }).then(function (results) {
      var match = pickBestMatch(results, info);
      if (!match) return [];
      if (mediaType !== 'tv' || !season || !episode) return resolveMovie(match.href);
      return resolveTv(match.href, season, episode);
    });
  }).catch(function () {
    return [];
  });
}

module.exports = { getStreams: getStreams };
