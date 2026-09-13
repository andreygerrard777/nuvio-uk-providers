// Nuvio provider: KlonTV (klonua.com)
// Hand-ported from the CloudStream Kotlin provider KlonTVProvider.kt
// (https://github.com/CakesTwix/cloudstream-extensions-uk).
//
// Confirmed against real, live-fetched pages: the category-listing markup
// (.short-news__slide-item / .card-link__style) and the movie player chain
// (div.film-player iframe[data-src] -> ashdi.vip/vod/<id> -> file:'...m3u8').
// The search endpoint itself returned a Cloudflare WAF block from this
// environment on POST (a different, harsher block than a JS challenge) so the
// search-result markup below is inferred from the confirmed listing-page
// template, not directly captured - verify with a real device/HAR if search
// comes back empty.
//
// Nuvio only gives us a TMDB id, not a title, so this provider resolves the
// TMDB id to a title via the TMDB API, then runs it through KlonTV's own site
// search and picks the best textual match - inherently best-effort for a
// non-English catalog.
//
// Written as plain Promise chains (no async/await) since the Hermes plugin
// runtime does not run async/await in dynamically loaded providers.

var TMDB_API_KEY = '439c478a771f35c05022f9feabcca01c'; // shared community demo key; swap for your own free key from themoviedb.org if you get rate-limited
var BASE = 'https://klonua.com';
var UA = 'Mozilla/5.0 (Linux; Android 15; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Mobile Safari/537.36';
var PLAYER_REFERER = 'https://tortuga.wtf/';

function fetchHtml(url, opts) {
  opts = opts || {};
  var headers = { 'User-Agent': UA };
  for (var k in (opts.headers || {})) headers[k] = opts.headers[k];
  return fetch(url, { method: opts.method, headers: headers, body: opts.body }).then(function (r) { return r.text(); });
}

function stripTags(s) {
  return (s || '').replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();
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
// Anchors carry the title-link classes in either order relative to href, so
// the attributes are pulled out independently instead of assuming order
// (a lesson from a real bug found while porting Uakino).

function parseSearchResults(html) {
  var results = [];
  var re = /<a([^>]*)>([\s\S]*?)<\/a>/g;
  var m;
  while ((m = re.exec(html))) {
    var attrs = m[1];
    if (!/class="[^"]*(?:card-link__style|short-news__small-card__link)[^"]*"/.test(attrs)) continue;
    var hrefMatch = /href="([^"]+)"/.exec(attrs);
    if (!hrefMatch) continue;
    var title = stripTags(m[2]);
    if (title) results.push({ href: hrefMatch[1], title: title });
  }
  return results;
}

function searchKlonTV(query) {
  var body = 'do=search&subaction=search&story=' + encodeURIComponent(query).replace(/%20/g, '+');
  return fetchHtml(BASE + '/', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body
  }).then(parseSearchResults);
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

// --- Player resolution -------------------------------------------------
// A movie's player URL (data-src, e.g. ashdi.vip/vod/<id>?multivoice) resolves
// to a single `file:'...m3u8'` when the "?multivoice" query is stripped.
// With "?multivoice" kept, the same endpoint instead returns a JSON blob of
// dubs -> seasons -> episodes (used for TV). Confirmed live for the movie case.

function extractPlaynd(html) {
  var m = /class="[^"]*film-player[^"]*"[\s\S]{0,300}?<iframe[^>]+data-src="([^"]+)"/.exec(html);
  return m ? m[1] : null;
}

function extractScripts(html) {
  var out = [];
  var re = /<script[^>]*>([\s\S]*?)<\/script>/g;
  var m;
  while ((m = re.exec(html))) out.push(m[1]);
  return out.join('\n');
}

function resolveMovieStream(playerUrl) {
  var url = playerUrl.replace('?multivoice', '');
  return fetchHtml(url).then(function (html) {
    var m = /file\s*:\s*'([^']+)'/.exec(extractScripts(html));
    if (!m) return [];
    return [{
      name: 'KlonTV',
      title: 'KlonTV ' + guessQuality(m[1]),
      url: m[1],
      quality: guessQuality(m[1]),
      headers: { Referer: PLAYER_REFERER }
    }];
  });
}

function resolveTvStream(playerUrl, season, episode) {
  return fetchHtml(playerUrl).then(function (html) {
    var m = /file\s*:\s*'([\s\S]*?)'\s*,\s*\n?\s*poster/.exec(extractScripts(html)) ||
      /file\s*:\s*'(\[[\s\S]*?\])'/.exec(extractScripts(html));
    if (!m) return [];
    var dubs;
    try { dubs = JSON.parse(m[1]); } catch (e) { return []; }
    if (!Array.isArray(dubs)) return [];
    var streams = [];
    dubs.forEach(function (dub) {
      (dub.folder || []).forEach(function (s) {
        var sNum = (/\d+/.exec(s.title) || [])[0];
        if (!sNum || parseInt(sNum, 10) !== season) return;
        (s.folder || []).forEach(function (ep) {
          var eNum = (/\d+/.exec(ep.title) || [])[0];
          if (!eNum || parseInt(eNum, 10) !== episode) return;
          if (ep.file) {
            streams.push({
              name: 'KlonTV',
              title: 'KlonTV ' + dub.title,
              url: ep.file,
              quality: guessQuality(ep.file),
              headers: { Referer: PLAYER_REFERER }
            });
          }
        });
      });
    });
    return streams;
  });
}

// --- Entry point -----------------------------------------------------------

function getStreams(tmdbId, mediaType, season, episode) {
  return getTmdbInfo(tmdbId, mediaType).then(function (info) {
    if (!info.title) return [];
    return searchKlonTV(info.title).then(function (results) {
      if (results.length || !info.originalTitle || info.originalTitle === info.title) return results;
      return searchKlonTV(info.originalTitle);
    }).then(function (results) {
      var match = pickBestMatch(results, info);
      if (!match) return [];
      return fetchHtml(match.href).then(function (html) {
        var playerUrl = extractPlaynd(html);
        if (!playerUrl) return [];
        if (mediaType !== 'tv' || !season || !episode) return resolveMovieStream(playerUrl);
        return resolveTvStream(playerUrl, season, episode);
      });
    });
  }).catch(function () {
    return [];
  });
}

module.exports = { getStreams: getStreams };
