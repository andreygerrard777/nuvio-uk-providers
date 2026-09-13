// Nuvio provider: UAFlix (uafix.net)
// Hand-ported from the CloudStream Kotlin provider UAFlixProvider.kt / UAFlixParsing.kt
// (https://github.com/CakesTwix/cloudstream-extensions-uk). All CSS-selector-equivalent
// regexes below were checked against live HTML pulled from uafix.net at port time.
//
// Nuvio only gives us a TMDB id, not a title, so this provider first resolves the TMDB id
// to a title via the TMDB API, then runs it through UAFlix's own site search and picks the
// best textual match. That matching step is inherently best-effort for a non-English catalog.
//
// Written as plain Promise chains (no async/await) since the Hermes plugin runtime does not
// run async/await in dynamically loaded providers.

var TMDB_API_KEY = '439c478a771f35c05022f9feabcca01c'; // shared community demo key; swap for your own free key from themoviedb.org if you get rate-limited
var BASE = 'https://uafix.net';
var UA = 'Mozilla/5.0 (Linux; Android 15; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Mobile Safari/537.36';
var PLAYER_REFERER = 'https://tortuga.wtf/';

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

function pad2(n) {
  n = String(n);
  return n.length < 2 ? '0' + n : n;
}

function guessQuality(url) {
  var m = /([0-9]{3,4})p/.exec(url || '');
  return m ? m[1] + 'p' : '1080p';
}

// --- TMDB lookup -----------------------------------------------------------

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
// Result markup (confirmed live):
// <a class="sres-wrap clearfix" href="URL"><div class="sres-img">...</div>
// <div class="sres-text"><h2>Ukr Title / Eng Title</h2>...

function parseSearchResults(html) {
  var results = [];
  var re = /<a class="sres-wrap[^"]*" href="([^"]+)">[\s\S]*?<h2>([^<]*)<\/h2>/g;
  var m;
  while ((m = re.exec(html))) {
    results.push({ href: m[1], title: m[2].trim() });
  }
  return results;
}

function searchUAFlix(query) {
  var url = BASE + '/index.php?do=search&subaction=search&search_start=0&story=' + encodeURIComponent(query);
  return fetchHtml(url).then(parseSearchResults);
}

function pickBestMatch(results, tmdbInfo) {
  var best = null;
  var bestScore = 0;
  results.forEach(function (r) {
    var parts = r.title.split('/').map(function (s) { return s.trim(); });
    var score = 0;
    parts.forEach(function (p) {
      score = Math.max(score, tokenScore(p, tmdbInfo.title), tokenScore(p, tmdbInfo.originalTitle));
    });
    if (score > bestScore) {
      bestScore = score;
      best = r;
    }
  });
  return bestScore >= 0.4 ? best : null;
}

// --- Player resolution -------------------------------------------------
// Every movie/episode page has:
// <div class="tabs-b video-box" id="playnd"><iframe src="PLAYER_URL"></iframe></div>
// PLAYER_URL is usually https://zetvideo.net/vod/<id>, whose page embeds:
//   file:"https://.../index.m3u8", subtitle:"[Lang]https://.../sub.vtt,"
// Some shows instead embed one big JSON blob directly (dubs -> seasons -> episodes).

function extractPlaynd(html) {
  var m = /id="playnd"[\s\S]{0,120}?<iframe[^>]+src="([^"]+)"/.exec(html);
  return m ? m[1] : null;
}

function resolveVodStream(vodUrl) {
  return fetchHtml(vodUrl, { headers: { Referer: BASE + '/' } }).then(function (html) {
    var fileMatch = /file\s*:\s*['"]([^'"]+)['"]/.exec(html);
    if (!fileMatch) return null;
    var streamUrl = fileMatch[1];
    return {
      name: 'UAFlix',
      title: 'UAFlix ' + guessQuality(streamUrl),
      url: streamUrl,
      quality: guessQuality(streamUrl),
      headers: { Referer: PLAYER_REFERER }
    };
  });
}

function resolveJsonPlayer(playerUrl, season, episode) {
  return fetchHtml(playerUrl, { headers: { Referer: BASE } }).then(function (html) {
    var fileMatch = /file\s*:\s*['"]([\s\S]*?)['"]\s*[,}]/.exec(html);
    if (!fileMatch) return [];
    var dubs;
    try { dubs = JSON.parse(fileMatch[1]); } catch (e) { return []; }
    var streams = [];
    dubs.forEach(function (dub) {
      (dub.folder || []).forEach(function (s) {
        var sNum = (/\d+/.exec(s.title) || [])[0];
        var ep = null;
        if (season == null) {
          ep = s.folder && s.folder[0];
        } else if (String(parseInt(sNum, 10)) === String(season)) {
          (s.folder || []).forEach(function (e) {
            var eNum = (/\d+/.exec(e.title) || [])[0];
            if (episode == null || String(parseInt(eNum, 10)) === String(episode)) ep = e;
          });
        }
        if (ep && ep.file) {
          streams.push({
            name: 'UAFlix',
            title: 'UAFlix ' + dub.title,
            url: ep.file,
            quality: guessQuality(ep.file),
            headers: { Referer: PLAYER_REFERER }
          });
        }
      });
    });
    return streams;
  });
}

function resolvePlayer(playerUrl, season, episode) {
  if (playerUrl.indexOf('//') === 0) playerUrl = 'https:' + playerUrl;
  if (playerUrl.indexOf('/vod/') !== -1) {
    return resolveVodStream(playerUrl).then(function (s) { return s ? [s] : []; });
  }
  return resolveJsonPlayer(playerUrl, season, episode);
}

// --- Episode navigation --------------------------------------------------
// Episode pages follow the convention <show>/season-SS-episode-EE/ (confirmed live).

function resolveFromPage(pageUrl) {
  return fetchHtml(pageUrl).then(function (html) {
    var playerUrl = extractPlaynd(html);
    if (!playerUrl) return [];
    return resolvePlayer(playerUrl, null, null);
  });
}

function findEpisodeViaListing(showHref, season, episode, page) {
  page = page || 1;
  if (page > 15) return Promise.resolve([]);
  var pageUrl = page === 1 ? showHref : showHref.replace(/\/?$/, '/') + '?page=' + page;
  return fetchHtml(pageUrl).then(function (html) {
    var re = new RegExp('href="([^"]*season-0*' + season + '-episode-0*' + episode + '[^"]*)"');
    var m = re.exec(html);
    if (m) {
      return fetchHtml(m[1]).then(function (epHtml) {
        var playerUrl = extractPlaynd(epHtml);
        return playerUrl ? resolvePlayer(playerUrl, season, episode) : [];
      });
    }
    if (html.indexOf('video-item') === -1) return [];
    return findEpisodeViaListing(showHref, season, episode, page + 1);
  });
}

function resolveEpisode(showHref, season, episode) {
  var guessUrl = showHref.replace(/\/?$/, '/') + 'season-' + pad2(season) + '-episode-' + pad2(episode) + '/';
  return fetchHtml(guessUrl).then(function (html) {
    var playerUrl = extractPlaynd(html);
    if (playerUrl) return resolvePlayer(playerUrl, season, episode);
    return findEpisodeViaListing(showHref, season, episode).then(function (streams) {
      if (streams.length) return streams;
      return resolveFromPage(showHref).then(function (s) { return s; });
    });
  }).catch(function () {
    return findEpisodeViaListing(showHref, season, episode);
  });
}

// --- Entry point -----------------------------------------------------------

function getStreams(tmdbId, mediaType, season, episode) {
  return getTmdbInfo(tmdbId, mediaType).then(function (info) {
    if (!info.title) return [];
    return searchUAFlix(info.title).then(function (results) {
      if (results.length || !info.originalTitle || info.originalTitle === info.title) return results;
      return searchUAFlix(info.originalTitle);
    }).then(function (results) {
      var match = pickBestMatch(results, info);
      if (!match) return [];
      if (mediaType !== 'tv' || !season || !episode) return resolveFromPage(match.href);
      return resolveEpisode(match.href, season, episode);
    });
  }).catch(function () {
    return [];
  });
}

module.exports = { getStreams: getStreams };
