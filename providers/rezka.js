// Nuvio provider: HDRezka (rezka.ag and other mirrors sharing the same backend)
//
// Built from scratch against real captured traffic (HAR), not ported from a CloudStream
// Kotlin source - CakesTwix's repo has no Rezka provider. Confirmed live on rezka.ag:
//  - search.php / the film-or-series page / get_cdn_series all responded with zero
//    Cloudflare/Anubis challenge and no auth/cookies required.
//  - Stream URLs come back as plain, unobfuscated "[quality]url or url2 or url3,[quality]..."
//    text - no base64/XOR/AES step needed on this domain (unlike some older Rezka forks).
//  - "premium" qualities (1080p Ultra, 4K) and even translators the site itself flags
//    premium_content:1 still come back with fully working URLs in the same unauthenticated
//    response - the premium lock on rezka.ag is UI-only, not enforced server-side.
//  - Per-translator season availability (e.g. an unofficial dub only covering season 2) is
//    reported by the server itself via action=get_episodes's "seasons" field - not guessed.
//
// Multiple domains, one file: DOMAINS below is tried in order, and whichever one returns a
// real (non-challenge) response to the search call is reused for the rest of that lookup.
// Only rezka.ag has actually been verified end-to-end here - add further mirrors to DOMAINS
// only after confirming (via a fresh HAR) they share the same markup/AJAX contract, since a
// differently-built mirror could pass the "not blocked" check yet fail every later step.
//
// Written as plain Promise chains (no async/await) since the Hermes plugin runtime does not
// run async/await in dynamically loaded providers.

var TMDB_API_KEY = '439c478a771f35c05022f9feabcca01c'; // shared community demo key; swap for your own free key from themoviedb.org if you get rate-limited
var DOMAINS = ['rezka.ag'];
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

// Anubis (proof-of-work anti-bot) and Cloudflare interstitials both answer with HTTP 200, so a
// status check alone can't tell a live domain from a challenged one - the body has to be sniffed.
function looksBlocked(text) {
  if (!text) return true;
  var head = text.slice(0, 2000).toLowerCase();
  return head.indexOf('anubis') !== -1 ||
    head.indexOf('checking your browser') !== -1 ||
    head.indexOf('cf-browser-verification') !== -1 ||
    head.indexOf('attention required') !== -1;
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
// Confirmed markup: <li><a href="URL"><span class="enty">Title</span> (OrigTitle, Year)
// <span class="rating">...</span></a></li>

function parseSearchResults(html) {
  var out = [];
  var re = /<li><a href="([^"]+)"><span class="enty">([^<]*)<\/span>\s*\(([^)]*)\)/g;
  var m;
  while ((m = re.exec(html))) {
    var paren = m[3];
    var yearMatch = /(\d{4})\s*$/.exec(paren);
    var year = yearMatch ? parseInt(yearMatch[1], 10) : null;
    var origTitle = yearMatch ? paren.slice(0, yearMatch.index).replace(/,\s*$/, '').trim() : paren.trim();
    out.push({ href: m[1], title: m[2].trim(), origTitle: origTitle, year: year });
  }
  return out;
}

function searchOnDomain(domain, query) {
  return fetchWithTimeout('https://' + domain + '/engine/ajax/search.php', {
    method: 'POST',
    headers: ajaxHeaders(domain),
    body: 'q=' + encodeURIComponent(query)
  }, 8000).then(function (r) { return r.text(); }).then(function (text) {
    if (looksBlocked(text)) throw new Error('blocked');
    return parseSearchResults(text);
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
// Confirmed markup: <li title="Name" class="b-translator__item ..." data-id="N"
// data-translator_id="T" ...>Name</li>. Attribute text is extracted whole first and the two
// data- attributes pulled out of it independently, the same attribute-order-agnostic pattern
// used elsewhere in this repo (uakino.js had a real bug from assuming a fixed attribute order).

function parseTranslators(html) {
  var out = [];
  var re = /<li([^>]*)>([^<]*)<\/li>/g;
  var m;
  while ((m = re.exec(html))) {
    var attrs = m[1];
    if (attrs.indexOf('b-translator__item') === -1) continue;
    var idMatch = /data-id="([^"]*)"/.exec(attrs);
    var tidMatch = /data-translator_id="([^"]*)"/.exec(attrs);
    if (!idMatch || !tidMatch || !idMatch[1] || !tidMatch[1]) continue;
    out.push({ id: idMatch[1], translatorId: tidMatch[1], label: (m[2] || '').trim() || 'Rezka' });
  }
  return out;
}

function resolveContentPage(domain, url) {
  return fetchWithTimeout(url, { headers: baseHeaders(domain) }, 10000)
    .then(function (r) { return r.text(); })
    .then(function (html) {
      var favsMatch = /<input[^>]+id="ctrl_favs"[^>]+value="([^"]*)"/.exec(html);
      return { translators: parseTranslators(html), favs: favsMatch ? favsMatch[1] : '' };
    });
}

// --- get_cdn_series calls ---------------------------------------------------

function postForm(domain, params) {
  var body = Object.keys(params).map(function (k) {
    return k + '=' + encodeURIComponent(params[k]);
  }).join('&');
  return fetchWithTimeout('https://' + domain + '/ajax/get_cdn_series/?t=' + Date.now(), {
    method: 'POST',
    headers: ajaxHeaders(domain),
    body: body
  }, 10000).then(function (r) { return r.text(); }).then(function (text) {
    var data;
    try { data = JSON.parse(text); } catch (e) { return null; }
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
      id: t.id, translator_id: t.translatorId, is_camrip: '0', is_ads: '0', is_director: '0',
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
