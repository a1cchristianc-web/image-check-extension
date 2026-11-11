// URL-based tracking heuristics. Runs BEFORE any download: if the URL looks like a tracker,
// the extension must not fetch it (the fetch itself would ping the tracker).
//
// The domain list is a small illustrative sample. For production, ship a maintained list such
// as EasyPrivacy or Disconnect and update it regularly.
const TRACKERS = [
  'doubleclick.net', 'google-analytics.com', 'googletagmanager.com', 'googlesyndication.com',
  'googleadservices.com', 'facebook.com/tr', 'facebook.net', 'px.ads.linkedin.com', 'bat.bing.com',
  'ads.twitter.com', 'analytics.twitter.com', 'analytics.tiktok.com', 'ct.pinterest.com',
  'tr.snapchat.com', 'pixel.wp.com', 'stats.wp.com', 'scorecardresearch.com', 'quantserve.com',
  'adsrvr.org', 'mathtag.com', 'criteo.com', 'criteo.net', 'hotjar.com', 'clarity.ms',
  'mixpanel.com', 'segment.io', 'amplitude.com', 'taboola.com', 'outbrain.com', 'demdex.net',
  'omtrdc.net', '2o7.net', 'agkn.com', 'bluekai.com', 'adnxs.com', 'pubmatic.com',
  'rubiconproject.com', 'openx.net', 'casalemedia.com', 'list-manage.com/track',
  'sendgrid.net/wf/open', 'mandrillapp.com/track', 'hs-analytics.net', 'analytics.yahoo.com',
];

const TRACKING_PARAM =
  /^(utm_[a-z]+|fbclid|gclid|dclid|msclkid|yclid|ttclid|twclid|igshid|mc_eid|mc_cid|_hsenc|_hsmi|vero_id|mkt_tok)$/i;
const ID_PARAM =
  /^(uid|user_?id|uuid|cid|eid|rid|sid|email|subscriber(_?id)?|recipient|contact_?id|customer_?id|tracking_?id|visitor(_?id)?|session(_?id)?|guid)$/i;
// Parameters that legitimately carry long opaque values (signatures, expiry, sizing).
const BENIGN_PARAM =
  /^(s|sig|signature|x-amz-.*|expires|e|policy|key-pair-id|h|hash|v|version|w|width|q|quality|url|src)$/i;
const HOST_HINT = /^(pixel|track|tracking|beacon|analytics|metrics|telemetry|stats|collect|trk|click|email)\d*\./;
const PATH_HINT =
  /(^|\/)(pixel|tracking?|trk|beacon|impressions?|collect)(\.[a-z]{2,4})?(\/|$)|\/open\.(gif|png)$/i;
const EMAIL_RE = /[A-Za-z0-9._%+-]+(?:@|%40)[A-Za-z0-9.-]+\.[A-Za-z]{2,}/;
const TWO_LEVEL = new Set(['co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'com.au', 'co.jp', 'com.br', 'co.in', 'com.cn', 'co.nz', 'co.za']);

function matchTracker(host, path, entry) {
  const [domain, prefix] = entry.split(/\/(.*)/s);
  const hostOk = host === domain || host.endsWith('.' + domain);
  return hostOk && (!prefix || path.startsWith('/' + prefix));
}

export function registrable(host) {
  if (/^[\d.]+$/.test(host) || host.includes(':')) return host;
  const l = host.split('.');
  if (l.length <= 2) return host;
  const last2 = l.slice(-2).join('.');
  return TWO_LEVEL.has(last2) ? l.slice(-3).join('.') : last2;
}

export function analyzeUrl(urlStr, pageUrl = '') {
  let u;
  try {
    u = new URL(urlStr);
  } catch {
    return [{ sev: 'info', text: 'Could not parse the image URL.' }];
  }
  if (u.protocol === 'data:') {
    return [{ sev: 'info', text: 'Image is embedded in the page (data: URL); no separate network request.' }];
  }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') {
    return [{ sev: 'info', text: `Unsupported URL type (${u.protocol}); only the page itself can read this image.` }];
  }

  const out = [];
  const host = u.hostname.toLowerCase();
  const known = TRACKERS.find((t) => matchTracker(host, u.pathname, t));
  let decoded = u.search;
  try { decoded = decodeURIComponent(u.search); } catch { /* keep raw */ }
  const emailHit = EMAIL_RE.test(decoded + ' ' + u.pathname);

  const trackParams = [];
  const idParams = [];
  for (const [k, v] of u.searchParams) {
    if (TRACKING_PARAM.test(k)) trackParams.push(k);
    else if (ID_PARAM.test(k) && v) idParams.push(k);
    else if (!BENIGN_PARAM.test(k) && /^[A-Za-z0-9_-]{20,}$/.test(v) && /\d/.test(v) && /[A-Za-z]/.test(v)) {
      idParams.push(k);
    }
  }
  const nameHint = HOST_HINT.test(host) || PATH_HINT.test(u.pathname);

  if (known) {
    out.push({
      sev: 'alert', skipFetch: true,
      text: `Served by a known tracking/advertising endpoint (${known}). Images from these exist to log views, not to show content.`,
    });
  }
  if (emailHit) {
    out.push({
      sev: 'alert', skipFetch: true,
      text: 'The image URL contains an email address, which ties this view to a specific person.',
    });
  }
  if (nameHint && (idParams.length || trackParams.length) && !known) {
    out.push({
      sev: 'alert', skipFetch: true,
      text: `Looks like a tracking pixel carrying identifiers (${[...trackParams, ...idParams].slice(0, 4).join(', ')}).`,
    });
  } else if (nameHint && !known) {
    out.push({ sev: 'warning', text: 'The URL looks like a tracking or analytics endpoint (name pattern only).' });
  } else if (idParams.length) {
    out.push({
      sev: 'warning',
      text: `The URL carries identifier-like parameters (${idParams.slice(0, 4).join(', ')}) that may single you out.`,
    });
  }
  if (trackParams.length && !(nameHint && !known)) {
    out.push({ sev: 'notice', text: `Campaign/click tracking parameters in the URL (${trackParams.slice(0, 4).join(', ')}).` });
  }

  try {
    const pageHost = new URL(pageUrl).hostname.toLowerCase();
    if (registrable(pageHost) !== registrable(host)) {
      out.push({ sev: 'info', text: `Hosted on a different site (${host}) than the page you are on.` });
    }
  } catch { /* no page URL */ }

  return out;
}
