---
name: adtech-radar
description: >
  Fetches a webpage and analyzes all JavaScript sources to identify adtech, tracking,
  and data-collection scripts. Use this skill whenever the user wants to audit a website
  for trackers, ads, or privacy risks — even if they phrase it as "check this site for
  trackers", "what scripts does X load", "is this site safe", "analyze the JS on this
  page", or "what domains should I block on this site". Also trigger when the user shares
  a URL and asks anything privacy-related about it.
---

# Adtech & Tracker Analyzer

Audits a public webpage's JavaScript sources and identifies tracking, advertising, analytics,
and data-collection scripts. Produces a categorised breakdown and a concrete block list for
DNS blockers (dot-block, Pi-hole, NextDNS) or uBlock Origin.

---

## Workflow

### Step 1 — Fetch the page HTML

Use `curl` to retrieve the raw HTML of the target URL. Set a realistic User-Agent header to
avoid bot protection. If the fetch fails (e.g. due to an auth wall, bot protection, or
Cloudflare), inform the user and suggest they paste the page's HTML directly or use browser
devtools to copy it.

### Step 2 — Extract script sources

Parse the HTML for:

- **External scripts**: all `<script src="...">` tags → collect the `src` attribute values
- **Inline scripts**: all `<script>` blocks without a `src` → collect the first 400 chars of each

Resolve relative URLs against the page's origin so every src is a full URL.

Deduplicate. Note the page origin (hostname) to distinguish first-party from third-party.

### Step 3 — Fetch and sample script content

For each third-party script, decide the fetch strategy based on the domain:

#### 3a — Opaque CDN domains (ALWAYS fetch)

These domains are used to deliberately obscure the true origin of a script. The domain
name alone tells you nothing — you **must** fetch the content and fingerprint it:

- `*.cloudfront.net` — Amazon CloudFront (random subdomain per distribution)
- `*.fastly.net` — Fastly CDN
- `*.akamaihd.net`, `*.akamaiapis.net` — Akamai
- `*.edgekey.net`, `*.edgesuite.net` — Akamai edge nodes
- `*.azureedge.net` — Azure CDN
- `*.storage.googleapis.com` — Google Cloud Storage
- Any URL where the subdomain is 8+ random-looking alphanumeric characters

For these, fetch the script and run **content fingerprinting** (see Step 3b).
Cap at the first 3 000 characters — vendor fingerprints almost always appear near the top.
If the fetch fails, mark as `unknown` and note the opaque CDN in the report.

#### 3b — Content fingerprinting

Scan the fetched content for these patterns to identify the real vendor:

| Fingerprint string / pattern | Vendor | Category |
|---|---|---|
| `hotjar`, `hjid`, `_hjSettings` | Hotjar | analytics |
| `FullStory`, `_fs_namespace`, `window['_fs_` | FullStory | analytics |
| `mixpanel`, `__mp_opt_in_out` | Mixpanel | analytics |
| `amplitude`, `AmplitudeClient` | Amplitude | analytics |
| `analytics.js`, `ga(`, `gtag(`, `UA-`, `G-` | Google Analytics | analytics |
| `GTM-`, `googletagmanager` | Google Tag Manager | analytics |
| `clarity`, `window.clarity` | Microsoft Clarity | analytics |
| `segment`, `analytics.track`, `analytics.identify` | Segment | analytics |
| `heap`, `window.heap`, `heap.track` | Heap | analytics |
| `fbq(`, `_fbq`, `facebook pixel`, `connect.facebook` | Meta Pixel | adtech |
| `twq(`, `twitter pixel`, `ads-twitter` | Twitter/X Ads | adtech |
| `lintrk(`, `linkedin insight` | LinkedIn Insight | adtech |
| `snaptr(`, `snap pixel` | Snapchat Pixel | adtech |
| `criteo`, `CriteoQ` | Criteo | adtech |
| `ttq.`, `tiktok pixel`, `TiktokAnalyticsObject` | TikTok Pixel | adtech |
| `uetq`, `bat.bing.com`, `microsoft advertising` | Microsoft Ads | adtech |
| `_tfa`, `tfa.js`, `teads` | Teads | adtech |
| `OneTrust`, `OptanonWrapper` | OneTrust CMP | consent |
| `Cookiebot`, `CookieConsent` | Cookiebot CMP | consent |
| `TrustArc`, `truste.com` | TrustArc CMP | consent |
| `FingerprintJS`, `fpjs`, `visitorId` | FingerprintJS | tracking |
| `iovation`, `io_bb` | iovation | tracking |
| `eval(decodeURIComponent(escape(window.atob(`, `/loader.min.js`, `asload()` | Ad-Shield (anti-adblock) | adtech |
| `xhr.open`, `fetch(`, `navigator.sendBeacon` | Data exfil endpoint — check destination URL | varies |

When you find a match, also extract the **beacon/API endpoint URL** the script phones
home to (look for `fetch(`, `XHR.open`, `sendBeacon(`, or hardcoded domain strings).
Add that domain to the block list in addition to the CloudFront distribution URL.

#### 3c — Known domains (fetch only if content would add clarity)

For scripts on well-known domains already in the **Known Patterns** list, fetching
content is optional — skip it if there are more than 10 such scripts and the URL is
already conclusive.

### Step 4 — Categorise each script

Assign one of these categories:

| Category | Definition |
|---|---|
| `adtech` | Advertising networks, programmatic ad serving, retargeting pixels |
| `analytics` | Behavioural analytics, session recording, heatmaps, A/B testing |
| `tracking` | Cross-site tracking pixels, fingerprinting, identity resolution |
| `cdn` | Pure delivery infrastructure — no data collection (e.g. jsDelivr, cdnjs, Cloudflare) |
| `firstparty` | The site's own application code |
| `unknown` | Cannot determine purpose |

Use the heuristics in the **Known Patterns** section below, plus any content sampled in Step 3.

### Step 5 — Produce the report

Output a structured report with these sections:

#### 5a. Summary

One paragraph of plain English: overall privacy risk (Low / Medium / High / Very High),
what types of scripts dominate, and any standout concerns.

#### 5b. Script breakdown table

| Script URL | Domain | Category | Name | Should block? | Notes |
|---|---|---|---|---|---|
| https://... | googletagmanager.com | analytics | Google Tag Manager | ⚠️ Yes | Loads further dynamic scripts; acts as a tag container |

Keep notes concise (≤ 15 words). Use ✅ No / ⚠️ Yes for the block recommendation.

#### 5c. Block list

A clean list of domains to add to a DNS blocker or uBlock Origin:

```
# Adtech
doubleclick.net          # Google display ads
adservice.google.com     # Google ad serving

# Analytics / tracking
hotjar.com               # Session recording
```

Group by category. Include a one-line comment explaining each domain.

#### 5d. Safe domains

List CDN and first-party domains that are safe and should NOT be blocked, so the user
doesn't accidentally break the site.

---

## Known Patterns

Use these to identify scripts without needing to fetch content.

### Adtech
- `doubleclick.net`, `googlesyndication.com`, `adservice.google.com` → Google Ads
- `ads.twitter.com`, `static.ads-twitter.com` → Twitter/X Ads
- `connect.facebook.net` → Meta Pixel
- `snap.licdn.com` → LinkedIn Insight Tag
- `sc-static.net` → Snapchat Pixel
- `amazon-adsystem.com` → Amazon Ads
- `criteo.net`, `criteo.com` → Criteo retargeting
- `adsrvr.org` → The Trade Desk
- `rubiconproject.com`, `pubmatic.com`, `openx.net` → Programmatic SSPs
- `taboola.com`, `outbrain.com` → Content recommendation / native ads

### Analytics & tracking
- `google-analytics.com`, `googletagmanager.com` → Google Analytics / GTM
- `hotjar.com` → Session recording + heatmaps
- `fullstory.com` → Session recording
- `mixpanel.com` → Product analytics
- `segment.com`, `segment.io` → Data pipeline (sends to many downstream tools)
- `amplitude.com` → Product analytics
- `heap.io` → Autocapture analytics
- `clarity.ms` → Microsoft Clarity (session recording)
- `mouseflow.com` → Session recording
- `optimizely.com`, `ab.tasty.com` → A/B testing
- `intercom.io` → Customer messaging + tracking

### Fingerprinting / identity
- `iovation.com`, `threatmetrix.com` → Device fingerprinting
- `fingerprintjs.com` → Browser fingerprinting

### Anti-adblock / ad reinsertion (Ad-Shield)

Ad-Shield is a Korean adtech company specialising in circumventing ad blockers. Its
scripts are **actively adversarial**: they use heavily obfuscated WASM, strip a page's
CSS, and display a fake error blaming the user's adblocker if their loader domain is
blocked. The error dialog routes through `error-report.com`.

**Detection — inline script bootstrap**: Look for an inline `<script>` containing
`eval(decodeURIComponent(escape(window.atob("KCgpPT...` — this is the Ad-Shield
bootstrap that loads `/loader.min.js` from one of their domains.

**Known Ad-Shield domains** (block ALL of these):
- `html-load.com`, `html-load.cc`
- `css-load.com`
- `js-load.com`
- `content-load.com`
- `content-loader.com`
- `07c225f3.online`
- `error-report.com` (fake error / gaslighting page)

**Regex pattern** for uBlock Origin / AdGuard (catches new domains following the same
naming scheme):
```
^(.+\.)?(html|js|css|content)-(load|loader)\.[a-z0-9-]+$
```

**Blocking strategy — IMPORTANT**: Unlike most adtech, DNS-level blocking of Ad-Shield
domains causes deliberate site breakage (they strip CSS and show a lockout dialog).
Prefer browser-level blocking:
1. **uBlock Origin** or **Brave** — both defeat Ad-Shield's techniques including the
   lockout script, without breaking the page layout
2. **microShield userscript** (`github.com/List-KR/microShield`) — a dedicated defuser
   that neutralises Ad-Shield without breaking sites; recommended for sites you visit
   regularly that deploy it
3. DNS blocking (Pi-hole / NextDNS) — blocks ads but will also break affected pages;
   only use if you are willing to whitelist per-site

Always flag Ad-Shield as **Very High** risk regardless of other scripts present — it is
intentionally deceptive and actively works against user agency.

### CDN / safe utilities
- `cdnjs.cloudflare.com`, `cdn.jsdelivr.net`, `unpkg.com` → Pure CDN
- `fonts.googleapis.com`, `fonts.gstatic.com` → Google Fonts (no tracking)
- `ajax.googleapis.com` → jQuery/AJAX CDN

---

## Risk Levels

| Risk | Criteria |
|---|---|
| **Low** | Only first-party and CDN scripts |
| **Medium** | Basic analytics (e.g. GA4 only) |
| **High** | Multiple adtech or tracking vendors |
| **Very High** | Cross-site identity resolution, fingerprinting, or 5+ adtech vendors |

---

## Output Format

Always produce all four sections (Summary, Script Breakdown, Block List, Safe Domains)
even if some are empty. Use markdown formatting. Keep the tone factual and non-alarmist —
explain what each script *does*, not just that it's "bad".

---

## Edge Cases

- **Dynamically injected scripts**: GTM and similar tag managers inject further scripts
  at runtime. Note this explicitly in the report — static analysis alone cannot reveal
  all scripts a page loads.
- **Opaque CDN subdomains** (`*.cloudfront.net` etc.): Always fetch and fingerprint —
  see Step 3a. Never mark these as `unknown` without attempting a content fetch first.
  Report both the CloudFront URL *and* the real vendor name/beacon domain in the block list.
- **First-party proxying**: Some sites serve third-party scripts through their own domain
  (e.g. `cdn.example.com/track.js` is really Hotjar). If content fingerprinting reveals
  a known vendor, flag it as that vendor even though the URL looks first-party. Note it
  explicitly — DNS blocking alone won't help in this case.
- **Consent managers**: CMP scripts (OneTrust, Cookiebot, TrustArc) are not themselves
  trackers but enable tracking. Note their presence.
- **No external scripts found**: Report this as Low risk, and note that dynamic injection
  may still occur.
- **Fetch blocked**: If `web_fetch` is blocked, ask the user to paste the page source
  or provide a `curl` dump.
- **Ad-Shield lockout dialog**: If the page displays an error saying it "could not be
  loaded properly" and references `report.error-report.com`, it is an Ad-Shield
  anti-adblock lockout — not a genuine error. Flag this explicitly in the report summary
  and recommend the microShield userscript rather than DNS blocking.
