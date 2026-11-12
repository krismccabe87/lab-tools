# -*- coding: utf-8 -*-
import json
from pathlib import Path

SRC = Path(__file__).resolve().parent
OUT = SRC.parent / 'index.html'

with open(SRC / 'watchlist.json', encoding='utf-8') as f:
    WATCHLIST = json.load(f)
with open(SRC / 'owasp.json', encoding='utf-8') as f:
    OWASP = json.load(f)
with open(SRC / 'kev-ai.json', encoding='utf-8') as f:
    KEV = json.load(f)

WATCHLIST_JS = json.dumps(WATCHLIST, indent=2)
OWASP_JS = json.dumps(OWASP, indent=2)
KEV_JS = json.dumps(KEV, indent=2)

HEAD = '''<!DOCTYPE html>
<html lang="en-GB">
<head>
<!-- Apply a stored theme choice before first paint, so there's no flash
     of the wrong theme while lab-theme.js is still loading. -->
<script>
(function(){try{var t=localStorage.getItem('lab-theme');if(t==='light'||t==='dark'){document.documentElement.setAttribute('data-theme',t);}}catch(e){}})();
</script>
<!-- Google Analytics - only loads after cookie consent, see banner script below -->
<script>
  window.dataLayer = window.dataLayer || [];
  function gtag(){dataLayer.push(arguments);}
  function loadGoogleAnalytics(){
    var s = document.createElement('script');
    s.async = true;
    s.src = 'https://www.googletagmanager.com/gtag/js?id=G-QE309XG3DJ';
    document.head.appendChild(s);
    gtag('js', new Date());
    gtag('config', 'G-QE309XG3DJ');
  }
</script>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Flare &mdash; AI Stack Exposure Checker | Kris McCabe</title>
<link rel="icon" href="/favicon.ico" sizes="any">
<link rel="icon" href="/favicon-32.png" type="image/png" sizes="32x32">
<link rel="icon" href="/favicon-16.png" type="image/png" sizes="16x16">
<link rel="apple-touch-icon" href="/apple-touch-icon.png">
<meta name="description" content="Pick the AI libraries you actually use and see what's currently live, high-severity, and worth patching this week &mdash; plus the OWASP LLM Top 10 as a permanent, plain-English reference." />
<meta property="og:type" content="website">
<meta property="og:site_name" content="Kris's Lab">
<meta property="og:title" content="Flare &mdash; AI Stack Exposure Checker">
<meta property="og:description" content="Pick the AI libraries you actually use and see what's currently live, high-severity, and worth patching this week.">
<meta property="og:url" content="https://lab.krismccabe.com/flare/">
<meta property="og:image" content="https://lab.krismccabe.com/og-image.png">
<meta property="og:image:width" content="1200">
<meta property="og:image:height" content="630">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="Flare &mdash; AI Stack Exposure Checker">
<meta name="twitter:description" content="Pick the AI libraries you actually use and see what's currently live, high-severity, and worth patching this week.">
<meta name="twitter:image" content="https://lab.krismccabe.com/og-image.png">
<link rel="stylesheet" href="/assets/lab.css?v=6">
<script src="/assets/lab-theme.js?v=1" defer></script>
'''

with open(SRC / 'style.css', encoding='utf-8') as f:
    STYLE = f.read()

JSONLD = '''<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "SoftwareApplication",
  "name": "Flare \\u2014 AI Stack Exposure Checker",
  "description": "Pick the AI libraries you actually use and see what's currently live, high-severity, and worth patching this week, plus the OWASP LLM Top 10 as a permanent reference.",
  "url": "https://lab.krismccabe.com/flare/",
  "applicationCategory": "SecurityApplication",
  "operatingSystem": "Any (runs in browser)",
  "isAccessibleForFree": true,
  "offers": { "@type": "Offer", "price": "0", "priceCurrency": "USD" },
  "author": { "@type": "Person", "name": "Kris McCabe", "url": "https://krismccabe.com/" }
}
</script>
'''

with open(SRC / 'body.html', encoding='utf-8') as f:
    BODY = f.read()

with open(SRC / 'script.js', encoding='utf-8') as f:
    SCRIPT = f.read()

SCRIPT = SCRIPT.replace('__WATCHLIST_JSON__', WATCHLIST_JS)
SCRIPT = SCRIPT.replace('__OWASP_JSON__', OWASP_JS)
SCRIPT = SCRIPT.replace('__KEV_JSON__', KEV_JS)

FINAL = HEAD + '<style>\n' + STYLE + '\n</style>\n' + JSONLD + '</head>\n<body>\n' + BODY + '\n<script>\n' + SCRIPT + '\n</script>\n</body>\n</html>\n'

with open(OUT, 'w', encoding='utf-8') as f:
    f.write(FINAL)
print('wrote', OUT, len(FINAL), 'chars')
