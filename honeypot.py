#!/usr/bin/env python3
"""
Web-based honeypot / tarpit for scraper agents (CYSE 610, Group 1).

Public face: "Greek History World", a small fan site of Greek mythology facts
(content lives in site_content.py, which must sit next to this file).

  /, /olympians, /heroes, /creatures, /myths, /about
                  Real, readable pages. Every page's header contains a link to
                  the trap hidden with display:none (invisible to humans and
                  screen readers, visible to scrapers that parse raw HTML).
  /robots.txt     Disallows /archive/. Polite crawlers never enter the trap.
  /sitemap.xml    Lists only the real pages, like a normal site.
  /archive/...    The infinite maze. Each URL deterministically generates its
                  own mythology "notes" page (Markov-chain text built from the
                  real articles) with 12 links to further maze pages.
  /static/style.css, /favicon.ico
                  Real assets. Browsers fetch them; most scrapers don't.
  /stats?key=...  JSON summary of visitors (key required when --stats-key set).
  anything else   Logged as a "probe" (vulnerability scanners) and 404'd.

Run locally (PyCharm): just run this file, then open http://127.0.0.1:8080
Requires:  pip install aiohttp
"""

import argparse
import asyncio
import hashlib
import html
import random
import sqlite3
import time
from collections import defaultdict

from aiohttp import web

import site_content as sc
from report import trap_metrics      # shared with report.py

LINKS_PER_PAGE = 12          # outgoing maze links per trap page
PARAGRAPHS_PER_PAGE = 4
MAX_TRAPPED = 200            # max simultaneous trap responses (protects host)
DB_PATH = "honeypot_log.db"
TRAP_ENTRY = "/archive/reader-notes-index?d=1"


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
def init_db(path):
    db = sqlite3.connect(path, check_same_thread=False)
    db.execute(
        """CREATE TABLE IF NOT EXISTS hits (
               ts REAL, ip TEXT, user_agent TEXT, path TEXT,
               kind TEXT, depth INTEGER, method TEXT, referer TEXT)"""
    )
    # Columns added later for trap timing. Added in place so an existing
    # log file from an older version keeps working (old rows get NULL).
    cols = {row[1] for row in db.execute("PRAGMA table_info(hits)")}
    if "duration" not in cols:
        # Seconds the trap page held the bot's connection.
        db.execute("ALTER TABLE hits ADD COLUMN duration REAL")
    if "completed" not in cols:
        # 1 = bot received the whole page, 0 = bot hung up early,
        # -1 = turned away with 503 because the trap was full.
        db.execute("ALTER TABLE hits ADD COLUMN completed INTEGER")
    db.commit()
    return db


def log_hit(app, request, kind, depth=0):
    # Only trust X-Forwarded-For behind our own reverse proxy (Caddy).
    # On a directly exposed server anyone can forge that header.
    if app["behind_proxy"]:
        ip = request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
    else:
        ip = request.remote or "?"
    cur = app["db"].execute(
        "INSERT INTO hits (ts, ip, user_agent, path, kind, depth, method, referer)"
        " VALUES (?,?,?,?,?,?,?,?)",
        (time.time(), ip or "?", request.headers.get("User-Agent", ""),
         request.path_qs[:2000], kind, depth, request.method,
         request.headers.get("Referer", "")[:500]),
    )
    app["db"].commit()
    return cur.lastrowid       # lets the trap fill in timing afterwards


def log_trap_end(app, rowid, started, completed):
    """Record how long a trap page held the bot, and whether it stayed."""
    app["db"].execute(
        "UPDATE hits SET duration = ?, completed = ? WHERE rowid = ?",
        (round(time.monotonic() - started, 3), completed, rowid),
    )
    app["db"].commit()


# ---------------------------------------------------------------------------
# Markov chain text generator (trained on the real articles)
# ---------------------------------------------------------------------------
class Markov:
    """Order-2 word Markov chain: picks each next word based on the previous
    two, so output sounds like the source text without copying it."""

    def __init__(self, sentences):
        self.chain = defaultdict(list)
        self.starts = []
        for words in sentences:
            if len(words) < 3:
                continue
            self.starts.append((words[0], words[1]))
            for a, b, c in zip(words, words[1:], words[2:]):
                self.chain[(a, b)].append(c)

    def sentence(self, rng, max_words=35):
        a, b = rng.choice(self.starts)
        out = [a, b]
        while len(out) < max_words and not out[-1].endswith((".", "?", "!")):
            nxt = self.chain.get((a, b))
            if not nxt:
                break
            c = rng.choice(nxt)
            out.append(c)
            a, b = b, c
        text = " ".join(out)
        return text if text.endswith((".", "?", "!")) else text + "."


MARKOV = Markov(sc.corpus_sentences())


# ---------------------------------------------------------------------------
# Page templates
# ---------------------------------------------------------------------------
NAV = [("/", "Home")] + [(p, label) for p, label, *_ in sc.REAL_PAGES] + [
    ("/about", "About")]


def page(title, body, canonical="", noindex=False):
    nav = " ".join(f'<a href="{p}">{label}</a>' for p, label in NAV)
    robots_meta = '<meta name="robots" content="noindex, nofollow">' if noindex else ""
    canon = f'<link rel="canonical" href="{canonical}">' if canonical else ""
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(title)} | {sc.SITE_NAME}</title>
<meta name="description" content="{sc.TAGLINE}.">
{robots_meta}{canon}
<link rel="stylesheet" href="/static/style.css">
<link rel="icon" href="/favicon.ico"></head>
<body>
<header><div class="wrap">
  <a class="brand" href="/">{sc.SITE_NAME}</a>
  <nav>{nav}</nav>
  <!-- Honeypot entry: hidden from humans and screen readers. -->
  <div style="display:none" aria-hidden="true">
    <a href="{TRAP_ENTRY}">Reader notes archive</a>
  </div>
</div></header>
<main class="wrap">
{body}
</main>
<footer><div class="wrap">&copy; 2026 {sc.SITE_NAME} &middot; A fan-made
reference to Greek myth and legend.</div></footer>
</body></html>"""


def base_url(request):
    dom = request.app["domain"]
    return f"https://{dom}" if dom else f"http://{request.host}"


def render_home(request):
    cards = "\n".join(
        f'<a class="card" href="{p}"><h3>{title}</h3><p>{html.escape(intro)}</p></a>'
        for p, _, title, intro, _ in sc.REAL_PAGES
    )
    # "Fact of the day" changes daily, like a real site would.
    day = int(time.time() // 86400)
    fact = sc.FACTS[day % len(sc.FACTS)]
    facts = "\n".join(f"<li>{html.escape(f)}</li>" for f in sc.FACTS[:6])
    body = f"""
<section class="hero"><h1>{sc.SITE_NAME}</h1><p>{sc.TAGLINE}.</p>
<p class="fotd"><strong>Fact of the day:</strong> {html.escape(fact)}</p></section>
<div class="cards">{cards}</div>
<h2>Did you know?</h2><ul class="facts">{facts}</ul>"""
    return page("Home", body, base_url(request) + "/")


def render_section(request, entry):
    p, _, title, intro, sections = entry
    parts = "\n".join(
        f"<h2>{html.escape(h)}</h2><p>{html.escape(t)}</p>" for h, t in sections
    )
    body = f"<h1>{title}</h1><p class='lead'>{html.escape(intro)}</p>{parts}"
    return page(title, body, base_url(request) + p)


def render_about(request):
    body = """<h1>About</h1>
<p>Greek History World is a small hobby site collecting the best-known stories
of Greek mythology in short, readable summaries. Most of the myths survive
through ancient writers such as Homer, Hesiod and Ovid, and many exist in
several versions; we usually give the most familiar one.</p>
<p>This site is maintained by a small group of students and enthusiasts.
Visits may be logged for research on web traffic.</p>"""
    return page("About", body, base_url(request) + "/about")


# ---------------------------------------------------------------------------
# Deterministic trap pages
# ---------------------------------------------------------------------------
def rng_for(path):
    """Seed a PRNG from the URL so each URL always yields the same page."""
    seed = int.from_bytes(hashlib.sha256(path.encode()).digest()[:8], "big")
    return random.Random(seed)


def make_title(rng):
    return rng.choice(sc.TITLE_TEMPLATES).format(
        name=rng.choice(sc.NAMES), place=rng.choice(sc.PLACES),
        thing=rng.choice(sc.THINGS).capitalize())


def make_slug(rng, title):
    tag = "".join(rng.choice("abcdefghjkmnpqrstuvwxyz23456789") for _ in range(4))
    words = [w.lower() for w in title.split() if len(w) > 3][:3]
    return "-".join(words + [tag])


def build_trap_page(path, depth):
    rng = rng_for(path)
    title = make_title(rng)
    paras = "\n".join(
        "<p>" + " ".join(MARKOV.sentence(rng) for _ in range(rng.randint(3, 6)))
        + "</p>"
        for _ in range(PARAGRAPHS_PER_PAGE)
    )
    links = []
    for _ in range(LINKS_PER_PAGE):
        t = make_title(rng)
        links.append(f'<li><a href="/archive/{make_slug(rng, t)}?d={depth + 1}">'
                     f"{html.escape(t)}</a></li>")
    body = (f"<p class='crumb'>Reader notes archive</p><h1>{html.escape(title)}</h1>"
            f"{paras}<h2>Related notes</h2><ul>{''.join(links)}</ul>")
    return page(title, body, noindex=True)


CSS = """
:root{--ink:#2b2118;--muted:#6b5d4f;--bg:#faf6ee;--card:#fff;--accent:#1f4e79;--line:#e3d9c6}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:17px/1.65 Georgia,'Times New Roman',serif}
.wrap{max-width:52rem;margin:0 auto;padding:0 1rem}
header{background:var(--accent);color:#fff;border-bottom:6px double #c9a227}
header .wrap{display:flex;flex-wrap:wrap;align-items:center;gap:.5rem 1.5rem;padding:.9rem 1rem}
.brand{color:#fff;font-size:1.35rem;font-weight:bold;text-decoration:none;letter-spacing:.03em}
nav a{color:#e8eef5;margin-right:1rem;text-decoration:none}
nav a:hover{text-decoration:underline}
main{padding:1.5rem 1rem 3rem}
h1{font-size:2rem;margin:.5rem 0}
h2{color:var(--accent);border-bottom:1px solid var(--line);padding-bottom:.2rem;margin-top:2rem}
a{color:var(--accent)}
.lead{font-size:1.1rem;color:var(--muted)}
.hero{text-align:center;padding:1rem 0}
.fotd{background:var(--card);border:1px solid var(--line);border-radius:6px;padding:.75rem 1rem}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(14rem,1fr));gap:1rem;margin-top:1rem}
.card{display:block;background:var(--card);border:1px solid var(--line);border-radius:6px;padding:1rem;color:inherit;text-decoration:none}
.card:hover{border-color:var(--accent)}
.card h3{margin:0 0 .4rem;color:var(--accent)}
.card p{margin:0;font-size:.95rem;color:var(--muted)}
.crumb{color:var(--muted);font-size:.9rem;margin:0}
footer{border-top:1px solid var(--line);color:var(--muted);font-size:.9rem;padding:1.5rem 0}
"""

# Simple Greek-key style favicon (SVG), counted as an "asset" request.
FAVICON = ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16">'
           '<rect width="16" height="16" fill="#1f4e79"/>'
           '<path d="M3 13V3h10v7H7V6h3" fill="none" stroke="#c9a227" '
           'stroke-width="2"/></svg>')


# ---------------------------------------------------------------------------
# Handlers
# ---------------------------------------------------------------------------
def html_response(text):
    return web.Response(text=text, content_type="text/html")


async def home(request):
    log_hit(request.app, request, "landing")
    return html_response(render_home(request))


def section_handler(entry):
    async def handler(request):
        log_hit(request.app, request, "real_page")
        return html_response(render_section(request, entry))
    return handler


async def about(request):
    log_hit(request.app, request, "real_page")
    return html_response(render_about(request))


async def robots(request):
    log_hit(request.app, request, "robots")
    text = (f"User-agent: *\nDisallow: /archive/\n\n"
            f"Sitemap: {base_url(request)}/sitemap.xml\n")
    return web.Response(text=text, content_type="text/plain")


async def sitemap(request):
    log_hit(request.app, request, "sitemap")
    base = base_url(request)
    paths = ["/"] + [p for p, *_ in sc.REAL_PAGES] + ["/about"]
    urls = "".join(f"<url><loc>{base}{p}</loc></url>" for p in paths)
    xml = ('<?xml version="1.0" encoding="UTF-8"?>'
           '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
           f"{urls}</urlset>")
    return web.Response(text=xml, content_type="application/xml")


async def css(request):
    log_hit(request.app, request, "asset")
    return web.Response(text=CSS, content_type="text/css",
                        headers={"Cache-Control": "public, max-age=3600"})


async def favicon(request):
    log_hit(request.app, request, "asset")
    return web.Response(text=FAVICON, content_type="image/svg+xml")


async def trap(request):
    """Serve a maze page, dripping it out slowly to waste the bot's time."""
    try:
        depth = int(request.query.get("d", "1"))
    except ValueError:
        depth = 1
    rowid = log_hit(request.app, request, "trap", depth)
    started = time.monotonic()   # stopwatch for this one page

    sem = request.app["sem"]
    if sem.locked():
        # Too many bots in the trap at once: answer cheaply instead of
        # letting the honeypot overload our own server.
        log_trap_end(request.app, rowid, started, -1)
        return web.Response(status=503, headers={"Retry-After": "120"})

    completed = 0
    async with sem:
        try:
            body = build_trap_page(request.path, depth).encode()
            drip = request.app["drip"]
            resp = web.StreamResponse(
                headers={"Content-Type": "text/html; charset=utf-8"})
            await resp.prepare(request)
            if drip <= 0:
                await resp.write(body)
            else:
                chunk = max(1, len(body) // 10)
                for i in range(0, len(body), chunk):
                    await resp.write(body[i:i + chunk])
                    await asyncio.sleep(drip / 10)
            await resp.write_eof()
            completed = 1
            return resp
        except ConnectionResetError:
            # The bot hung up before the page finished: it gave up waiting.
            return resp
        finally:
            # Runs whether the page finished, the bot hung up, or the
            # request was cancelled -- so every trap page gets a duration.
            log_trap_end(request.app, rowid, started, completed)


async def catch_all(request):
    """Every other request: scanners probing /wp-login.php, /.env, etc."""
    log_hit(request.app, request, "probe")
    return web.Response(status=404, text="Not Found")


async def stats(request):
    key = request.app["stats_key"]
    if key and request.query.get("key") != key:
        return await catch_all(request)
    db = request.app["db"]
    rows = db.execute(
        """SELECT ip, user_agent,
                  SUM(kind='trap'), SUM(kind='probe'), MAX(depth),
                  SUM(kind='robots') > 0, SUM(kind='asset') > 0,
                  ROUND(MAX(ts) - MIN(ts), 1)
           FROM hits GROUP BY ip, user_agent
           ORDER BY 3 DESC, 4 DESC LIMIT 500"""
    ).fetchall()
    # Per-page trap timing, grouped by client, for the trapped-time numbers.
    trap_rows = defaultdict(list)
    for ip, ua, ts, dur, comp in db.execute(
            "SELECT ip, user_agent, ts, duration, completed FROM hits "
            "WHERE kind='trap'"):
        trap_rows[(ip, ua)].append((ts, dur, comp))

    clients = []
    for r in rows:
        c = {
            "ip": r[0], "user_agent": r[1], "trap_pages": r[2], "probes": r[3],
            "max_depth": r[4], "read_robots_txt": bool(r[5]),
            "fetched_assets": bool(r[6]), "seconds_active": r[7],
            # One-strike rule (McKenna 2016): entering a robots.txt-disallowed
            # area makes a client "bad". Probing exploit paths marks a scanner.
            "verdict": "BAD BOT" if r[2] else "SCANNER" if r[3] else "ok",
        }
        if r[2]:
            c.update(trap_metrics(trap_rows[(r[0], r[1])]))
        clients.append(c)
    return web.json_response({"clients": clients})


# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------
def make_app(drip, db_path, stats_key="", behind_proxy=False, domain=""):
    app = web.Application()
    app["db"] = init_db(db_path)
    app["drip"] = drip
    app["stats_key"] = stats_key
    app["behind_proxy"] = behind_proxy
    app["domain"] = domain
    app["sem"] = asyncio.Semaphore(MAX_TRAPPED)
    routes = [
        web.get("/", home),
        web.get("/about", about),
        web.get("/robots.txt", robots),
        web.get("/sitemap.xml", sitemap),
        web.get("/static/style.css", css),
        web.get("/favicon.ico", favicon),
        web.get("/archive/{slug}", trap),
        web.get("/stats", stats),
    ]
    routes += [web.get(entry[0], section_handler(entry)) for entry in sc.REAL_PAGES]
    routes.append(web.route("*", "/{tail:.*}", catch_all))   # must be last
    app.add_routes(routes)
    return app


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="Greek History World honeypot")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8080)
    p.add_argument("--drip", type=float, default=0.5,
                   help="seconds to spend sending each trap page (0 = instant)")
    p.add_argument("--db", default=DB_PATH, help="SQLite log file")
    p.add_argument("--stats-key", default="",
                   help="require /stats?key=<this>; set it on public servers")
    p.add_argument("--behind-proxy", action="store_true",
                   help="trust X-Forwarded-For (only behind your own proxy)")
    p.add_argument("--domain", default="",
                   help="public domain, e.g. greekhistoryworld.com (used in "
                        "sitemap/canonical links; blank = use request host)")
    args = p.parse_args()
    print(f"Honeypot on http://{args.host}:{args.port}")
    web.run_app(make_app(args.drip, args.db, args.stats_key,
                         args.behind_proxy, args.domain),
                host=args.host, port=args.port, print=None)
