#!/usr/bin/env python3
"""
Web-based honeypot / tarpit for scraper agents (CYSE 610, Group 1).

What it does
------------
  /               A normal-looking landing page. It contains a link to the
                  trap that is hidden from humans with display:none (the
                  method McKenna 2016 found screen readers also skip).
  /robots.txt     Disallows /archive/. Polite crawlers never enter the trap;
                  only bots that ignore robots.txt get caught.
  /archive/...    The infinite maze. Every URL returns a unique page with
                  more links back into the maze. Pages are generated from a
                  hash of the URL, so the same URL always returns the same
                  page (looks like a static site), but there are effectively
                  infinitely many URLs.
  /static/style.css  Real stylesheet. Browsers fetch it; most simple scrapers
                  don't, which is a bot signal (Doran & Gokhale 2012).
  /stats          JSON summary of what the honeypot has seen (for your demo).

Defenses against the usual crawler escape mechanisms
----------------------------------------------------
  * URL-seen dedup      -> every link is a new, unique URL
  * content dedup       -> page text is generated per URL, never identical
  * depth / URL length  -> URLs stay short and flat (/archive/<slug>)
  * server cost         -> async server + slow "drip" responses + a cap on
                           concurrent trapped connections

Run:   pip install aiohttp
       python honeypot.py --port 8080 --drip 0.5
"""

import argparse
import asyncio
import hashlib
import json
import random
import sqlite3
import time

from aiohttp import web

# ---------------------------------------------------------------------------
# Configuration (overridable from the command line)
# ---------------------------------------------------------------------------
LINKS_PER_PAGE = 12          # outgoing maze links per trap page
PARAGRAPHS_PER_PAGE = 4
MAX_TRAPPED = 200            # max simultaneous trap responses (protects host)
DB_PATH = "honeypot_log.db"

# Small built-in vocabulary for babble text. Swap in a Markov chain trained on
# public-domain text (e.g. the `markovify` package) for more realistic output.
WORDS = (
    "archive record report survey network system policy analysis data index "
    "protocol security research library catalog volume section review study "
    "method result model signal domain resource request server client access "
    "history summary journal article metric sample control field value range "
    "process structure feature source document entry update version release "
    "regional annual internal public technical federal standard extended "
    "primary secondary general special final initial complete partial "
    "describes includes provides supports requires indicates presents covers "
    "shows contains reviews examines compares outlines measures tracks lists"
).split()


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
def init_db(path):
    db = sqlite3.connect(path, check_same_thread=False)
    db.execute(
        """CREATE TABLE IF NOT EXISTS hits (
               ts REAL, ip TEXT, user_agent TEXT, path TEXT,
               kind TEXT, depth INTEGER)"""
    )
    db.commit()
    return db


def log_hit(app, request, kind, depth=0):
    ip = request.headers.get("X-Forwarded-For", request.remote or "?")
    ua = request.headers.get("User-Agent", "")
    app["db"].execute(
        "INSERT INTO hits VALUES (?,?,?,?,?,?)",
        (time.time(), ip, ua, request.path_qs, kind, depth),
    )
    app["db"].commit()


# ---------------------------------------------------------------------------
# Deterministic page generation
# ---------------------------------------------------------------------------
def rng_for(path):
    """Seed a PRNG from the URL so each URL always yields the same page."""
    seed = int.from_bytes(hashlib.sha256(path.encode()).digest()[:8], "big")
    return random.Random(seed)


def make_slug(rng):
    # Short, flat, plausible-looking slugs: /archive/k3x9-signal-review
    tag = "".join(rng.choice("abcdefghjkmnpqrstuvwxyz23456789") for _ in range(4))
    return f"{tag}-{rng.choice(WORDS)}-{rng.choice(WORDS)}"


def sentence(rng):
    words = [rng.choice(WORDS) for _ in range(rng.randint(8, 18))]
    return " ".join(words).capitalize() + "."


def build_trap_page(path, depth):
    rng = rng_for(path)
    title = " ".join(rng.choice(WORDS) for _ in range(4)).title()
    paras = "\n".join(
        f"<p>{' '.join(sentence(rng) for _ in range(rng.randint(3, 6)))}</p>"
        for _ in range(PARAGRAPHS_PER_PAGE)
    )
    links = "\n".join(
        f'<li><a href="/archive/{make_slug(rng)}?d={depth + 1}">'
        f"{' '.join(rng.choice(WORDS) for _ in range(3)).title()}</a></li>"
        for _ in range(LINKS_PER_PAGE)
    )
    return f"""<!doctype html>
<html><head><meta charset="utf-8">
<meta name="robots" content="noindex, nofollow">
<title>{title} | Records Archive</title>
<link rel="stylesheet" href="/static/style.css"></head>
<body><h1>{title}</h1>
{paras}
<h2>Related records</h2>
<ul>
{links}
</ul></body></html>"""


LANDING = """<!doctype html>
<html><head><meta charset="utf-8"><title>CYSE 610 Test Site</title>
<link rel="stylesheet" href="/static/style.css"></head>
<body>
<h1>Welcome to the CYSE 610 test site</h1>
<p>This is the legitimate page a human visitor sees.</p>
<p><a href="/about">About this project</a></p>

<!-- Honeypot entry: invisible to humans and screen readers, visible to any
     scraper that just parses <a href> tags out of the HTML. -->
<div style="display:none" aria-hidden="true">
  <a href="/archive/start-records-index?d=1">Full records archive</a>
</div>
</body></html>"""

ABOUT = """<!doctype html><html><head><meta charset="utf-8"><title>About</title>
<link rel="stylesheet" href="/static/style.css"></head>
<body><h1>About</h1><p>Group 1 honeypot research project.</p>
<p><a href="/">Home</a></p></body></html>"""

ROBOTS = "User-agent: *\nDisallow: /archive/\n"
CSS = "body{font-family:sans-serif;max-width:46rem;margin:2rem auto;padding:0 1rem}"


# ---------------------------------------------------------------------------
# Handlers
# ---------------------------------------------------------------------------
async def landing(request):
    log_hit(request.app, request, "landing")
    return web.Response(text=LANDING, content_type="text/html")


async def about(request):
    log_hit(request.app, request, "real_page")
    return web.Response(text=ABOUT, content_type="text/html")


async def robots(request):
    log_hit(request.app, request, "robots")
    return web.Response(text=ROBOTS, content_type="text/plain")


async def css(request):
    log_hit(request.app, request, "asset")
    return web.Response(text=CSS, content_type="text/css")


async def trap(request):
    """Serve a maze page, dripping it out slowly to waste the bot's time."""
    try:
        depth = int(request.query.get("d", "1"))
    except ValueError:
        depth = 1
    log_hit(request.app, request, "trap", depth)

    sem = request.app["sem"]
    if sem.locked():
        # Too many bots in the trap right now: answer cheaply instead of
        # letting the honeypot become a DoS against our own server.
        return web.Response(status=503, headers={"Retry-After": "120"})

    async with sem:
        body = build_trap_page(request.path, depth).encode()
        drip = request.app["drip"]
        resp = web.StreamResponse(
            headers={"Content-Type": "text/html; charset=utf-8"}
        )
        await resp.prepare(request)
        if drip <= 0:
            await resp.write(body)
        else:
            # Send the page in ~10 chunks spread over `drip` seconds.
            chunk = max(1, len(body) // 10)
            for i in range(0, len(body), chunk):
                await resp.write(body[i : i + chunk])
                await asyncio.sleep(drip / 10)
        await resp.write_eof()
        return resp


async def stats(request):
    db = request.app["db"]
    per_client = db.execute(
        """SELECT ip, user_agent,
                  SUM(kind='trap')                  AS trap_pages,
                  MAX(depth)                        AS max_depth,
                  SUM(kind='robots') > 0            AS read_robots,
                  SUM(kind='asset')  > 0            AS fetched_assets,
                  ROUND(MAX(ts) - MIN(ts), 1)       AS seconds_active
           FROM hits GROUP BY ip, user_agent ORDER BY trap_pages DESC"""
    ).fetchall()
    clients = [
        {
            "ip": r[0],
            "user_agent": r[1],
            "trap_pages": r[2],
            "max_depth": r[3],
            "read_robots_txt": bool(r[4]),
            "fetched_css": bool(r[5]),
            "seconds_active": r[6],
            # One-strike rule (McKenna 2016): entering a robots.txt-disallowed
            # area makes a client "bad". No CSS fetch is a supporting signal.
            "verdict": "BAD BOT" if r[2] else "ok",
        }
        for r in per_client
    ]
    return web.json_response({"clients": clients})


# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------
def make_app(drip, db_path):
    app = web.Application()
    app["db"] = init_db(db_path)
    app["drip"] = drip
    app["sem"] = asyncio.Semaphore(MAX_TRAPPED)
    app.add_routes(
        [
            web.get("/", landing),
            web.get("/about", about),
            web.get("/robots.txt", robots),
            web.get("/static/style.css", css),
            web.get("/archive/{slug}", trap),
            web.get("/stats", stats),
        ]
    )
    return app


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="Scraper honeypot / tarpit")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8080)
    p.add_argument("--drip", type=float, default=0.5,
                   help="seconds to spend sending each trap page (0 = instant)")
    p.add_argument("--db", default=DB_PATH, help="SQLite log file")
    args = p.parse_args()
    print(f"Honeypot on http://{args.host}:{args.port}  (stats at /stats)")
    web.run_app(make_app(args.drip, args.db), host=args.host, port=args.port,
                print=None)