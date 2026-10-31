#!/usr/bin/env python3
"""
Summarize what the honeypot caught.

Usage:  python report.py [honeypot_log.db]

Sorts every visitor (IP + user agent) into a rough category:
  search engine   self-identified Googlebot, Bingbot, etc. (should obey robots.txt)
  AI crawler      self-identified AI/LLM data crawlers (GPTBot, ClaudeBot, ...)
  SEO/other bot   other self-identified bots (Ahrefs, Semrush, ...)
  scanner         probes for /wp-login.php, /.env, /admin and other exploits
  tool/library    python-requests, curl, Go, Scrapy... (custom scrapers)
  browser-like    claims to be a normal web browser

Note: user agents can be faked. To confirm a real Googlebot, do a reverse DNS
lookup on its IP (should end in googlebot.com) -- McKenna (2016) found about
half of "browser" bots in his logs were forged.
"""

import sqlite3
import sys
from collections import Counter, defaultdict
from datetime import datetime

SEARCH = ("googlebot", "bingbot", "yandex", "baiduspider", "duckduckbot",
          "applebot", "slurp", "seznambot", "petalbot")
AI = ("gptbot", "chatgpt", "oai-searchbot", "claudebot", "claude-web",
      "anthropic", "ccbot", "perplexity", "bytespider", "amazonbot",
      "google-extended", "meta-externalagent", "facebookbot", "cohere",
      "diffbot", "imagesiftbot", "timpibot", "omgili", "ai2bot")
TOOLS = ("python", "curl", "wget", "go-http", "scrapy", "java/", "okhttp",
         "libwww", "httpclient", "node-fetch", "axios", "headless", "zgrab",
         "masscan", "nmap", "nuclei")


def categorize(ua, probes):
    u = ua.lower()
    if any(k in u for k in AI):
        return "AI crawler"
    if any(k in u for k in SEARCH):
        return "search engine"
    if probes:
        return "scanner"
    if any(k in u for k in TOOLS):
        return "tool/library"
    if "bot" in u or "crawl" in u or "spider" in u:
        return "SEO/other bot"
    if not u:
        return "no user agent"
    return "browser-like"


SESSION_GAP = 30 * 60   # 30 min of silence = the bot left (standard in web-log research)


def trap_metrics(trap_rows, gap=SESSION_GAP):
    """How long one client was trapped.

    trap_rows: list of (ts, duration, completed) for that client's trap pages.
      ts        when the request arrived
      duration  seconds the page held the connection (None for old log rows)
      completed 1 = got the whole page, 0 = hung up early, -1 = turned away

    A "session" is a run of trap requests with no gap longer than `gap`
    between the end of one page and the start of the next. Long pauses are
    NOT counted as trapped time.
    """
    rows = sorted(trap_rows)
    if not rows:
        return {}
    sessions = []
    start, end = rows[0][0], rows[0][0] + (rows[0][1] or 0)
    for ts, dur, _ in rows[1:]:
        if ts - end > gap:              # went quiet: close this session
            sessions.append(end - start)
            start = ts
        end = max(end, ts + (dur or 0))
    sessions.append(end - start)
    return {
        # Wall-clock time inside the trap, pauses over 30 min excluded.
        "trapped_seconds": round(sum(sessions), 1),
        "trap_sessions": len(sessions),
        "longest_session_seconds": round(max(sessions), 1),
        # Total time our slow pages held its connections open (if the bot
        # opens several pages at once this can exceed trapped_seconds).
        "held_seconds": round(sum(d or 0 for _, d, _ in rows), 1),
        "pages_abandoned": sum(1 for *_, c in rows if c == 0),
    }


def fmt_secs(s):
    s = int(s or 0)
    return f"{s // 3600}h{s % 3600 // 60:02d}m" if s >= 3600 else f"{s // 60}m{s % 60:02d}s"


def main(path):
    db = sqlite3.connect(path)
    cols = {row[1] for row in db.execute("PRAGMA table_info(hits)")}
    timing = ("duration, completed" if "duration" in cols
              else "NULL, NULL")        # log files from before timing existed
    rows = db.execute(
        f"SELECT ts, ip, user_agent, path, kind, depth, {timing} FROM hits"
    ).fetchall()
    if not rows:
        print("No hits yet.")
        return

    clients = defaultdict(lambda: Counter())
    depth = defaultdict(int)
    trap_rows = defaultdict(list)
    for ts, ip, ua, p, kind, d, dur, comp in rows:
        clients[(ip, ua)][kind] += 1
        depth[(ip, ua)] = max(depth[(ip, ua)], d or 0)
        if kind == "trap":
            trap_rows[(ip, ua)].append((ts, dur, comp))

    first = datetime.fromtimestamp(min(r[0] for r in rows))
    last = datetime.fromtimestamp(max(r[0] for r in rows))
    print(f"Log covers {first:%Y-%m-%d %H:%M} -> {last:%Y-%m-%d %H:%M}")
    print(f"Total requests: {len(rows)}   Unique clients (IP+UA): {len(clients)}\n")

    cat_counts = Counter()
    table = []
    for (ip, ua), k in clients.items():
        cat = categorize(ua, k["probe"])
        cat_counts[cat] += 1
        table.append((k["trap"], cat, ip, k["robots"] > 0, k["probe"],
                      depth[(ip, ua)], ua, trap_metrics(trap_rows[(ip, ua)])))

    print("Visitors by category:")
    for cat, n in cat_counts.most_common():
        print(f"  {cat:<15} {n}")

    trapped = [t for t in table if t[0] > 0]
    print(f"\nClients that entered the trap (ignored robots.txt): {len(trapped)}")
    print("  trapped = time inside the trap (pauses over 30 min left out)")
    print("  held    = total time our slow pages kept its connections open")
    print(f"  {'pages':>6} {'depth':>5} {'trapped':>8} {'held':>8} {'visits':>6} "
          f"{'quit':>4}  {'category':<14} {'ip':<16} user agent")
    for pages, cat, ip, robots, probes, d, ua, m in sorted(
            trapped, key=lambda t: t[7].get("trapped_seconds", 0), reverse=True)[:25]:
        print(f"  {pages:>6} {d:>5} {fmt_secs(m['trapped_seconds']):>8} "
              f"{fmt_secs(m['held_seconds']):>8} {m['trap_sessions']:>6} "
              f"{m['pages_abandoned']:>4}  {cat:<14} {ip:<16} {ua[:50]}")
    if trapped:
        total = sum(t[7]["trapped_seconds"] for t in trapped)
        held = sum(t[7]["held_seconds"] for t in trapped)
        print(f"\n  All trapped bots combined: {fmt_secs(total)} trapped, "
              f"{fmt_secs(held)} of connection time wasted")

    print("\nMost-probed paths (what scanners look for):")
    probes = Counter(r[3].split("?")[0] for r in rows if r[4] == "probe")
    for p, n in probes.most_common(15):
        print(f"  {n:>5}  {p[:70]}")

    print("\nTop user agents overall:")
    for ua, n in Counter(r[2] for r in rows).most_common(10):
        print(f"  {n:>5}  {ua[:80] or '(none)'}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "honeypot_log.db")
