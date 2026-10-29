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


def main(path):
    db = sqlite3.connect(path)
    rows = db.execute(
        "SELECT ts, ip, user_agent, path, kind, depth FROM hits").fetchall()
    if not rows:
        print("No hits yet.")
        return

    clients = defaultdict(lambda: Counter())
    depth = defaultdict(int)
    for ts, ip, ua, p, kind, d in rows:
        clients[(ip, ua)][kind] += 1
        depth[(ip, ua)] = max(depth[(ip, ua)], d or 0)

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
                      depth[(ip, ua)], ua))

    print("Visitors by category:")
    for cat, n in cat_counts.most_common():
        print(f"  {cat:<15} {n}")

    trapped = [t for t in table if t[0] > 0]
    print(f"\nClients that entered the trap (ignored robots.txt): {len(trapped)}")
    print(f"  {'pages':>6} {'depth':>5} {'robots':>6}  {'category':<14} {'ip':<16} user agent")
    for pages, cat, ip, robots, probes, d, ua in sorted(trapped, reverse=True)[:25]:
        print(f"  {pages:>6} {d:>5} {str(robots):>6}  {cat:<14} {ip:<16} {ua[:60]}")

    print("\nMost-probed paths (what scanners look for):")
    probes = Counter(r[3].split("?")[0] for r in rows if r[4] == "probe")
    for p, n in probes.most_common(15):
        print(f"  {n:>5}  {p[:70]}")

    print("\nTop user agents overall:")
    for ua, n in Counter(r[2] for r in rows).most_common(10):
        print(f"  {n:>5}  {ua[:80] or '(none)'}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "honeypot_log.db")
