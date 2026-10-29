#!/usr/bin/env python3
"""
A deliberately naive breadth-first scraper, modeled on the basic crawl loop in
Olston & Najork (2010): pop a URL from the frontier, download it, extract every
<a href>, add unseen links to the frontier, repeat.

It has the two defenses almost every crawler has:
  * a "seen" set, so it never downloads the same URL twice
  * a same-host restriction, so it stays on the target site

It does NOT read robots.txt, check CSS visibility, limit depth, or detect
duplicate content -- which is exactly why it falls into the honeypot.

For safety in a demo it stops after --max-pages or --max-seconds and prints a
report; without those caps it would crawl forever.

Run:   python naive_scraper.py http://127.0.0.1:8080/ --max-pages 200
Uses only the Python standard library.
"""

import argparse
import time
from collections import deque
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse
from urllib.request import Request, urlopen


class LinkParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            href = dict(attrs).get("href")
            if href:
                self.links.append(href)


def crawl(start, max_pages, max_seconds):
    host = urlparse(start).netloc
    frontier = deque([start])
    seen = {start}
    fetched = 0
    trap_pages = 0
    max_depth = 0
    t0 = time.time()

    while frontier:
        if fetched >= max_pages or time.time() - t0 >= max_seconds:
            break
        url = frontier.popleft()
        try:
            req = Request(url, headers={"User-Agent": "NaiveScraper/1.0"})
            with urlopen(req, timeout=30) as r:
                html = r.read().decode("utf-8", "replace")
        except Exception as e:
            print(f"  ! {url}: {e}")
            continue
        fetched += 1

        if "/archive/" in url:
            trap_pages += 1
            d = int(url.split("d=")[-1]) if "d=" in url else 0
            max_depth = max(max_depth, d)

        parser = LinkParser()
        parser.feed(html)
        new = 0
        for href in parser.links:
            link = urljoin(url, href)
            if urlparse(link).netloc == host and link not in seen:
                seen.add(link)
                frontier.append(link)
                new += 1

        if fetched <= 5 or fetched % 25 == 0:
            print(f"[{fetched:4d}] {urlparse(url).path:<40} "
                  f"+{new:2d} new links | frontier={len(frontier)}")

    elapsed = time.time() - t0
    print("\n=== Scraper report ===")
    print(f"Pages fetched        : {fetched}")
    print(f"  of which trap pages: {trap_pages}  "
          f"({100 * trap_pages / max(fetched, 1):.0f}%)")
    print(f"Deepest trap level   : {max_depth}")
    print(f"Unvisited URLs queued: {len(frontier)}  (still growing -> never finishes)")
    print(f"Time spent           : {elapsed:.1f}s")
    print("Stopped by           :",
          "page cap" if fetched >= max_pages else
          "time cap" if elapsed >= max_seconds else "frontier empty (escaped!)")


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("start_url", nargs="?", default="http://127.0.0.1:8080/")
    p.add_argument("--max-pages", type=int, default=200)
    p.add_argument("--max-seconds", type=float, default=120)
    a = p.parse_args()
    crawl(a.start_url, a.max_pages, a.max_seconds)
