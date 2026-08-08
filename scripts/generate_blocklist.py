#!/usr/bin/env python3
"""
Fetch the SearXNG public instances list and convert it into an
AdBlock/uBlock Origin style domain blocklist (||domain^ per line).

Source: https://github.com/searxng/searx-instances
Output: one `||domain^` rule per unique clearnet domain, sorted.
"""

import sys
import urllib.request
from urllib.parse import urlparse

import yaml

SOURCE_URL = (
    "https://raw.githubusercontent.com/searxng/searx-instances/"
    "master/searxinstances/instances.yml"
)
OUTPUT_PATH = "searx-blocklist.txt"


def fetch_yaml(url: str) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "searx-blocklist-bot"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        raw = resp.read().decode("utf-8")
    data = yaml.safe_load(raw)
    if not isinstance(data, dict):
        raise ValueError("Unexpected YAML structure from source file")
    return data


def extract_domains(data: dict) -> set[str]:
    """
    Each top-level key is a clearnet URL (e.g. https://searx.example.com).
    Some entries also have an `additional_urls` dict pointing at .onion
    mirrors -- those are skipped since they aren't standard DNS/adblock
    blockable domains.
    """
    domains = set()
    for url in data.keys():
        parsed = urlparse(url)
        host = parsed.netloc or parsed.path  # fallback in case of malformed entries
        host = host.strip("/").lower()
        if host:
            domains.add(host)
    return domains


def to_adblock_rules(domains: set[str]) -> list[str]:
    return [f"||{domain}^" for domain in sorted(domains)]


def main() -> int:
    try:
        data = fetch_yaml(SOURCE_URL)
    except Exception as exc:  # noqa: BLE001
        print(f"ERROR: failed to fetch/parse source YAML: {exc}", file=sys.stderr)
        return 1

    domains = extract_domains(data)
    if not domains:
        print("ERROR: no domains extracted, refusing to write an empty blocklist", file=sys.stderr)
        return 1

    rules = to_adblock_rules(domains)

    header = [
        "! Title: SearXNG Public Instances Blocklist",
        "! Description: Auto-generated daily from searxng/searx-instances",
        f"! Source: {SOURCE_URL}",
        f"! Domain count: {len(rules)}",
        "!",
    ]

    with open(OUTPUT_PATH, "w") as f:
        f.write("\n".join(header + rules) + "\n")

    print(f"Wrote {len(rules)} domains to {OUTPUT_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
