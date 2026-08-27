#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import tomllib
from urllib.request import Request, urlopen


def request_json(url: str, payload: dict[str, object] | None = None) -> dict[str, object]:
    body = None if payload is None else json.dumps(payload).encode("utf-8")
    request = Request(
        url,
        data=body,
        headers={"Content-Type": "application/json", "User-Agent": "blueeconomy-osv-audit/1"},
        method="GET" if payload is None else "POST",
    )
    with urlopen(request, timeout=60) as response:  # noqa: S310 -- fixed HTTPS OSV endpoint only
        return json.load(response)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lock", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    # Explicitly reviewed advisory exceptions (e.g. informational
    # "unmaintained" notices in an optional feature tree). Every exception is
    # recorded in the report and must be justified at the call site.
    parser.add_argument("--allow-advisory", action="append", default=[])
    arguments = parser.parse_args()
    allowed = set(arguments.allow_advisory)

    with arguments.lock.open("rb") as handle:
        lock = tomllib.load(handle)
    packages = [
        {"name": package["name"], "version": package["version"]}
        for package in lock.get("package", [])
        if str(package.get("source", "")).startswith("registry+")
    ]
    queries = [
        {
            "version": package["version"],
            "package": {"name": package["name"], "ecosystem": "crates.io"},
        }
        for package in packages
    ]
    batch = request_json("https://api.osv.dev/v1/querybatch", {"queries": queries})
    results = batch.get("results")
    if not isinstance(results, list) or len(results) != len(packages):
        raise RuntimeError("OSV result count does not match locked package count")

    findings: list[dict[str, object]] = []
    for package, result in zip(packages, results, strict=True):
        if not isinstance(result, dict):
            raise RuntimeError("OSV returned a malformed package result")
        vulnerabilities = result.get("vulns", [])
        if not isinstance(vulnerabilities, list):
            raise RuntimeError("OSV returned a malformed vulnerability list")
        for vulnerability in vulnerabilities:
            if not isinstance(vulnerability, dict) or not isinstance(vulnerability.get("id"), str):
                raise RuntimeError("OSV returned a malformed vulnerability reference")
            detail = request_json(f"https://api.osv.dev/v1/vulns/{vulnerability['id']}")
            suppressed = vulnerability["id"] in allowed
            findings.append(
                {
                    "package": package,
                    "id": detail.get("id"),
                    "summary": detail.get("summary", ""),
                    "aliases": detail.get("aliases", []),
                    "modified": detail.get("modified", ""),
                    "withdrawn": detail.get("withdrawn"),
                    "suppressed": suppressed,
                }
            )

    report = {
        "schema_version": "blueeconomy.dependency-audit.osv.v1",
        "source": "https://api.osv.dev/v1/querybatch",
        "ecosystem": "crates.io",
        "locked_package_count": len(packages),
        "finding_count": len(findings),
        "findings": findings,
    }
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    arguments.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    active = [finding for finding in findings if not finding["suppressed"]]
    print(json.dumps({"locked_package_count": len(packages), "finding_count": len(active)}))
    return 1 if active else 0


if __name__ == "__main__":
    sys.exit(main())
