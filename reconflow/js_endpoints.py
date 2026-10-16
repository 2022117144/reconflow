"""
reconflow.js_endpoints
----------------------
Extracts hidden API endpoints, REST routes, GraphQL operations, and internal
query parameters from discovered client-side JavaScript bundles.
"""

import json
import re
import urllib.request
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Dict, List, Set, Any

# Common API route patterns in modern SPAs (React, Vue, Angular, Next.js)
ROUTE_PATTERNS = [
    re.compile(r"""(?:["'`])(\/(?:api|v[0-9]+|graphql|auth|oauth|admin|internal|user|account|debug|rest|v1|v2|v3)[\w\-./?&=#%]*)(?:["'`])""", re.IGNORECASE),
    re.compile(r"""(?:["'`])(\/swagger[\w\-./?&=#%]*|\/openapi[\w\-./?&=#%]*)(?:["'`])""", re.IGNORECASE),
]

# Absolute URLs pointing to internal or same-root infrastructure
URL_PATTERN = re.compile(r"""https?://[a-zA-Z0-9.\-]+(?:\:[0-9]+)?/[a-zA-Z0-9_\-./?&=#%]*""")

# GraphQL queries & mutations defined in client code
GRAPHQL_QUERY_PATTERN = re.compile(r"""(?:query|mutation|subscription)\s+([A-Za-z0-9_]+)\s*[\(\{]""")

# URL parameters embedded in strings or fetch calls
PARAM_PATTERN = re.compile(r"""(?:\?|&)([a-zA-Z0-9_\-]{2,35})=""")

# Extensions and vendor paths to filter out as noise
STATIC_EXTENSIONS = (
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico",
    ".css", ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mp3",
    ".webm", ".map", ".wasm"
)

IGNORED_FRAGMENTS = [
    "node_modules", "core-js", "react-dom", "webpack://", "regenerator-runtime",
    "/static/media/", "xmlns=", "w3.org"
]


def extract_routes_from_text(content: str, domain: str = "") -> Dict[str, Any]:
    """Parse JavaScript source code to extract routes, URLs, GraphQL queries, and parameters."""
    routes: Set[str] = set()
    absolute_urls: Set[str] = set()
    graphql_ops: Set[str] = set()
    params: Set[str] = set()

    # 1. Relative API routes
    for pat in ROUTE_PATTERNS:
        for match in pat.finditer(content):
            route = match.group(1).strip()
            # Basic sanity checks
            if len(route) < 3 or len(route) > 250:
                continue
            if any(route.lower().endswith(ext) for ext in STATIC_EXTENSIONS):
                continue
            if any(ign in route for ign in IGNORED_FRAGMENTS):
                continue
            routes.add(route)

    # 2. Absolute URLs matching target or general endpoints
    for match in URL_PATTERN.finditer(content):
        url = match.group(0).strip()
        if any(url.lower().endswith(ext) for ext in STATIC_EXTENSIONS):
            continue
        if any(ign in url for ign in IGNORED_FRAGMENTS):
            continue
        if domain and domain.lower() in url.lower():
            absolute_urls.add(url)
        elif not domain:
            absolute_urls.add(url)

    # 3. GraphQL operations
    for match in GRAPHQL_QUERY_PATTERN.finditer(content):
        op_name = match.group(1).strip()
        if len(op_name) > 1 and op_name not in {"fragment", "type", "schema"}:
            graphql_ops.add(op_name)

    # 4. Embedded query parameters
    for match in PARAM_PATTERN.finditer(content):
        param = match.group(1).strip()
        if len(param) > 1 and not param.isdigit():
            params.add(param)

    # Categorize routes into high-value buckets
    categorized = {
        "admin_internal": [],
        "auth_oauth": [],
        "graphql": [],
        "api_rest": [],
        "general": []
    }

    for r in sorted(routes):
        low = r.lower()
        if any(k in low for k in ["/admin", "/internal", "/debug", "/super"]):
            categorized["admin_internal"].append(r)
        elif any(k in low for k in ["/auth", "/oauth", "/login", "/sso", "/token", "/session"]):
            categorized["auth_oauth"].append(r)
        elif "/graphql" in low:
            categorized["graphql"].append(r)
        elif any(k in low for k in ["/api", "/v1", "/v2", "/v3", "/rest"]):
            categorized["api_rest"].append(r)
        else:
            categorized["general"].append(r)

    return {
        "routes_count": len(routes),
        "categorized_routes": categorized,
        "all_routes": sorted(list(routes)),
        "absolute_urls": sorted(list(absolute_urls)),
        "graphql_operations": sorted(list(graphql_ops)),
        "parameters": sorted(list(params)),
    }


def fetch_js_file(url: str, timeout: int = 7) -> str:
    """Fetch JavaScript content over HTTP/HTTPS safely."""
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "reconflow-endpoint-extractor/1.0"}
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            content_type = resp.headers.get("Content-Type", "")
            # Only read if textual or javascript-like
            raw = resp.read(5 * 1024 * 1024)  # 5 MB max per file
            return raw.decode("utf-8", errors="ignore")
    except Exception:
        return ""


def extract_js_endpoints(
    js_urls: List[str],
    output_dir: Path,
    domain: str = "",
    threads: int = 10,
    timeout: int = 7
) -> Dict[str, Any]:
    """Download and analyze discovered JS URLs to extract routes and endpoints."""
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Filter down to probable JS files
    target_urls = [u for u in js_urls if u.split("?")[0].endswith(".js") or "/js/" in u]
    if not target_urls:
        target_urls = js_urls[:50]  # Fallback sample

    print(f"[*] Extracting endpoints & API routes from {len(target_urls)} JavaScript source(s)...")

    combined_routes: Set[str] = set()
    combined_absolute: Set[str] = set()
    combined_graphql: Set[str] = set()
    combined_params: Set[str] = set()
    file_findings: List[Dict[str, Any]] = []

    def process_url(u: str):
        content = fetch_js_file(u, timeout=timeout)
        if not content:
            return None
        res = extract_routes_from_text(content, domain=domain)
        if res["routes_count"] > 0 or res["graphql_operations"] or res["parameters"]:
            return {"url": u, "data": res}
        return None

    with ThreadPoolExecutor(max_workers=min(threads, 20)) as pool:
        results = pool.map(process_url, target_urls)

    for item in results:
        if not item:
            continue
        u = item["url"]
        data = item["data"]
        combined_routes.update(data["all_routes"])
        combined_absolute.update(data["absolute_urls"])
        combined_graphql.update(data["graphql_operations"])
        combined_params.update(data["parameters"])
        file_findings.append({
            "source_url": u,
            "routes_count": data["routes_count"],
            "categorized_routes": data["categorized_routes"],
            "graphql_operations": data["graphql_operations"],
        })

    # Regroup combined routes
    categorized_total = {
        "admin_internal": [],
        "auth_oauth": [],
        "graphql": [],
        "api_rest": [],
        "general": []
    }
    for r in sorted(combined_routes):
        low = r.lower()
        if any(k in low for k in ["/admin", "/internal", "/debug", "/super"]):
            categorized_total["admin_internal"].append(r)
        elif any(k in low for k in ["/auth", "/oauth", "/login", "/sso", "/token", "/session"]):
            categorized_total["auth_oauth"].append(r)
        elif "/graphql" in low:
            categorized_total["graphql"].append(r)
        elif any(k in low for k in ["/api", "/v1", "/v2", "/v3", "/rest"]):
            categorized_total["api_rest"].append(r)
        else:
            categorized_total["general"].append(r)

    summary = {
        "domain": domain,
        "js_files_scanned": len(target_urls),
        "total_unique_routes": len(combined_routes),
        "total_graphql_ops": len(combined_graphql),
        "total_unique_params": len(combined_params),
        "categorized_routes": categorized_total,
        "all_routes": sorted(list(combined_routes)),
        "absolute_urls": sorted(list(combined_absolute)),
        "graphql_operations": sorted(list(combined_graphql)),
        "parameters": sorted(list(combined_params)),
        "files": file_findings,
    }

    # Save outputs
    json_path = output_dir / "js_endpoints.json"
    json_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    txt_path = output_dir / "js_endpoints.txt"
    all_endpoints = sorted(list(combined_routes | combined_absolute))
    txt_path.write_text("\n".join(all_endpoints) + ("\n" if all_endpoints else ""), encoding="utf-8")

    print(
        f"[+] Extracted {len(combined_routes)} unique route(s) and {len(combined_graphql)} "
        f"GraphQL operation(s) across {len(file_findings)} file(s) -> {json_path.name}"
    )
    return summary
