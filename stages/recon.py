"""Stage 1: subdomain enumeration and live-host probing.

`run` discovers candidate hosts (subfinder/assetfinder, or a single seeded
host for bare-IP targets) and confirms liveness with ProjectDiscovery httpx,
falling back to Shaidra's own httpx library when the Go tool is missing.
`scan_ports` runs naabu against the target and reports admin/database ports.
"""

from __future__ import annotations

import asyncio
import contextlib
import html as html_lib
import json
import re
from pathlib import Path
from typing import Final
from urllib.parse import urlsplit

import httpx

from shaidra.core.events import EventBus
from shaidra.core.models import Category, Finding, Host, LogLevel, ScanContext, Severity
from shaidra.utils.http import make_http_client
from shaidra.utils.process import RunOptions, run_tool, stream_lines
from shaidra.utils.rate_limiter import RateLimiter

STAGE: Final[str] = "recon"
PORT_STAGE: Final[str] = "port-scan"
FALLBACK_HOST_CAP: Final[int] = 100
FALLBACK_HOST_CAP_DEEP: Final[int] = 400
FALLBACK_TIMEOUT: Final[float] = 10.0
FALLBACK_CONCURRENCY: Final[int] = 10
_TITLE_RE: Final[re.Pattern[str]] = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_ADMIN_PORTS: Final[dict[int, str]] = {
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    27017: "MongoDB",
    9200: "Elasticsearch",
    11211: "Memcached",
    2375: "Docker API",
    5900: "VNC",
}
_PORT_SCAN_TIMEOUT: Final[float] = 1.5
_PORT_SCAN_CONCURRENCY: Final[int] = 200
_COMMON_PORTS: Final[tuple[int, ...]] = (
    20,
    21,
    22,
    23,
    25,
    53,
    67,
    68,
    69,
    80,
    88,
    110,
    111,
    119,
    123,
    135,
    137,
    138,
    139,
    143,
    161,
    162,
    179,
    194,
    389,
    443,
    445,
    464,
    465,
    500,
    512,
    513,
    514,
    515,
    520,
    548,
    554,
    563,
    587,
    593,
    623,
    631,
    636,
    646,
    873,
    902,
    903,
    989,
    990,
    992,
    993,
    995,
    1025,
    1026,
    1027,
    1028,
    1029,
    1080,
    1081,
    1099,
    1110,
    1158,
    1194,
    1241,
    1311,
    1337,
    1352,
    1433,
    1434,
    1521,
    1522,
    1524,
    1533,
    1556,
    1582,
    1583,
    1594,
    1604,
    1645,
    1701,
    1717,
    1720,
    1723,
    1755,
    1812,
    1813,
    1863,
    1883,
    1900,
    1935,
    1947,
    1971,
    2000,
    2001,
    2002,
    2003,
    2004,
    2005,
    2006,
    2007,
    2008,
    2009,
    2010,
    2020,
    2022,
    2049,
    2082,
    2083,
    2086,
    2087,
    2095,
    2096,
    2100,
    2103,
    2105,
    2107,
    2111,
    2121,
    2144,
    2160,
    2181,
    2200,
    2222,
    2231,
    2301,
    2323,
    2366,
    2375,
    2376,
    2379,
    2381,
    2382,
    2383,
    2399,
    2400,
    2480,
    2483,
    2484,
    2557,
    2601,
    2604,
    2638,
    2809,
    2869,
    2947,
    3000,
    3001,
    3005,
    3006,
    3007,
    3011,
    3013,
    3017,
    3030,
    3031,
    3050,
    3052,
    3071,
    3077,
    3128,
    3168,
    3200,
    3211,
    3221,
    3260,
    3261,
    3268,
    3269,
    3283,
    3300,
    3301,
    3306,
    3322,
    3323,
    3324,
    3325,
    3333,
    3351,
    3367,
    3369,
    3370,
    3371,
    3372,
    3389,
    3390,
    3404,
    3476,
    3493,
    3517,
    3527,
    3546,
    3551,
    3580,
    3659,
    3689,
    3690,
    3703,
    3737,
    3766,
    3784,
    3800,
    3801,
    3809,
    3814,
    3826,
    3827,
    3851,
    3869,
    3871,
    3878,
    3880,
    3888,
    3900,
    3918,
    3920,
    3945,
    3971,
    3986,
    3995,
    3998,
    4000,
    4001,
    4002,
    4003,
    4004,
    4005,
    4006,
    4040,
    4045,
    4064,
    4111,
    4125,
    4126,
    4127,
    4128,
    4129,
    4224,
    4242,
    4279,
    4321,
    4333,
    4343,
    4443,
    4444,
    4445,
    4446,
    4449,
    4550,
    4567,
    4660,
    4662,
    4664,
    4672,
    4711,
    4712,
    4730,
    4786,
    4800,
    4848,
    4899,
    4900,
    4998,
    5000,
    5001,
    5002,
    5003,
    5004,
    5005,
    5009,
    5030,
    5033,
    5050,
    5051,
    5054,
    5060,
    5061,
    5080,
    5087,
    5093,
    5099,
    5100,
    5101,
    5102,
    5120,
    5190,
    5191,
    5192,
    5193,
    5200,
    5221,
    5222,
    5225,
    5226,
    5269,
    5280,
    5298,
    5300,
    5301,
    5302,
    5303,
    5304,
    5305,
    5306,
    5307,
    5308,
    5310,
    5311,
    5314,
    5353,
    5357,
    5405,
    5414,
    5431,
    5432,
    5433,
    5440,
    5500,
    5501,
    5503,
    5504,
    5510,
    5544,
    5550,
    5555,
    5560,
    5566,
    5631,
    5633,
    5666,
    5672,
    5678,
    5679,
    5680,
    5718,
    5730,
    5800,
    5801,
    5802,
    5803,
    5810,
    5811,
    5814,
    5858,
    5900,
    5901,
    5902,
    5903,
    5904,
    5906,
    5907,
    5910,
    5911,
    5912,
    5915,
    5920,
    5922,
    5925,
    5950,
    5952,
    5959,
    5960,
    5961,
    5962,
    5963,
    5984,
    5985,
    5986,
    5987,
    5988,
    5998,
    5999,
    6000,
    6001,
    6002,
    6003,
    6004,
    6005,
    6006,
    6007,
    6009,
    6025,
    6059,
    6106,
    6112,
    6123,
    6129,
    6156,
    6346,
    6347,
    6379,
    6389,
    6443,
    6481,
    6502,
    6510,
    6543,
    6544,
    6550,
    6556,
    6565,
    6566,
    6567,
    6580,
    6588,
    6600,
    6622,
    6626,
    6628,
    6631,
    6646,
    6653,
    6660,
    6664,
    6666,
    6667,
    6668,
    6669,
    6689,
    6692,
    6699,
    6779,
    6788,
    6792,
    6800,
    6817,
    6839,
    6881,
    6901,
    6969,
    7000,
    7001,
    7002,
    7003,
    7004,
    7007,
    7019,
    7025,
    7070,
    7071,
    7077,
    7080,
    7100,
    7106,
    7200,
    7201,
    7262,
    7272,
    7402,
    7435,
    7443,
    7496,
    7512,
    7625,
    7627,
    7676,
    7722,
    7741,
    7777,
    7778,
    7800,
    7878,
    7902,
    7911,
    7920,
    7921,
    7937,
    7938,
    7999,
    8000,
    8001,
    8002,
    8003,
    8004,
    8005,
    8006,
    8007,
    8008,
    8009,
    8010,
    8011,
    8012,
    8013,
    8014,
    8015,
    8016,
    8017,
    8018,
    8019,
    8020,
    8021,
    8022,
    8032,
    8042,
    8045,
    8080,
    8081,
    8082,
    8083,
    8084,
    8085,
    8086,
    8087,
    8088,
    8089,
    8090,
    8091,
    8092,
    8093,
    8094,
    8095,
    8096,
    8097,
    8098,
    8099,
    8100,
    8111,
    8112,
    8118,
    8123,
    8129,
    8140,
    8161,
    8180,
    8181,
    8182,
    8192,
    8193,
    8200,
    8222,
    8243,
    8254,
    8290,
    8291,
    8300,
    8301,
    8333,
    8383,
    8400,
    8402,
    8443,
    8444,
    8500,
    8529,
    8530,
    8531,
    8545,
    8600,
    8649,
    8651,
    8652,
    8654,
    8701,
    8800,
    8873,
    8880,
    8888,
    8889,
    8890,
    8899,
    8900,
    8910,
    8983,
    8994,
    9000,
    9001,
    9002,
    9003,
    9009,
    9010,
    9011,
    9020,
    9021,
    9022,
    9023,
    9024,
    9025,
    9026,
    9080,
    9090,
    9091,
    9099,
    9100,
    9101,
    9102,
    9103,
    9110,
    9111,
    9200,
    9207,
    9220,
    9290,
    9418,
    9443,
    9500,
    9535,
    9575,
    9593,
    9594,
    9595,
    9600,
    9666,
    9800,
    9876,
    9877,
    9878,
    9898,
    9900,
    9901,
    9903,
    9929,
    9943,
    9944,
    9968,
    9987,
    9997,
    9998,
    9999,
    10000,
    10001,
    10002,
    10003,
    10004,
    10009,
    10010,
    10012,
    10024,
    10025,
    10082,
    10083,
    10180,
    10215,
    10243,
    10566,
    10616,
    10617,
    10621,
    10626,
    10628,
    10629,
    10778,
    11110,
    11111,
    11967,
    12000,
    12174,
    12265,
    12345,
    13456,
    13722,
    13782,
    13783,
    14000,
    14238,
    14441,
    14442,
    15000,
    15002,
    15003,
    15004,
    15660,
    15742,
    16000,
    16001,
    16012,
    16016,
    16018,
    16080,
    16113,
    16992,
    16993,
    17877,
    17988,
    18040,
    18101,
    18988,
    19101,
    19283,
    19315,
    19350,
    19780,
    19801,
    19842,
    20000,
    20005,
    20031,
    20221,
    20222,
    20828,
    21571,
    22939,
    23502,
    24444,
    24800,
    25734,
    25735,
    26214,
    27000,
    27017,
    27018,
    27019,
    27352,
    27353,
    27355,
    27356,
    27715,
    28201,
    30000,
    30718,
    30951,
    31038,
    31337,
    32768,
    32769,
    32770,
    32771,
    32772,
    32773,
    32774,
    32775,
    32776,
    32777,
    32778,
    32779,
    32780,
    32781,
    32782,
    32783,
    32784,
    32785,
    33354,
    33899,
    34571,
    34572,
    34573,
    35500,
    38292,
    40193,
    40911,
    41511,
    42510,
    44176,
    44442,
    44443,
    44501,
    45100,
    48080,
    49152,
    49153,
    49154,
    49155,
    49156,
    49157,
    49158,
    49159,
    49160,
    49161,
    49163,
    49165,
    49167,
    49175,
    49176,
    49400,
    49999,
    50000,
    50001,
    50002,
    50006,
    50300,
    50389,
    50500,
    50636,
    50800,
    51103,
    51493,
    52673,
    52822,
    52848,
    52869,
    54045,
    54328,
    55055,
    55056,
    55555,
    55600,
    56737,
    56738,
    57294,
    57797,
    58080,
    60020,
    60443,
    61532,
    61900,
    62078,
    63331,
    64623,
    64680,
    65000,
    65129,
    65389,
)
# Deep mode widens the port sweep to the full 1-1024 range plus the common set.
_DEEP_PORTS: Final[tuple[int, ...]] = tuple(sorted({*_COMMON_PORTS, *range(1, 1025)}))
_CRT_SH_URL: Final[str] = "https://crt.sh/"
_HACKERTARGET_URL: Final[str] = "https://api.hackertarget.com/hostsearch/"
_CRT_TIMEOUT: Final[float] = 25.0
_DNS_TIMEOUT: Final[float] = 5.0
_BUILTIN_ENUM_CONCURRENCY: Final[int] = 30
_WILDCARD_PROBE_LABEL: Final[str] = "shaidra-wildcard-probe-9f3a1c"


async def run(ctx: ScanContext, bus: EventBus) -> None:
    """Enumerate subdomains, probe for liveness, and record live hosts."""
    await bus.stage_start(STAGE)
    base = _bare_host(ctx.target)
    seeded = urlsplit(ctx.target_url)
    candidates: list[Host] = [
        Host(host=base, url=ctx.target_url, scheme=seeded.scheme, port=seeded.port, source="target")
    ]
    if _is_bare_ip(base):
        await bus.log("Target is a bare IP address; subdomain enumeration skipped.", LogLevel.INFO)
    else:
        seen: set[str] = {base}
        for name in await _enumerate_subdomains(ctx, bus, base):
            if name not in seen:
                seen.add(name)
                candidates.append(Host(host=name, source="subdomain-enum"))
    if ctx.has_tool("httpx") and await _httpx_is_pd(ctx):
        live = await _probe_with_pd_httpx(ctx, bus, candidates)
    else:
        live = await _probe_with_python_httpx(ctx, bus, candidates)
    for host in live:
        ctx.add_host(host)
        await bus.host(host)
    await bus.stage_done(STAGE, f"{len(live)} live host(s) out of {len(candidates)} candidate(s)")


async def scan_ports(ctx: ScanContext, bus: EventBus) -> None:
    """Scan common ports and report interesting open services."""
    if ctx.has_tool("naabu"):
        await _scan_ports_naabu(ctx, bus)
        return
    await _scan_ports_builtin(ctx, bus)


async def _scan_ports_naabu(ctx: ScanContext, bus: EventBus) -> None:
    """Top-ports scan via ProjectDiscovery naabu."""
    await bus.stage_start(PORT_STAGE)
    argv = ["naabu", "-host", _bare_host(ctx.target), "-top-ports", "1000", "-silent", "-rate", str(ctx.rate_limit)]
    opts = RunOptions(timeout=float(ctx.config.timeout_for("naabu", 600)))
    found = 0
    async for line in stream_lines(argv, opts):
        parsed = _parse_host_port(line)
        if parsed is None:
            continue
        key, port = parsed
        if not ctx.scope.in_scope(key):
            continue
        matched = _match_host(ctx, key)
        if matched is None:
            continue
        found += 1
        if matched.port is None:
            matched.port = port
        await bus.stage_progress(PORT_STAGE, found, 0)
        service = _ADMIN_PORTS.get(port)
        if service is not None:
            await bus.finding(
                Finding(
                    title=f"Open {service} port {port}",
                    severity=Severity.INFO,
                    category=Category.RECON,
                    host=matched.host,
                    tool="naabu",
                    evidence=f"{key}:{port}",
                    url=matched.url,
                    description=f"Port {port} ({service}) is reachable on {key}.",
                )
            )
    await bus.stage_done(PORT_STAGE, f"{found} open port(s) found")


async def _scan_ports_builtin(ctx: ScanContext, bus: EventBus) -> None:
    """Fallback: async TCP connect scan over a common-port list.

    Used when naabu is unavailable — including when a host antivirus
    quarantines the naabu binary — so port discovery still works out of the box.
    """
    await bus.stage_start(PORT_STAGE)
    host = _bare_host(ctx.target)
    matched = _match_host(ctx, host)
    if matched is None:
        await bus.stage_skip(PORT_STAGE, "target not in scope")
        return
    ports = _DEEP_PORTS if ctx.deep else _COMMON_PORTS
    await bus.log(
        f"naabu not installed; falling back to built-in TCP scan ({len(ports)} ports).",
        LogLevel.WARN,
    )
    limiter = RateLimiter(float(ctx.rate_limit))
    sem = asyncio.Semaphore(_PORT_SCAN_CONCURRENCY)
    open_ports: list[int] = []

    async def probe(port: int) -> None:
        await limiter.acquire()
        async with sem:
            try:
                _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=_PORT_SCAN_TIMEOUT)
            except (TimeoutError, OSError):
                return
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
        open_ports.append(port)

    await asyncio.gather(*(probe(port) for port in ports), return_exceptions=True)
    open_ports.sort()
    if matched.port is None and open_ports:
        matched.port = open_ports[0]
    for port in open_ports:
        service = _ADMIN_PORTS.get(port)
        if service is None:
            continue
        await bus.finding(
            Finding(
                title=f"Open {service} port {port}",
                severity=Severity.INFO,
                category=Category.RECON,
                host=matched.host,
                tool="builtin",
                evidence=f"{host}:{port}",
                url=matched.url,
                description=f"Port {port} ({service}) is reachable on {host}.",
            )
        )
    await bus.stage_done(PORT_STAGE, f"{len(open_ports)} open port(s) found")


async def _enumerate_subdomains(ctx: ScanContext, bus: EventBus, base: str) -> list[str]:
    """Run the installed enum tools and return sorted, in-scope hostnames."""
    argvs: list[list[str]] = []
    if ctx.has_tool("subfinder"):
        argvs.append(["subfinder", "-d", base, "-silent"])
    if ctx.has_tool("assetfinder"):
        argvs.append(["assetfinder", "--subs-only", base])
    if argvs:
        results = await asyncio.gather(
            *(run_tool(argv, RunOptions(timeout=_tool_timeout(ctx, argv[0]))) for argv in argvs)
        )
        merged: set[str] = set()
        for result in results:
            if not result.ok:
                await bus.log(f"{result.tool} failed (rc={result.returncode}): {result.stderr.strip()}", LogLevel.WARN)
                continue
            merged.update(line.strip() for line in result.stdout.splitlines() if line.strip())
    else:
        merged = await _enumerate_builtin(ctx, bus, base)
    scoped = sorted(name for name in merged if ctx.scope.in_scope(name))
    await bus.log(f"Subdomain enumeration found {len(scoped)} in-scope candidate(s).")
    return scoped


async def _enumerate_builtin(ctx: ScanContext, bus: EventBus, base: str) -> set[str]:
    """Built-in subdomain discovery: Certificate Transparency logs + DNS brute force.

    Used only when subfinder/assetfinder are absent so a bare hostname still
    yields subdomains. CT-log names come from a third party (crt.sh) and are
    fetched with a bare client so no target auth headers leak; the DNS
    brute-force is skipped when the domain answers wildcard DNS, since every
    label would then falsely "resolve".
    """
    await bus.log(
        "No subdomain enumeration tool installed; using built-in enumeration (Certificate Transparency + DNS wordlist).",
        LogLevel.WARN,
    )
    found: set[str] = set()
    found.update(await _crt_sh_names(base))
    found.update(await _hackertarget_names(base))
    if await _has_wildcard_dns(base):
        await bus.log(
            f"{base} answers a random label (wildcard DNS); DNS brute-force skipped to avoid false positives.",
            LogLevel.WARN,
        )
    else:
        found.update(await _dns_brute(base, ctx.config.wordlist_subdomains))
    return found


async def _crt_sh_names(base: str) -> set[str]:
    """Return hostnames under `base` from Certificate Transparency logs."""
    names: set[str] = set()
    bare = base.casefold()
    try:
        async with httpx.AsyncClient(timeout=_CRT_TIMEOUT, headers={"User-Agent": "shaidra"}) as client:
            resp = await client.get(_CRT_SH_URL, params={"q": f"%.{base}", "output": "json"})
            if resp.status_code != 200:
                return names
            raw = resp.json()
    except (httpx.HTTPError, ValueError):
        return names
    if not isinstance(raw, list):
        return names
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        value = entry.get("name_value")
        if not isinstance(value, str):
            continue
        for line in value.splitlines():
            name = line.strip().lstrip("*.").casefold()
            if name == bare or name.endswith("." + bare):
                names.add(name)
    return names


async def _hackertarget_names(base: str) -> set[str]:
    """Return hostnames under `base` from the hackertarget host-search API."""
    names: set[str] = set()
    bare = base.casefold()
    try:
        async with httpx.AsyncClient(timeout=_CRT_TIMEOUT, headers={"User-Agent": "shaidra"}) as client:
            resp = await client.get(_HACKERTARGET_URL, params={"q": base})
            if resp.status_code != 200:
                return names
            body = resp.text
    except httpx.HTTPError:
        return names
    for line in body.splitlines():
        name = line.split(",", 1)[0].strip().casefold()
        if name and (name == bare or name.endswith("." + bare)):
            names.add(name)
    return names


async def _dns_brute(base: str, configured: str) -> set[str]:
    """Resolve each wordlist label under `base`; return the names that resolve."""
    words = _load_subdomain_labels(configured)
    if not words:
        return set()
    sem = asyncio.Semaphore(_BUILTIN_ENUM_CONCURRENCY)
    found: set[str] = set()

    async def check(word: str) -> None:
        name = f"{word}.{base}"
        async with sem:
            if await _resolves(name):
                found.add(name)

    await asyncio.gather(*(check(word) for word in words), return_exceptions=True)
    return found


async def _has_wildcard_dns(base: str) -> bool:
    """Return True when a random label under `base` resolves (wildcard DNS)."""
    return await _resolves(f"{_WILDCARD_PROBE_LABEL}.{base}")


async def _resolves(name: str) -> bool:
    """Return True when `name` resolves to at least one address."""
    loop = asyncio.get_running_loop()
    try:
        infos = await asyncio.wait_for(loop.getaddrinfo(name, None), timeout=_DNS_TIMEOUT)
    except (TimeoutError, OSError):
        return False
    return bool(infos)


def _load_subdomain_labels(configured: str) -> list[str]:
    """Read subdomain labels from the first existing wordlist, or return []."""
    path = _resolve_subdomain_wordlist(configured)
    if path is None:
        return []
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return []
    return [line.strip() for line in text.splitlines() if line.strip() and not line.startswith("#")]


def _resolve_subdomain_wordlist(configured: str) -> Path | None:
    """Return the first existing subdomain wordlist, or None when none exist."""
    requested = Path(configured)
    package_root = Path(__file__).resolve().parent.parent
    if requested.is_absolute():
        candidates = [requested]
    else:
        candidates = [
            Path.cwd() / requested,
            package_root / requested,
            package_root / "wordlists" / requested.name,
        ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None


def _tool_timeout(ctx: ScanContext, tool: str) -> float:
    return float(ctx.config.timeout_for(tool))


async def _httpx_is_pd(ctx: ScanContext) -> bool:
    """Confirm the ``httpx`` on PATH is ProjectDiscovery's, not the Python library CLI.

    The Python ``httpx`` package ships its own console script named ``httpx``;
    feeding it ProjectDiscovery flags produces no usable output, so its bare
    presence must not select the JSONL probe path. ProjectDiscovery httpx is
    recognised by its version banner; anything else falls back to built-in
    probing.
    """
    result = await run_tool(["httpx", "-version"], RunOptions(timeout=15.0))
    if not result.ok:
        return False
    output = f"{result.stdout}\n{result.stderr}"
    if "projectdiscovery" in output.casefold():
        return True
    return not re.search(r"httpx[^\n]{0,16}\s+\d", output, re.IGNORECASE)


async def _probe_with_pd_httpx(ctx: ScanContext, bus: EventBus, candidates: list[Host]) -> list[Host]:
    """Probe candidates through ProjectDiscovery httpx JSONL output."""
    argv = ["httpx", "-silent", "-json", "-status-code", "-title", "-tech-detect", "-cdn", "-ip", "-no-color"]
    stdin_text = "\n".join(c.host for c in candidates) + "\n"
    opts = RunOptions(timeout=float(ctx.config.timeout_for("httpx")), input_text=stdin_text)
    live: list[Host] = []
    total = len(candidates)
    async for line in stream_lines(argv, opts):
        host = _host_from_httpx_line(line)
        if host is None or not ctx.scope.in_scope(host.host):
            continue
        live.append(host)
        await bus.stage_progress(STAGE, len(live), total)
    return live


async def _probe_with_python_httpx(ctx: ScanContext, bus: EventBus, candidates: list[Host]) -> list[Host]:
    """Fallback: one GET per host via the python httpx library."""
    cap = ctx.scale(FALLBACK_HOST_CAP, FALLBACK_HOST_CAP_DEEP)
    capped = candidates[:cap]
    await bus.log(
        f"PD httpx not installed; falling back to built-in probing ({len(capped)}/{len(candidates)} host(s)).",
        LogLevel.WARN,
    )
    limiter = RateLimiter(float(ctx.rate_limit))
    sem = asyncio.Semaphore(FALLBACK_CONCURRENCY)
    default_scheme = urlsplit(ctx.target_url).scheme or "https"
    results: list[Host] = []
    done = 0

    async with make_http_client(ctx, follow_redirects=True, timeout=FALLBACK_TIMEOUT, verify=False) as client:

        async def probe(candidate: Host) -> None:
            nonlocal done
            await limiter.acquire()
            async with sem:
                result = await _single_probe(client, candidate, default_scheme)
            done += 1
            if result is not None and ctx.scope.in_scope(result.host):
                results.append(result)
            await bus.stage_progress(STAGE, done, len(capped))

        await asyncio.gather(*(probe(c) for c in capped), return_exceptions=True)
    return results


async def _single_probe(client: httpx.AsyncClient, candidate: Host, default_scheme: str) -> Host | None:
    """GET one candidate URL; return an enriched live Host or None on failure.

    A discovered subdomain carries only its name, so it is tried with the
    target's scheme first and then the opposite one — a host that serves only
    plain HTTP (or only HTTPS) would otherwise be written off as dead.
    """
    if candidate.url:
        urls = [candidate.url]
    else:
        alternate = "http" if default_scheme == "https" else "https"
        urls = [f"{default_scheme}://{candidate.host}", f"{alternate}://{candidate.host}"]
    for url in urls:
        try:
            resp = await client.get(url)
        except httpx.HTTPError:
            continue
        return Host(
            host=candidate.host,
            url=str(resp.url),
            status_code=resp.status_code,
            title=_extract_title(resp.text),
            server=resp.headers.get("server"),
            content_length=len(resp.content),
            scheme=resp.url.scheme,
            port=resp.url.port,
            is_live=True,
            source="httpx-fallback",
        )
    return None


def _host_from_httpx_line(line: str) -> Host | None:
    """Map one PD httpx JSONL record onto a live Host."""
    try:
        raw: object = json.loads(line)
    except json.JSONDecodeError:
        return None
    if not isinstance(raw, dict):
        return None
    url = raw.get("url")
    if not isinstance(url, str) or not url:
        return None
    parts = urlsplit(url)
    raw_host = raw.get("host")
    name = raw_host if isinstance(raw_host, str) and raw_host else (parts.hostname or "")
    if not name:
        return None
    tech_list = raw.get("tech")
    tech = [item for item in tech_list if isinstance(item, str)] if isinstance(tech_list, list) else []
    server_raw = raw.get("webserver") or raw.get("server")
    return Host(
        host=name,
        url=url,
        ip=_opt_str(raw.get("ip")),
        port=_opt_int(raw.get("port")) or parts.port,
        scheme=parts.scheme or _opt_str(raw.get("scheme")),
        status_code=_opt_int(raw.get("status_code")),
        title=_opt_str(raw.get("title")),
        server=server_raw if isinstance(server_raw, str) else None,
        content_length=_opt_int(raw.get("content_length")),
        tech=tech,
        cdn=isinstance(raw.get("cdn"), bool) and bool(raw.get("cdn")),
        is_live=True,
        source="httpx",
    )


def _opt_str(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


def _opt_int(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def _extract_title(body: str) -> str | None:
    match = _TITLE_RE.search(body[:200_000])
    if match is None:
        return None
    title = html_lib.unescape(match.group(1)).strip()
    return title[:200] or None


def _bare_host(target: str) -> str:
    if target.startswith("["):
        end = target.find("]")
        return target[1:end] if end != -1 else target
    head, sep, tail = target.rpartition(":")
    if sep and tail.isdigit():
        return head
    return target


def _is_bare_ip(host: str) -> bool:
    return not any(ch.isascii() and ch.isalpha() for ch in host)


def _parse_host_port(line: str) -> tuple[str, int] | None:
    text = line.strip()
    if not text or text.count(":") != 1:
        return None
    host, _, port_text = text.partition(":")
    if not host or not port_text.isdigit():
        return None
    return host, int(port_text)


def _match_host(ctx: ScanContext, key: str) -> Host | None:
    direct = ctx.hosts.get(key)
    if direct is not None:
        return direct
    for host in ctx.hosts.values():
        if host.ip == key:
            return host
    return None
