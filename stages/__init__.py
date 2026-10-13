"""Pipeline stages.

Every module in this package exposes one entry point:

    async def run(ctx: ScanContext, bus: EventBus) -> None

Contract every stage follows:

* Never raise. External tools fail, time out, or are missing; a stage reports
  the problem through the bus and returns. The orchestrator wraps calls as a
  backstop, but a stage should degrade on its own.
* Respect scope. Any host or URL is checked with ``ctx.scope.in_scope(...)``
  before it is touched; out-of-scope discovered hosts are skipped silently.
* Target access. ``ctx.target`` is the canonical ``host[:port]`` form (pass it
  to tools that accept a host). ``ctx.target_url`` is the scheme-qualified base
  URL (use it for Shaidra's own HTTP probes). ``ctx.live_hosts()`` returns the
  hosts httpx confirmed reachable. ``ctx.crawled_urls`` holds URLs discovered
  by the crawl stage for later XSS/redirect checks.
* Check tools first. Use ``ctx.has_tool("nuclei")``; when a tool is missing,
  call ``await bus.stage_skip(name, "nuclei not installed")`` and return instead
  of warning loudly.
* Stream findings immediately with ``await bus.finding(Finding(...))``. Never
  batch findings until the end.
* Report lifecycle with ``bus.stage_start`` / ``bus.stage_progress`` /
  ``bus.stage_done`` so the renderer can drive the progress bars.
* Run external tools through ``shaidra.utils.process`` (``run_tool`` for
  captured output, ``stream_lines`` for streaming JSONL) and use
  ``shaidra.utils.rate_limiter.RateLimiter`` for Shaidra's own HTTP probes.
"""
