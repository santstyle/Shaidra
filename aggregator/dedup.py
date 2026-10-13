"""Cross-tool duplicate collapsing for aggregated findings.

Identity is a stable key derived from the Finding fields that describe WHAT
and WHERE a problem is (category, host, title, matched URL, template or
reference id). The producing tool, severity, evidence, and timestamp are
deliberately excluded: they vary between duplicate reports of one issue.
"""

from __future__ import annotations

from shaidra.core.models import SEVERITY_RANK, Finding

FindingKey = tuple[str, str, str, str, str]


def finding_key(finding: Finding) -> FindingKey:
    """Build the identity key used to detect duplicate findings.

    The slots are category, host, normalized title, matched URL, and the
    template/reference identifier. Text slots are stripped (host and title
    casefolded) so cosmetic differences do not defeat deduplication.
    """
    return (
        finding.category.value,
        finding.host.strip().casefold(),
        finding.title.strip().casefold(),
        (finding.url or "").strip(),
        finding.template or finding.reference or "",
    )


def dedup_findings(findings: list[Finding]) -> list[Finding]:
    """Collapse duplicate findings, keeping the most informative of each group.

    Duplicates share a ``finding_key``; among them the highest severity wins,
    ties are broken by the richer evidence/description text, and a final tie
    keeps the first-seen finding. The result preserves first-seen key order
    and never mutates the input list.
    """
    kept: dict[FindingKey, Finding] = {}
    for finding in findings:
        key = finding_key(finding)
        incumbent = kept.get(key)
        if incumbent is None or _more_informative(finding, incumbent):
            kept[key] = finding
    return list(kept.values())


def _more_informative(candidate: Finding, incumbent: Finding) -> bool:
    """Decide whether candidate should replace incumbent for the same key.

    Higher severity wins first; ties go to the richer evidence/description
    text, and a full tie keeps the incumbent (first-seen) finding.
    """
    rank = SEVERITY_RANK[candidate.severity]
    held_rank = SEVERITY_RANK[incumbent.severity]
    detail = len(candidate.evidence.strip()) + len(candidate.description.strip())
    held_detail = len(incumbent.evidence.strip()) + len(incumbent.description.strip())
    return (rank, detail) > (held_rank, held_detail)
