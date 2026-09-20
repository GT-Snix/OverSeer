import re
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

from bs4 import BeautifulSoup
from cvss import CVSS3, CVSS4

from overseer.collector.base import RawAdvisory
from overseer.parser.schema import Advisory

HIGH_SEVERITY_THRESHOLD = 7.0
UNSCORED_SEVERITY = "UNSCORED - Manual Review"

ICSA_ID_RE = re.compile(r"\bICSA-\d{2}-\d{3}-\d{2}\b", re.IGNORECASE)

# Full vector strings, e.g. "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
# and "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N".
# v3.x and v4.0 use different metric groups (and different score classes
# below), so they're matched and scored separately.
CVSS_V3_VECTOR_RE = re.compile(r"CVSS:3\.[01]/[A-Za-z:/]+[A-Za-z]")
CVSS_V4_VECTOR_RE = re.compile(r"CVSS:4\.0/[A-Za-z:/]+[A-Za-z0-9]")

# CISA prose often states the v3 metrics without the "CVSS:3.x/" header,
# e.g. "the CVSS vector string is (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)".
CVSS_BARE_METRICS_RE = re.compile(
    r"AV:[NAL]/AC:[LH]/PR:[NLH]/UI:[NR]/S:[UC]/C:[NLH]/I:[NLH]/A:[NLH]"
)

# A plain numeric score in prose, e.g. "CVSS v3.1 base score of 9.8".
CVSS_SCORE_PROSE_RE = re.compile(
    r"CVSS\s*v?3(?:\.[01])?\s*(?:base\s*)?score[^0-9]{0,15}(\d{1,2}(?:\.\d)?)",
    re.IGNORECASE,
)


def _strip_html(text: str) -> str:
    return BeautifulSoup(text or "", "html.parser").get_text(separator=" ", strip=True)


def _score_from_vector(vector: str) -> float | None:
    try:
        if vector.startswith("CVSS:4.0"):
            return CVSS4(vector).base_score
        return CVSS3(vector).base_score
    except Exception:
        return None


def _all_text_scores(text: str) -> list[float]:
    """All CVSS scores found in free text, across every vector present.

    An advisory can bundle several CVEs, each with its own vector (and
    each vector can appear in both v3.x and v4.0 form for the same CVE).
    Rather than taking the first match in document order -- which
    silently picks an arbitrary CVE's score -- this collects every full
    vector match (v3.x and v4.0) and lets the caller take the max, so a
    bundled advisory is scored by its worst vulnerability. Bare-metrics
    and prose fallbacks only kick in when no full vector was found at
    all, since those are less reliable than a real vector string.
    """
    scores: list[float] = []

    for match in CVSS_V3_VECTOR_RE.finditer(text):
        score = _score_from_vector(match.group(0))
        if score is not None:
            scores.append(score)

    for match in CVSS_V4_VECTOR_RE.finditer(text):
        score = _score_from_vector(match.group(0))
        if score is not None:
            scores.append(score)

    if scores:
        return scores

    for match in CVSS_BARE_METRICS_RE.finditer(text):
        score = _score_from_vector(f"CVSS:3.1/{match.group(0)}")
        if score is not None:
            scores.append(score)

    if scores:
        return scores

    for match in CVSS_SCORE_PROSE_RE.finditer(text):
        try:
            scores.append(float(match.group(1)))
        except ValueError:
            pass

    return scores


def _extract_cvss_score(raw: RawAdvisory, clean_summary: str) -> float | None:
    extra = raw.extra or {}

    if extra.get("cvss_score") is not None:
        try:
            return float(extra["cvss_score"])
        except (TypeError, ValueError):
            pass

    if extra.get("cvss_vector"):
        score = _score_from_vector(extra["cvss_vector"])
        if score is not None:
            return score

    scores = _all_text_scores(clean_summary)
    if scores:
        return max(scores)

    return None


def _severity_label(score: float) -> str:
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    return "Low"


def _extract_unique_id(raw: RawAdvisory) -> str:
    # The ID often isn't in the title at all in current CISA feeds -- it
    # only shows up (lowercase) as the last path segment of the link, e.g.
    # link=".../icsa-26-260-07" while id="/node/25507" and the title is
    # just the vendor/product name. Check link before the raw id/guid,
    # which can be a bare relative Drupal path unsafe to use as a filename.
    for candidate in (raw.raw_title, raw.raw_link, raw.raw_id):
        match = ICSA_ID_RE.search(candidate or "")
        if match:
            return match.group(0).upper()

    # No canonical ICSA-##-###-## found anywhere: fall back to a
    # filesystem-safe slug instead of a raw id/link that may contain "/".
    fallback = raw.raw_link or raw.raw_id or raw.raw_title or "UNKNOWN"
    slug = fallback.rstrip("/").rsplit("/", 1)[-1]
    return slug or "UNKNOWN"


def _split_oem_and_product(raw: RawAdvisory, unique_id: str) -> tuple[str, str]:
    """Best-effort split of "<ID> <Vendor> <Product...>" titles.

    CISA doesn't cleanly separate vendor from product in the RSS title, so
    this takes the first remaining word as the vendor. It's a heuristic,
    not a reliable vendor lookup.
    """
    title = raw.raw_title or ""
    remainder = title.replace(unique_id, "", 1).strip(" :-")
    if not remainder:
        return "Unknown", title or "Unknown"
    parts = remainder.split(" ", 1)
    if len(parts) == 2:
        return parts[0], parts[1]
    return "Unknown", remainder


def _parse_published_date(raw_published: str) -> datetime:
    try:
        parsed = parsedate_to_datetime(raw_published)
        if parsed is not None:
            return parsed
    except (TypeError, ValueError):
        pass
    return datetime.now(timezone.utc)


def normalize(raw: RawAdvisory) -> Advisory | None:
    """Normalize a RawAdvisory into a validated Advisory, or None if filtered out.

    Routing:
      - CVSS score found and >= 7.0 (High/Critical): kept.
      - CVSS score found and < 7.0: filtered out (returns None).
      - No CVSS score found anywhere (raw.extra or raw_summary): NOT dropped.
        Kept with severity="UNSCORED - Manual Review" and needs_review=True
        on the Advisory, so the caller can route it to a manual review
        queue instead of silently discarding low-confidence entries.
    """
    clean_summary = _strip_html(raw.raw_summary)
    score = _extract_cvss_score(raw, clean_summary)

    if score is not None and score < HIGH_SEVERITY_THRESHOLD:
        return None

    unique_id = _extract_unique_id(raw)
    oem_name, product_name = _split_oem_and_product(raw, unique_id)
    published_date = _parse_published_date(raw.raw_published)

    if score is not None:
        severity = _severity_label(score)
        needs_review = False
    else:
        severity = UNSCORED_SEVERITY
        needs_review = True

    return Advisory(
        product_name=product_name,
        oem_name=oem_name,
        severity=severity,
        unique_id=unique_id,
        description=clean_summary,
        published_date=published_date,
        source_url=raw.raw_link,
        needs_review=needs_review,
    )
