import re
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

from bs4 import BeautifulSoup
from cvss import CVSS3

from overseer.collector.base import RawAdvisory
from overseer.parser.schema import Advisory

HIGH_SEVERITY_THRESHOLD = 7.0
UNSCORED_SEVERITY = "UNSCORED - Manual Review"

ICSA_ID_RE = re.compile(r"\bICSA-\d{2}-\d{3}-\d{2}\b")

# A full vector string, e.g. "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".
CVSS_FULL_VECTOR_RE = re.compile(r"CVSS:3\.[01]/[A-Za-z:/]+[A-Za-z]")

# CISA prose often states the metrics without the "CVSS:3.x/" header, e.g.
# "the CVSS vector string is (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)".
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
        return CVSS3(vector).base_score
    except Exception:
        return None


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

    full_vector_match = CVSS_FULL_VECTOR_RE.search(clean_summary)
    if full_vector_match:
        score = _score_from_vector(full_vector_match.group(0))
        if score is not None:
            return score

    bare_metrics_match = CVSS_BARE_METRICS_RE.search(clean_summary)
    if bare_metrics_match:
        score = _score_from_vector(f"CVSS:3.1/{bare_metrics_match.group(0)}")
        if score is not None:
            return score

    score_match = CVSS_SCORE_PROSE_RE.search(clean_summary)
    if score_match:
        try:
            return float(score_match.group(1))
        except ValueError:
            pass

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
    for candidate in (raw.raw_title, raw.raw_id, raw.raw_link):
        match = ICSA_ID_RE.search(candidate or "")
        if match:
            return match.group(0)
    return raw.raw_id or raw.raw_link


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
