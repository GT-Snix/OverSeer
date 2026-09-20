import feedparser

from overseer.collector.base import RawAdvisory, SourceAdapter

CISA_ICS_FEED_URL = "https://www.cisa.gov/cybersecurity-advisories/ics-advisories.xml"


class CISAICSAdapter(SourceAdapter):
    """Pulls raw advisories from CISA's ICS advisories RSS feed."""

    SOURCE_NAME = "CISA ICS"

    def __init__(self, feed_url: str = CISA_ICS_FEED_URL):
        self.feed_url = feed_url

    def fetch(self) -> list[RawAdvisory]:
        parsed = feedparser.parse(self.feed_url)
        return [self._to_raw_advisory(entry) for entry in parsed.entries]

    def _to_raw_advisory(self, entry) -> RawAdvisory:
        tags = [tag.get("term") for tag in entry.get("tags", [])] if entry.get("tags") else []
        return RawAdvisory(
            source_name=self.SOURCE_NAME,
            raw_id=entry.get("id", entry.get("link", "")),
            raw_title=entry.get("title", ""),
            raw_summary=entry.get("summary", ""),
            raw_published=entry.get("published", ""),
            raw_link=entry.get("link", ""),
            extra={"tags": tags} if tags else {},
        )
