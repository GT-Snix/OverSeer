from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass
class RawAdvisory:
    """Unvalidated advisory data exactly as scraped from a source.

    No CVSS parsing, severity filtering, or field normalization has
    happened yet -- that's the parser stage's job. Fields are kept as
    raw strings because the source may omit or malform any of them.
    """

    source_name: str
    raw_id: str
    raw_title: str
    raw_summary: str
    raw_published: str
    raw_link: str
    extra: dict = field(default_factory=dict)


class SourceAdapter(ABC):
    """Base class for anything that can pull raw advisories from a source."""

    @abstractmethod
    def fetch(self) -> list[RawAdvisory]:
        ...
