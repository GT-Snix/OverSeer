from datetime import datetime

from pydantic import BaseModel, HttpUrl


class Advisory(BaseModel):
    """Normalized security advisory, independent of its original source format."""

    product_name: str
    product_version: str = "NA"
    oem_name: str
    severity: str
    unique_id: str
    description: str
    mitigation: str = "N/A - Pending Vendor Patch"
    published_date: datetime
    source_url: HttpUrl
    needs_review: bool = False
    """True when no CVSS score could be found and severity is a manual-review placeholder."""
