import os

import httpx

from overseer.collector.base import RawAdvisory, SourceAdapter

TOKEN_URL = "https://id.cisco.com/oauth2/default/v1/token"
ADVISORIES_URL = "https://api.cisco.com/security/advisories/v2/all"


class CiscoAdapter(SourceAdapter):
    """Pulls raw advisories from Cisco's PSIRT openVuln API (structured JSON).

    Requires OAuth2 client-credentials from environment variables
    CISCO_CLIENT_ID / CISCO_CLIENT_SECRET -- never hardcoded. Credentials
    are read (but not validated) at construction time so that simply
    importing/instantiating this adapter -- e.g. building the CLI's
    ADAPTERS list at module load -- doesn't blow up commands that never
    call fetch(). The clear failure happens in fetch() itself.
    """

    SOURCE_NAME = "Cisco PSIRT"

    def __init__(
        self,
        client_id: str | None = None,
        client_secret: str | None = None,
        advisories_url: str = ADVISORIES_URL,
        token_url: str = TOKEN_URL,
        http_client: httpx.Client | None = None,
    ):
        self.client_id = client_id or os.environ.get("CISCO_CLIENT_ID")
        self.client_secret = client_secret or os.environ.get("CISCO_CLIENT_SECRET")
        self.advisories_url = advisories_url
        self.token_url = token_url
        self._http_client = http_client

    def _require_credentials(self) -> None:
        missing = [
            name
            for name, value in (
                ("CISCO_CLIENT_ID", self.client_id),
                ("CISCO_CLIENT_SECRET", self.client_secret),
            )
            if not value
        ]
        if missing:
            raise RuntimeError(
                "CiscoAdapter is missing required credentials: "
                f"{', '.join(missing)}. Set them as environment variables "
                "(CISCO_CLIENT_ID, CISCO_CLIENT_SECRET) before running "
                "`overseer run`."
            )

    def _get_access_token(self, client: httpx.Client) -> str:
        response = client.post(
            self.token_url,
            data={
                "grant_type": "client_credentials",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
            },
        )
        response.raise_for_status()
        return response.json()["access_token"]

    def fetch(self) -> list[RawAdvisory]:
        self._require_credentials()

        client = self._http_client or httpx.Client(timeout=30)
        owns_client = self._http_client is None
        try:
            token = self._get_access_token(client)
            response = client.get(
                self.advisories_url,
                headers={"Authorization": f"Bearer {token}"},
            )
            response.raise_for_status()
            payload = response.json()
        finally:
            if owns_client:
                client.close()

        return [self._to_raw_advisory(item) for item in payload.get("advisories", [])]

    def _to_raw_advisory(self, item: dict) -> RawAdvisory:
        return RawAdvisory(
            source_name=self.SOURCE_NAME,
            raw_id=item.get("advisoryId", ""),
            raw_title=item.get("advisoryTitle", ""),
            raw_summary=item.get("summary", ""),
            raw_published=item.get("firstPublished", ""),
            raw_link=item.get("publicationUrl", ""),
            extra={
                # Clean numeric score straight from the API -- this is
                # what lets normalize() skip prose parsing entirely for
                # this source (see extra["cvss_score"] handling there).
                "cvss_score": item.get("cvssBaseScore"),
                "cves": item.get("cves", []),
                "bug_ids": item.get("bugIDs", []),
                "security_impact_rating": item.get("securityImpactRating"),
                "product_names": item.get("productNames", []),
                "cvrf_url": item.get("cvrfUrl"),
                "status": item.get("status"),
                "version": item.get("version"),
            },
        )
