from overseer.collector.cisa_ics import CISAICSAdapter

# A static snapshot of CISA's ICS advisories RSS shape. Feeding real XML
# content (rather than a URL) straight into feedparser.parse() exercises
# the actual parsing logic without hitting the network or depending on
# feed content that changes daily.
SAMPLE_FEED_XML = """<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <title>All ICS Advisories</title>
    <link>https://www.cisa.gov/cybersecurity-advisories/ics-advisories</link>
    <description>CISA ICS Advisories</description>
    <item>
      <title>ICSA-26-263-01 Acme Widget Controller</title>
      <link>https://www.cisa.gov/news-events/ics-advisories/icsa-26-263-01</link>
      <description>CISA is aware of a public report of a vulnerability affecting the Acme Widget Controller.</description>
      <pubDate>Thu, 18 Sep 2026 12:00:00 +0000</pubDate>
      <guid isPermaLink="true">https://www.cisa.gov/news-events/ics-advisories/icsa-26-263-01</guid>
    </item>
    <item>
      <title>ICSA-26-262-05 Beta Systems PLC</title>
      <link>https://www.cisa.gov/news-events/ics-advisories/icsa-26-262-05</link>
      <description>CISA is aware of a public report affecting Beta Systems PLC.</description>
      <pubDate>Wed, 17 Sep 2026 09:30:00 +0000</pubDate>
      <guid isPermaLink="true">https://www.cisa.gov/news-events/ics-advisories/icsa-26-262-05</guid>
    </item>
  </channel>
</rss>
"""


def test_fetch_maps_feed_entries_to_raw_advisory():
    adapter = CISAICSAdapter(feed_url=SAMPLE_FEED_XML)

    results = adapter.fetch()

    assert len(results) == 2

    first = results[0]
    assert first.source_name == "CISA ICS"
    assert first.raw_title == "ICSA-26-263-01 Acme Widget Controller"
    assert first.raw_link == "https://www.cisa.gov/news-events/ics-advisories/icsa-26-263-01"
    assert "Acme Widget Controller" in first.raw_summary
    assert first.raw_published == "Thu, 18 Sep 2026 12:00:00 +0000"
    assert first.raw_id == "https://www.cisa.gov/news-events/ics-advisories/icsa-26-263-01"

    second = results[1]
    assert second.raw_title == "ICSA-26-262-05 Beta Systems PLC"


def test_fetch_returns_empty_list_for_empty_feed():
    empty_feed = """<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0"><channel><title>Empty</title></channel></rss>
"""
    adapter = CISAICSAdapter(feed_url=empty_feed)

    assert adapter.fetch() == []
