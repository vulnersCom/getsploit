from __future__ import annotations

from getsploit.models import Exploit


def test_content_prefers_source_data(exploit: Exploit) -> None:
    assert exploit.content == "print('source')"


def test_content_falls_back_to_description() -> None:
    exploit = Exploit("ID", "title", "url", description="description")
    assert exploit.content == "description"
