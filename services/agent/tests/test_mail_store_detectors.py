"""Deterministic mail-store detectors over parsed Outlook/OE message envelopes.

The mail store is an artifact class the engine could not see at all before
``pst_parse``: the Outlook Express lane was mount-gated and DBX-only, so a
rootless run over a disk image whose mail lives in a PST had zero mail coverage.

These detectors are pure header comparisons over whatever ``pst_parse`` /
``oe_dbx_parse`` actually returned. They must key on general mail signatures
(Reply-To divergence, display-name reuse, attachment media type, thread
grouping) and never on a specific image's names, domains, or subjects.
"""

from __future__ import annotations

import sys
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parents[3] / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import find_evil_auto as fea  # noqa: E402

INTERNAL = "corp.example"
OUTSIDE = "mailhost.example"


def _msg(**over):
    base = {
        "folder": "Inbox",
        "subject": "hello",
        "from_display": "",
        "from_address": f"staff@{INTERNAL}",
        "reply_to_display": "",
        "reply_to_address": "",
        "to": [f"cfo@{INTERNAL}"],
        "date": "Tue, 15 Jul 2008 09:12:44 -0700",
        "attachments": [],
    }
    base.update(over)
    return base


class TestInternalDomain:
    def test_most_frequent_domain_across_the_store_is_the_internal_one(self) -> None:
        msgs = [
            _msg(),
            _msg(from_address=f"a@{INTERNAL}", to=[f"b@{INTERNAL}"]),
            _msg(from_address=f"x@{OUTSIDE}", to=[f"cfo@{INTERNAL}"]),
        ]
        assert fea.mail_internal_domains(msgs) == {INTERNAL}

    def test_empty_store_has_no_internal_domain(self) -> None:
        assert fea.mail_internal_domains([]) == set()


class TestReplyToDivergence:
    def test_reply_to_on_a_different_domain_is_a_divergence(self) -> None:
        msgs = [
            _msg(
                from_address=f"boss@{INTERNAL}",
                reply_to_address=f"boss@{OUTSIDE}",
                subject="urgent request",
            )
        ]
        rows = fea.mail_reply_to_divergence(msgs)
        assert len(rows) == 1
        assert rows[0]["from_address"] == f"boss@{INTERNAL}"
        assert rows[0]["reply_to_address"] == f"boss@{OUTSIDE}"
        assert rows[0]["domain_divergent"] is True
        assert rows[0]["subject"] == "urgent request"

    def test_same_address_in_both_headers_is_not_a_divergence(self) -> None:
        assert fea.mail_reply_to_divergence([_msg(reply_to_address=f"staff@{INTERNAL}")]) == []

    def test_case_and_whitespace_differences_alone_are_not_a_divergence(self) -> None:
        msgs = [_msg(from_address="Staff@Corp.Example", reply_to_address=" staff@corp.example ")]
        assert fea.mail_reply_to_divergence(msgs) == []

    def test_absent_reply_to_is_not_a_divergence(self) -> None:
        assert fea.mail_reply_to_divergence([_msg()]) == []

    def test_same_domain_different_mailbox_is_flagged_but_not_domain_divergent(self) -> None:
        msgs = [
            _msg(
                from_address=f"boss@{INTERNAL}",
                reply_to_address=f"assistant@{INTERNAL}",
            )
        ]
        rows = fea.mail_reply_to_divergence(msgs)
        assert len(rows) == 1
        assert rows[0]["domain_divergent"] is False


class TestImpersonation:
    def test_display_name_of_an_internal_principal_sent_from_outside(self) -> None:
        msgs = [
            # the real internal principal, so the display name is known-internal
            _msg(from_display="Pat Morgan", from_address=f"pat.morgan@{INTERNAL}"),
            # the impersonating message: same display name, outside address
            _msg(
                from_display="Pat Morgan",
                from_address=f"pat.morgan@{OUTSIDE}",
                subject="urgent request",
            ),
        ]
        rows = fea.mail_impersonation_candidates(msgs, {INTERNAL})
        assert len(rows) == 1
        assert rows[0]["display_name"] == "Pat Morgan"
        assert rows[0]["from_address"] == f"pat.morgan@{OUTSIDE}"
        assert rows[0]["basis"] == "internal_display_name_external_sender"

    def test_internal_from_with_external_reply_to_is_an_impersonation_candidate(self) -> None:
        msgs = [
            _msg(
                from_display="Pat Morgan",
                from_address=f"pat.morgan@{INTERNAL}",
                reply_to_address=f"pat.morgan@{OUTSIDE}",
            )
        ]
        rows = fea.mail_impersonation_candidates(msgs, {INTERNAL})
        assert len(rows) == 1
        assert rows[0]["basis"] == "internal_sender_external_reply_to"

    def test_ordinary_internal_mail_is_not_an_impersonation_candidate(self) -> None:
        msgs = [_msg(from_display="Pat Morgan", from_address=f"pat.morgan@{INTERNAL}")]
        assert fea.mail_impersonation_candidates(msgs, {INTERNAL}) == []

    def test_ordinary_external_mail_from_an_unknown_name_is_not_a_candidate(self) -> None:
        msgs = [_msg(from_display="Newsletter", from_address=f"news@{OUTSIDE}")]
        assert fea.mail_impersonation_candidates(msgs, {INTERNAL}) == []


class TestSpreadsheetEgress:
    def _sent(self, **over):
        base = {
            "folder": "Personal Folders/Sent Items",
            "from_address": f"cfo@{INTERNAL}",
            "to": [f"outsider@{OUTSIDE}"],
            "subject": "as requested",
            "attachments": [{"name": "staff-roster.xls", "extension": "xls", "content_type": ""}],
        }
        base.update(over)
        return _msg(**base)

    def test_spreadsheet_attachment_to_an_external_recipient_is_a_candidate(self) -> None:
        rows = fea.mail_attachment_egress_candidates([self._sent()], {INTERNAL})
        assert len(rows) == 1
        assert rows[0]["attachment"] == "staff-roster.xls"
        assert rows[0]["external_recipients"] == [f"outsider@{OUTSIDE}"]
        assert rows[0]["folder"] == "Personal Folders/Sent Items"

    def test_media_type_alone_identifies_a_spreadsheet(self) -> None:
        msg = self._sent(
            attachments=[
                {
                    "name": "roster",
                    "extension": "",
                    "content_type": "application/vnd.ms-excel",
                }
            ]
        )
        assert len(fea.mail_attachment_egress_candidates([msg], {INTERNAL})) == 1

    def test_same_spreadsheet_to_an_internal_recipient_only_is_not_a_candidate(self) -> None:
        msg = self._sent(to=[f"hr@{INTERNAL}"])
        assert fea.mail_attachment_egress_candidates([msg], {INTERNAL}) == []

    def test_non_spreadsheet_attachment_is_not_a_candidate(self) -> None:
        msg = self._sent(
            attachments=[{"name": "logo.png", "extension": "png", "content_type": "image/png"}]
        )
        assert fea.mail_attachment_egress_candidates([msg], {INTERNAL}) == []

    def test_inbound_spreadsheet_from_outside_is_not_egress(self) -> None:
        msg = self._sent(
            folder="Inbox",
            from_address=f"outsider@{OUTSIDE}",
            to=[f"cfo@{INTERNAL}"],
        )
        assert fea.mail_attachment_egress_candidates([msg], {INTERNAL}) == []


class TestThreadEscalation:
    def _thread(self, n: int, *, diverging: bool) -> list[dict]:
        out = []
        for i in range(n):
            prefix = "" if i == 0 else "RE: "
            out.append(
                _msg(
                    subject=f"{prefix}urgent request",
                    from_address=f"outsider@{OUTSIDE}" if i % 2 == 0 else f"cfo@{INTERNAL}",
                    to=[f"cfo@{INTERNAL}"] if i % 2 == 0 else [f"outsider@{OUTSIDE}"],
                    reply_to_address=(f"other@{OUTSIDE}" if diverging and i % 2 == 0 else ""),
                    date=f"Tue, 1{i} Jul 2008 09:12:44 -0700",
                )
            )
        return out

    def test_multi_message_thread_with_an_external_counterparty_escalates(self) -> None:
        rows = fea.mail_thread_escalation(self._thread(4, diverging=True), {INTERNAL})
        assert len(rows) == 1
        assert rows[0]["thread"] == "urgent request"
        assert rows[0]["message_count"] == 4
        assert rows[0]["diverging_message_count"] == 2
        assert f"outsider@{OUTSIDE}" in rows[0]["external_participants"]

    def test_re_and_fwd_prefixes_collapse_into_one_thread(self) -> None:
        msgs = [
            _msg(subject="Quarterly numbers", from_address=f"a@{OUTSIDE}"),
            _msg(subject="RE: Quarterly numbers", from_address=f"a@{OUTSIDE}"),
            _msg(subject="Fwd: RE: Quarterly numbers", from_address=f"a@{OUTSIDE}"),
        ]
        rows = fea.mail_thread_escalation(msgs, {INTERNAL})
        assert len(rows) == 1
        assert rows[0]["thread"] == "quarterly numbers"
        assert rows[0]["message_count"] == 3

    def test_a_two_message_exchange_is_below_the_thread_floor(self) -> None:
        assert fea.mail_thread_escalation(self._thread(2, diverging=True), {INTERNAL}) == []

    def test_a_purely_internal_thread_does_not_escalate(self) -> None:
        msgs = [
            _msg(subject=f"{p}status", from_address=f"a@{INTERNAL}", to=[f"b@{INTERNAL}"])
            for p in ("", "RE: ", "RE: RE: ")
        ]
        assert fea.mail_thread_escalation(msgs, {INTERNAL}) == []


class TestMailStoreRouting:
    def test_pst_and_ost_route_to_pst_parse_and_dbx_routes_to_oe_dbx_parse(self) -> None:
        assert fea.mail_store_tool_for("/x/mail_store/Outlook/outlook.pst") == "pst_parse"
        assert fea.mail_store_tool_for("/x/mail_store/Outlook/ARCHIVE.OST") == "pst_parse"
        assert fea.mail_store_tool_for("/x/mail_store/OE/Inbox.dbx") == "oe_dbx_parse"

    def test_an_unknown_extension_is_not_routed(self) -> None:
        assert fea.mail_store_tool_for("/x/mail_store/notes.txt") is None
