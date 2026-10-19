"""Unit tests for webhook notifications (--notify) for Discord and Slack."""

import io
import json
import unittest
from unittest.mock import MagicMock, patch

from reconflow import notify


class TestWebhookNotification(unittest.TestCase):
    """Test suite for webhook delivery logic and security constraints."""

    def test_insecure_http_rejected(self):
        """Webhooks over plaintext HTTP must be rejected immediately."""
        with patch("sys.stderr", new_callable=io.StringIO) as mock_err:
            res = notify.send_webhook("http://hooks.slack.com/services/123", "test")
            self.assertFalse(res)
            self.assertIn("must use HTTPS", mock_err.getvalue())

    def test_discord_payload_formatting(self):
        """Discord webhooks must use the 'content' JSON key."""
        mock_resp = MagicMock()
        mock_resp.status = 204
        mock_resp.__enter__.return_value = mock_resp
        mock_resp.__exit__.return_value = None

        captured_requests = []

        def fake_open(req, timeout=None):
            captured_requests.append(req)
            return mock_resp

        url = "https://discord.com/api/webhooks/123/token"
        res = notify.send_webhook(url, "Diff detected", opener=fake_open)

        self.assertTrue(res)
        self.assertEqual(len(captured_requests), 1)
        req = captured_requests[0]
        self.assertEqual(req.full_url, url)
        payload = json.loads(req.data.decode("utf-8"))
        self.assertIn("content", payload)
        self.assertIn("Diff detected", payload["content"])

    def test_slack_payload_formatting(self):
        """Slack webhooks must use the 'text' JSON key."""
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.__enter__.return_value = mock_resp
        mock_resp.__exit__.return_value = None

        captured_requests = []

        def fake_open(req, timeout=None):
            captured_requests.append(req)
            return mock_resp

        url = "https://hooks.slack.com/services/T00/B00/X00"
        res = notify.send_webhook(url, "Diff detected", opener=fake_open)

        self.assertTrue(res)
        self.assertEqual(len(captured_requests), 1)
        req = captured_requests[0]
        payload = json.loads(req.data.decode("utf-8"))
        self.assertIn("text", payload)
        self.assertEqual(payload["text"], "Diff detected")

    def test_discord_2000_char_splitting(self):
        """Messages exceeding Discord's limit must be cleanly chunked."""
        long_message = "Line of text\n" * 300  # ~3900 chars
        self.assertGreater(len(long_message), 2000)

        chunks = notify.chunk_message_for_discord(long_message, max_chunk=1000)
        self.assertGreater(len(chunks), 1)
        for chunk in chunks:
            self.assertLessEqual(len(chunk), 1000)

    def test_webhook_failure_fails_gracefully_without_leaking_url(self):
        """Network or HTTP errors fail gracefully without leaking secrets in logs."""
        secret_url = "https://discord.com/api/webhooks/999/super_secret_token_12345"

        def failing_open(req, timeout=None):
            raise OSError("Connection timed out")

        with patch("sys.stderr", new_callable=io.StringIO) as mock_err:
            res = notify.send_webhook(secret_url, "Message", opener=failing_open)
            err_output = mock_err.getvalue()

        self.assertFalse(res)
        self.assertIn("Webhook delivery failed", err_output)
        # CRITICAL: Webhook secret token must NEVER be exposed
        self.assertNotIn("super_secret_token_12345", err_output)

    def test_resolve_webhook_url_precedence(self):
        """resolve_webhook_url follows explicit > RECONFLOW > DISCORD > SLACK precedence."""
        self.assertEqual(notify.resolve_webhook_url("https://custom.hook"), "https://custom.hook")

        with patch.dict("os.environ", {"RECONFLOW_WEBHOOK_URL": "https://reconflow.hook"}):
            self.assertEqual(notify.resolve_webhook_url(), "https://reconflow.hook")

        with patch.dict(
            "os.environ",
            {
                "RECONFLOW_WEBHOOK_URL": "",
                "DISCORD_WEBHOOK_URL": "https://discord.hook",
            },
        ):
            self.assertEqual(notify.resolve_webhook_url(), "https://discord.hook")


class TestDiffNotifyIntegration(unittest.TestCase):
    """Test suite for diff --notify CLI behavior."""

    @patch("reconflow.notify.send_webhook")
    @patch("reconflow.history.list_runs")
    @patch("reconflow.history.load_snapshot")
    def test_notify_skips_when_no_changes(self, mock_load, mock_list, mock_send):
        """When diff detects no changes, no webhook must be sent."""
        from reconflow import diff

        mock_list.return_value = [MagicMock(name="run1"), MagicMock(name="run2")]
        mock_load.side_effect = [
            {"run_id": "run1", "subdomains": ["a.com"], "hosts": [{"url": "https://a.com"}]},
            {"run_id": "run2", "subdomains": ["a.com"], "hosts": [{"url": "https://a.com"}]},
        ]

        args = MagicMock()
        args.domain = "example.com"
        args.output = "output"
        args.json_report = False
        args.notify = True
        args.webhook_url = "https://discord.com/api/webhooks/test"

        with self.assertRaises(SystemExit) as cm:
            diff.run(args)

        self.assertEqual(cm.exception.code, 0)
        self.assertFalse(mock_send.called)

    @patch("reconflow.notify.send_webhook")
    @patch("reconflow.history.list_runs")
    @patch("reconflow.history.load_snapshot")
    def test_notify_sends_when_changes_present(self, mock_load, mock_list, mock_send):
        """When diff detects changes, webhook is triggered."""
        from reconflow import diff

        mock_list.return_value = [MagicMock(name="run1"), MagicMock(name="run2")]
        mock_load.side_effect = [
            {"run_id": "run1", "subdomains": ["a.com"], "hosts": [{"url": "https://a.com"}]},
            {
                "run_id": "run2",
                "subdomains": ["a.com", "b.com"],
                "hosts": [{"url": "https://a.com"}, {"url": "https://b.com"}],
            },
        ]

        args = MagicMock()
        args.domain = "example.com"
        args.output = "output"
        args.json_report = False
        args.notify = True
        args.webhook_url = "https://discord.com/api/webhooks/test"

        with self.assertRaises(SystemExit) as cm:
            diff.run(args)

        self.assertEqual(cm.exception.code, 1)
        self.assertTrue(mock_send.called)


if __name__ == "__main__":
    unittest.main()
