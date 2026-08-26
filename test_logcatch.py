import threading
import unittest
import uuid
from datetime import datetime
from pathlib import Path

from logcatch import (
    PREVIEW_EVENT_LIMIT,
    SearchGroup,
    SearchOptions,
    create_result_path,
    detect_encoding,
    extract_logs,
    format_elapsed,
)


class LogCatchTests(unittest.TestCase):
    def test_format_elapsed(self):
        self.assertEqual(format_elapsed(0), "00:00:00")
        self.assertEqual(format_elapsed(3661.9), "01:01:01")

    def test_result_path_uses_start_timestamp_without_overwriting(self):
        root = Path(f".test_results_{uuid.uuid4().hex}")
        try:
            started_at = datetime(2026, 8, 26, 15, 49, 30)
            first = create_result_path(root, started_at)
            self.assertEqual(first.name, "logcatch_20260826154930.log")
            first.touch()
            second = create_result_path(root, started_at)
            self.assertEqual(second.name, "logcatch_20260826154930_2.log")
        finally:
            for path in sorted(root.glob("**/*"), reverse=True):
                if path.is_file():
                    path.unlink()
                elif path.is_dir():
                    path.rmdir()
            root.rmdir()

    def test_extracts_utf8_and_cp932_with_markers(self):
        token = uuid.uuid4().hex
        utf8 = Path(f".test_{token}_one.log")
        cp932 = Path(f".test_{token}_two.log")
        output = Path(f".test_{token}_result.log")
        try:
            utf8.write_text("INFO start\nERROR timeout\nERROR ok\n", encoding="utf-8")
            cp932.write_bytes("INFO\nERROR 座村清市 timeout\n".encode("cp932"))
            events = []
            extraction = extract_logs(
                [utf8, cp932],
                SearchOptions([SearchGroup(["ERROR", "timeout"], "and")], "and", False, "auto"),
                output,
                threading.Event(),
                lambda kind, payload: events.append((kind, payload)),
            )
            result = output.read_text(encoding="utf-8")
            self.assertEqual(extraction.matches, 2)
            self.assertEqual(extraction.file_errors, 0)
            self.assertIn(f"[===Open File :{utf8}==]", result)
            self.assertIn("ERROR timeout", result)
            self.assertIn("ERROR 座村清市 timeout", result)
            self.assertIn(f"[===Close File :{cp932}==]", result)
            self.assertEqual(detect_encoding(cp932, "auto"), "cp932")
        finally:
            utf8.unlink(missing_ok=True)
            cp932.unlink(missing_ok=True)
            output.unlink(missing_ok=True)

    def test_combines_groups_and_treats_comma_as_literal(self):
        token = uuid.uuid4().hex
        source = Path(f".test_{token}_conditions.log")
        output = Path(f".test_{token}_conditions_result.log")
        try:
            source.write_text(
                "AAA DD,E,FF\nBBB DD,E,FF\nCCC DD E FF\nCCC DD,E,FF\n",
                encoding="utf-8",
            )
            extraction = extract_logs(
                [source],
                SearchOptions(
                    [
                        SearchGroup(["AAA", "BBB"], "or"),
                        SearchGroup(["DD,E,FF"], "and"),
                    ],
                    "and",
                    False,
                    "auto",
                ),
                output,
                threading.Event(),
                lambda _kind, _payload: None,
            )
            result = output.read_text(encoding="utf-8")
            self.assertEqual(extraction.matches, 2)
            self.assertEqual(extraction.file_errors, 0)
            self.assertIn("AAA DD,E,FF", result)
            self.assertIn("BBB DD,E,FF", result)
            self.assertNotIn("CCC DD E FF\n", result)
        finally:
            source.unlink(missing_ok=True)
            output.unlink(missing_ok=True)

    def test_continues_after_unreadable_file_and_records_error(self):
        token = uuid.uuid4().hex
        missing = Path(f".test_{token}_missing.log")
        readable = Path(f".test_{token}_readable.log")
        output = Path(f".test_{token}_error_result.log")
        events = []
        try:
            readable.write_text("INFO\nERROR recovered\n", encoding="utf-8")
            extraction = extract_logs(
                [missing, readable],
                SearchOptions([SearchGroup(["ERROR"], "and")], "and", False, "auto"),
                output,
                threading.Event(),
                lambda kind, payload: events.append((kind, payload)),
            )
            result = output.read_text(encoding="utf-8")
            self.assertEqual(extraction.matches, 1)
            self.assertEqual(extraction.file_errors, 1)
            self.assertIn(f"[===Error File :{missing} |", result)
            self.assertIn("ERROR recovered", result)
            self.assertTrue(any(kind == "file_error" for kind, _payload in events))
        finally:
            readable.unlink(missing_ok=True)
            output.unlink(missing_ok=True)

    def test_large_match_batch_limits_only_preview_payload(self):
        token = uuid.uuid4().hex
        source = Path(f".test_{token}_large_preview.log")
        output = Path(f".test_{token}_large_preview_result.log")
        events = []
        try:
            source.write_text("".join(f"MATCH {index}\n" for index in range(5000)), encoding="utf-8")
            extraction = extract_logs(
                [source],
                SearchOptions([SearchGroup(["MATCH"], "and")], "and", False, "auto"),
                output,
                threading.Event(),
                lambda kind, payload: events.append((kind, payload)),
            )
            preview_sizes = [len(payload["lines"]) for kind, payload in events if kind == "preview"]
            self.assertEqual(extraction.matches, 5000)
            self.assertTrue(preview_sizes)
            self.assertLessEqual(max(preview_sizes), PREVIEW_EVENT_LIMIT)
            self.assertIn("MATCH 0", output.read_text(encoding="utf-8"))
        finally:
            source.unlink(missing_ok=True)
            output.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
