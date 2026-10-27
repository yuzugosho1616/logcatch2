from __future__ import annotations

import codecs
import os
import queue
import shutil
import sys
import threading
import time
import tkinter as tk
from collections import deque
from contextlib import ExitStack
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Callable, Iterable

from tkinterdnd2 import DND_FILES, TkinterDnD


CHUNK_SIZE = 1024 * 1024
PREVIEW_LIMIT = 5000
PREVIEW_EVENT_LIMIT = 500
COPY_WARNING_BYTES = 100 * 1024 * 1024
EVENT_QUEUE_LIMIT = 100
EVENTS_PER_POLL = 50
GROUP_ALL_LABEL = "すべての条件を満たす (AND)"
GROUP_ANY_LABEL = "いずれかの条件を満たす (OR)"
OVERALL_ALL_LABEL = "すべてのグループを満たす (AND)"
OVERALL_ANY_LABEL = "いずれかのグループを満たす (OR)"
TERM_INCLUDE_LABEL = "含む"
TERM_EXCLUDE_LABEL = "含まない (NOT)"


def format_bytes(size: int) -> str:
    units = ("B", "KB", "MB", "GB", "TB")
    value = float(size)
    for unit in units:
        if value < 1024 or unit == units[-1]:
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{size} B"


def format_elapsed(seconds: float) -> str:
    total = max(0, int(seconds))
    hours, remainder = divmod(total, 3600)
    minutes, seconds = divmod(remainder, 60)
    return f"{hours:02d}:{minutes:02d}:{seconds:02d}"


def preserve_nonblank_terms(values: Iterable[str]) -> list[str]:
    return [value for value in values if value.strip()]


def sanitize_search_term(value: str) -> str:
    return value.rstrip("\r\n")


def application_directory() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


def create_result_path(base_directory: Path, started_at: datetime | None = None) -> Path:
    result_directory = base_directory / "results"
    result_directory.mkdir(parents=True, exist_ok=True)
    timestamp = (started_at or datetime.now()).strftime("%Y%m%d%H%M%S")
    suffix = 2
    candidate = result_directory / f"logcatch_{timestamp}.log"
    while True:
        try:
            candidate.touch(exist_ok=False)
            return candidate
        except FileExistsError:
            candidate = result_directory / f"logcatch_{timestamp}_{suffix}.log"
            suffix += 1


def sanitize_output_name(value: str, fallback: str) -> str:
    invalid = '<>:"/\\|?*'
    cleaned = "".join("_" if character in invalid or ord(character) < 32 else character for character in value)
    cleaned = cleaned.strip().rstrip(".")
    return (cleaned or fallback)[:80]


def create_result_paths(
    base_directory: Path,
    output_names: Iterable[str],
    started_at: datetime | None = None,
) -> list[Path]:
    names = list(output_names)
    if len(names) == 1:
        return [create_result_path(base_directory, started_at)]

    result_directory = base_directory / "results"
    result_directory.mkdir(parents=True, exist_ok=True)
    timestamp = (started_at or datetime.now()).strftime("%Y%m%d%H%M%S")
    paths: list[Path] = []
    try:
        for index, name in enumerate(names, start=1):
            safe_name = sanitize_output_name(name, f"条件{index}")
            candidate = result_directory / f"logcatch_{timestamp}_{safe_name}.log"
            suffix = 2
            while True:
                try:
                    candidate.touch(exist_ok=False)
                    paths.append(candidate)
                    break
                except FileExistsError:
                    candidate = result_directory / f"logcatch_{timestamp}_{safe_name}_{suffix}.log"
                    suffix += 1
    except OSError:
        for path in paths:
            path.unlink(missing_ok=True)
        raise
    return paths


def detect_encoding_from_sample(sample: bytes, requested: str) -> str:
    if requested != "auto":
        return requested
    if sample.startswith(codecs.BOM_UTF8):
        return "utf-8-sig"
    try:
        sample.decode("utf-8", errors="strict")
        return "utf-8"
    except UnicodeDecodeError:
        return "cp932"


def detect_encoding(path: Path, requested: str) -> str:
    if requested != "auto":
        return requested
    with path.open("rb") as source:
        return detect_encoding_from_sample(source.read(CHUNK_SIZE), requested)


@dataclass(frozen=True)
class SearchGroup:
    terms: list[str]
    mode: str
    excluded_terms: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class SearchOptions:
    groups: list[SearchGroup]
    group_mode: str
    case_sensitive: bool
    encoding: str


@dataclass(frozen=True)
class ExtractionResult:
    matches: int
    file_errors: int


@dataclass(frozen=True)
class MultiSearchRule:
    name: str
    options: SearchOptions
    output_path: Path


@dataclass(frozen=True)
class MultiExtractionResult:
    matches: list[int]
    file_errors: int


@dataclass(frozen=True)
class ByteSearchPlan:
    groups: list[tuple[list[bytes], list[bytes], str]]
    group_mode: str
    ignore_case: bool

    def __call__(self, line: bytes) -> bool:
        haystack = line.lower() if self.ignore_case else line
        return self.matches_haystack(haystack)

    def matches_haystack(self, haystack: bytes) -> bool:
        for group in self.groups:
            terms, excluded_terms, mode = group
            if mode == "and":
                group_matches = all(term in haystack for term in terms) and all(
                    term not in haystack for term in excluded_terms
                )
            else:
                group_matches = any(term in haystack for term in terms) or any(
                    term not in haystack for term in excluded_terms
                )
            if self.group_mode == "and" and not group_matches:
                return False
            if self.group_mode == "or" and group_matches:
                return True
        return self.group_mode == "and"


EventCallback = Callable[[str, dict], None]


def build_text_matcher(options: SearchOptions) -> Callable[[str], bool]:
    groups = [
        SearchGroup(
            group.terms if options.case_sensitive else [term.casefold() for term in group.terms],
            group.mode,
            (
                group.excluded_terms
                if options.case_sensitive
                else [term.casefold() for term in group.excluded_terms]
            ),
        )
        for group in options.groups
    ]

    def matches(line: str) -> bool:
        haystack = line if options.case_sensitive else line.casefold()

        def group_matches(group: SearchGroup) -> bool:
            if group.mode == "and":
                return all(term in haystack for term in group.terms) and all(
                    term not in haystack for term in group.excluded_terms
                )
            return any(term in haystack for term in group.terms) or any(
                term not in haystack for term in group.excluded_terms
            )

        results = (group_matches(group) for group in groups)
        return all(results) if options.group_mode == "and" else any(results)

    return matches


def supports_byte_casefold(term: str) -> bool:
    return all(character.isascii() or character.lower() == character.upper() for character in term)


def build_byte_prefilter(options: SearchOptions, encoding: str) -> ByteSearchPlan | None:
    if not options.case_sensitive and not all(
        supports_byte_casefold(term)
        for group in options.groups
        for term in (*group.terms, *group.excluded_terms)
    ):
        return None

    codec = "utf-8" if encoding == "utf-8-sig" else encoding
    try:
        groups = [
            (
                [
                    (
                        term.encode(codec, errors="strict")
                        if options.case_sensitive
                        else term.casefold().encode(codec, errors="strict").lower()
                    )
                    for term in group.terms
                ],
                [
                    (
                        term.encode(codec, errors="strict")
                        if options.case_sensitive
                        else term.casefold().encode(codec, errors="strict").lower()
                    )
                    for term in group.excluded_terms
                ],
                group.mode,
            )
            for group in options.groups
        ]
    except UnicodeEncodeError:
        return None

    return ByteSearchPlan(groups, options.group_mode, not options.case_sensitive)


def extract_logs(
    paths: Iterable[Path],
    options: SearchOptions,
    output_path: Path,
    cancel: threading.Event,
    emit: EventCallback,
) -> ExtractionResult:
    files = list(paths)
    file_sizes: dict[Path, int] = {}
    for path in files:
        try:
            file_sizes[path] = path.stat().st_size
        except OSError:
            file_sizes[path] = 0
    total_bytes = sum(file_sizes.values())
    completed_bytes = 0
    match_count = 0
    file_errors = 0
    matches = build_text_matcher(options)

    with output_path.open("w", encoding="utf-8", newline="\n", buffering=CHUNK_SIZE) as output:
        for index, path in enumerate(files):
            if cancel.is_set():
                break
            if index:
                output.write("\n")
                emit("marker", {"lines": [""]})
            open_marker = f"[===Open File :{path}==]"
            output.write(open_marker + "\n")
            file_read = 0
            had_file_error = False
            preview_batch: list[str] = []
            emit("marker", {"lines": [open_marker]})
            try:
                with path.open("rb", buffering=CHUNK_SIZE) as source:
                    first_chunk = source.read(CHUNK_SIZE) if options.encoding == "auto" else None
                    encoding = detect_encoding_from_sample(first_chunk or b"", options.encoding)
                    byte_prefilter = build_byte_prefilter(options, encoding)
                    emit(
                        "file",
                        {
                            "index": index + 1,
                            "count": len(files),
                            "path": str(path),
                            "encoding": encoding,
                            "fast_path": byte_prefilter is not None,
                        },
                    )
                    if byte_prefilter is not None:
                        source.seek(0)
                        last_progress = 0
                        last_update = 0.0
                        byte_groups = byte_prefilter.groups
                        single_group = byte_groups[0] if len(byte_groups) == 1 else None
                        ignore_case = byte_prefilter.ignore_case
                        for raw_line in source:
                            file_read += len(raw_line)
                            haystack = raw_line.lower() if ignore_case else raw_line
                            if single_group is not None:
                                terms, excluded_terms, mode = single_group
                                if mode == "and":
                                    is_candidate = all(term in haystack for term in terms) and all(
                                        term not in haystack for term in excluded_terms
                                    )
                                else:
                                    is_candidate = any(term in haystack for term in terms) or any(
                                        term not in haystack for term in excluded_terms
                                    )
                            else:
                                group_results = []
                                for terms, excluded_terms, mode in byte_groups:
                                    if mode == "and":
                                        group_results.append(
                                            all(term in haystack for term in terms)
                                            and all(term not in haystack for term in excluded_terms)
                                        )
                                    else:
                                        group_results.append(
                                            any(term in haystack for term in terms)
                                            or any(term not in haystack for term in excluded_terms)
                                        )
                                is_candidate = (
                                    all(group_results)
                                    if byte_prefilter.group_mode == "and"
                                    else any(group_results)
                                )
                            if is_candidate:
                                content = raw_line
                                if content.endswith(b"\n"):
                                    content = content[:-1]
                                if content.endswith(b"\r"):
                                    content = content[:-1]
                                line = content.decode(encoding, errors="replace")
                                if matches(line):
                                    output.write(line + "\n")
                                    match_count += 1
                                    preview_batch.append(line)
                                    if len(preview_batch) >= PREVIEW_EVENT_LIMIT * 2:
                                        del preview_batch[:-PREVIEW_EVENT_LIMIT]
                            if file_read - last_progress >= CHUNK_SIZE:
                                if cancel.is_set():
                                    break
                                now = time.monotonic()
                                if now - last_update >= 0.1:
                                    if preview_batch:
                                        emit(
                                            "preview",
                                            {"lines": preview_batch[-PREVIEW_EVENT_LIMIT:], "matches": match_count},
                                        )
                                        preview_batch = []
                                    emit("progress", {"done": completed_bytes + file_read, "total": total_bytes})
                                    last_update = now
                                last_progress = file_read
                                time.sleep(0)
                    else:
                        decoder = codecs.getincrementaldecoder(encoding)(errors="replace")
                        pending = ""
                        last_update = 0.0
                        while not cancel.is_set():
                            if first_chunk is not None:
                                chunk = first_chunk
                                first_chunk = None
                            else:
                                chunk = source.read(CHUNK_SIZE)
                            if not chunk:
                                break
                            file_read += len(chunk)
                            text = pending + decoder.decode(chunk, final=False)
                            lines = text.split("\n")
                            pending = lines.pop()
                            for line in lines:
                                line = line.removesuffix("\r")
                                if matches(line):
                                    output.write(line + "\n")
                                    match_count += 1
                                    preview_batch.append(line)
                            now = time.monotonic()
                            if preview_batch and (len(preview_batch) >= 200 or now - last_update >= 0.1):
                                emit("preview", {"lines": preview_batch[-PREVIEW_EVENT_LIMIT:], "matches": match_count})
                                preview_batch = []
                            if now - last_update >= 0.1:
                                emit("progress", {"done": completed_bytes + file_read, "total": total_bytes})
                                last_update = now

                        if not cancel.is_set():
                            pending += decoder.decode(b"", final=True)
                            if pending:
                                pending = pending.removesuffix("\r")
                                if matches(pending):
                                    output.write(pending + "\n")
                                    match_count += 1
                                    preview_batch.append(pending)
            except OSError as error:
                file_errors += 1
                had_file_error = True
                error_marker = f"[===Error File :{path} | {error}==]"
                output.write(error_marker + "\n")
                emit("file_error", {"path": str(path), "message": str(error)})
                emit("marker", {"lines": [error_marker]})

            if preview_batch:
                emit("preview", {"lines": preview_batch[-PREVIEW_EVENT_LIMIT:], "matches": match_count})
            close_marker = f"[===Close File :{path}==]"
            output.write(close_marker + "\n")
            output.flush()
            emit("marker", {"lines": [close_marker], "matches": match_count})
            completed_bytes += file_sizes[path] if had_file_error else file_read
            emit("progress", {"done": completed_bytes, "total": total_bytes})

    return ExtractionResult(match_count, file_errors)


def extract_logs_multi(
    paths: Iterable[Path],
    rules: list[MultiSearchRule],
    cancel: threading.Event,
    emit: EventCallback,
) -> MultiExtractionResult:
    if not rules:
        return MultiExtractionResult([], 0)

    files = list(paths)
    file_sizes: dict[Path, int] = {}
    for path in files:
        try:
            file_sizes[path] = path.stat().st_size
        except OSError:
            file_sizes[path] = 0
    total_bytes = sum(file_sizes.values())
    completed_bytes = 0
    match_counts = [0] * len(rules)
    file_errors = 0
    text_matchers = [build_text_matcher(rule.options) for rule in rules]
    requested_encoding = rules[0].options.encoding

    with ExitStack() as stack:
        outputs = [
            stack.enter_context(
                rule.output_path.open("w", encoding="utf-8", newline="\n", buffering=CHUNK_SIZE)
            )
            for rule in rules
        ]
        for file_index, path in enumerate(files):
            if cancel.is_set():
                break
            if file_index:
                for rule_index, output in enumerate(outputs):
                    output.write("\n")
                    emit("marker", {"rule": rule_index, "lines": [""]})

            open_marker = f"[===Open File :{path}==]"
            for rule_index, output in enumerate(outputs):
                output.write(open_marker + "\n")
                emit("marker", {"rule": rule_index, "lines": [open_marker]})

            file_read = 0
            had_file_error = False
            preview_batches: list[list[str]] = [[] for _rule in rules]
            try:
                with path.open("rb", buffering=CHUNK_SIZE) as source:
                    first_chunk = source.read(CHUNK_SIZE) if requested_encoding == "auto" else None
                    encoding = detect_encoding_from_sample(first_chunk or b"", requested_encoding)
                    byte_plans = [build_byte_prefilter(rule.options, encoding) for rule in rules]
                    all_fast = all(plan is not None for plan in byte_plans)
                    emit(
                        "file",
                        {
                            "index": file_index + 1,
                            "count": len(files),
                            "path": str(path),
                            "encoding": encoding,
                            "fast_path": all_fast,
                        },
                    )

                    if all_fast:
                        source.seek(0)
                        plans = [plan for plan in byte_plans if plan is not None]
                        needs_lower = any(plan.ignore_case for plan in plans)
                        plan_groups = [plan.groups for plan in plans]
                        plan_modes = [plan.group_mode for plan in plans]
                        single_groups = [groups[0] if len(groups) == 1 else None for groups in plan_groups]
                        last_progress = 0
                        last_update = 0.0
                        for raw_line in source:
                            file_read += len(raw_line)
                            lowered = raw_line.lower() if needs_lower else raw_line
                            candidates: list[bool] = []
                            for rule_index, plan in enumerate(plans):
                                haystack = lowered if plan.ignore_case else raw_line
                                single_group = single_groups[rule_index]
                                if single_group is not None:
                                    terms, excluded_terms, mode = single_group
                                    if not excluded_terms and len(terms) == 1:
                                        is_candidate = terms[0] in haystack
                                    elif mode == "and":
                                        is_candidate = all(term in haystack for term in terms) and all(
                                            term not in haystack for term in excluded_terms
                                        )
                                    else:
                                        is_candidate = any(term in haystack for term in terms) or any(
                                            term not in haystack for term in excluded_terms
                                        )
                                else:
                                    group_results = []
                                    for terms, excluded_terms, mode in plan_groups[rule_index]:
                                        if mode == "and":
                                            group_results.append(
                                                all(term in haystack for term in terms)
                                                and all(term not in haystack for term in excluded_terms)
                                            )
                                        else:
                                            group_results.append(
                                                any(term in haystack for term in terms)
                                                or any(term not in haystack for term in excluded_terms)
                                            )
                                    is_candidate = (
                                        all(group_results)
                                        if plan_modes[rule_index] == "and"
                                        else any(group_results)
                                    )
                                candidates.append(is_candidate)
                            if any(candidates):
                                content = raw_line.removesuffix(b"\n").removesuffix(b"\r")
                                line = content.decode(encoding, errors="replace")
                                for rule_index, is_candidate in enumerate(candidates):
                                    if is_candidate and text_matchers[rule_index](line):
                                        outputs[rule_index].write(line + "\n")
                                        match_counts[rule_index] += 1
                                        batch = preview_batches[rule_index]
                                        batch.append(line)
                                        if len(batch) >= PREVIEW_EVENT_LIMIT * 2:
                                            del batch[:-PREVIEW_EVENT_LIMIT]

                            if file_read - last_progress >= CHUNK_SIZE:
                                if cancel.is_set():
                                    break
                                now = time.monotonic()
                                if now - last_update >= 0.1:
                                    for rule_index, batch in enumerate(preview_batches):
                                        if batch:
                                            emit(
                                                "preview",
                                                {
                                                    "rule": rule_index,
                                                    "lines": batch[-PREVIEW_EVENT_LIMIT:],
                                                    "matches": match_counts[rule_index],
                                                },
                                            )
                                            preview_batches[rule_index] = []
                                    emit(
                                        "progress",
                                        {"done": completed_bytes + file_read, "total": total_bytes},
                                    )
                                    last_update = now
                                last_progress = file_read
                                time.sleep(0)
                    else:
                        decoder = codecs.getincrementaldecoder(encoding)(errors="replace")
                        pending = ""
                        last_update = 0.0
                        while not cancel.is_set():
                            if first_chunk is not None:
                                chunk = first_chunk
                                first_chunk = None
                            else:
                                chunk = source.read(CHUNK_SIZE)
                            if not chunk:
                                break
                            file_read += len(chunk)
                            text = pending + decoder.decode(chunk, final=False)
                            lines = text.split("\n")
                            pending = lines.pop()
                            for line in lines:
                                line = line.removesuffix("\r")
                                for rule_index, matcher in enumerate(text_matchers):
                                    if matcher(line):
                                        outputs[rule_index].write(line + "\n")
                                        match_counts[rule_index] += 1
                                        preview_batches[rule_index].append(line)
                            now = time.monotonic()
                            if now - last_update >= 0.1:
                                for rule_index, batch in enumerate(preview_batches):
                                    if batch:
                                        emit(
                                            "preview",
                                            {
                                                "rule": rule_index,
                                                "lines": batch[-PREVIEW_EVENT_LIMIT:],
                                                "matches": match_counts[rule_index],
                                            },
                                        )
                                        preview_batches[rule_index] = []
                                emit(
                                    "progress",
                                    {"done": completed_bytes + file_read, "total": total_bytes},
                                )
                                last_update = now

                        if not cancel.is_set():
                            pending += decoder.decode(b"", final=True)
                            if pending:
                                line = pending.removesuffix("\r")
                                for rule_index, matcher in enumerate(text_matchers):
                                    if matcher(line):
                                        outputs[rule_index].write(line + "\n")
                                        match_counts[rule_index] += 1
                                        preview_batches[rule_index].append(line)
            except OSError as error:
                file_errors += 1
                had_file_error = True
                error_marker = f"[===Error File :{path} | {error}==]"
                for rule_index, output in enumerate(outputs):
                    output.write(error_marker + "\n")
                    emit("marker", {"rule": rule_index, "lines": [error_marker]})
                emit("file_error", {"path": str(path), "message": str(error)})

            for rule_index, batch in enumerate(preview_batches):
                if batch:
                    emit(
                        "preview",
                        {
                            "rule": rule_index,
                            "lines": batch[-PREVIEW_EVENT_LIMIT:],
                            "matches": match_counts[rule_index],
                        },
                    )
            close_marker = f"[===Close File :{path}==]"
            for rule_index, output in enumerate(outputs):
                output.write(close_marker + "\n")
                output.flush()
                emit(
                    "marker",
                    {"rule": rule_index, "lines": [close_marker], "matches": match_counts[rule_index]},
                )
            completed_bytes += file_sizes[path] if had_file_error else file_read
            emit("progress", {"done": completed_bytes, "total": total_bytes})

    return MultiExtractionResult(match_counts, file_errors)


class LogCatchApp:
    def __init__(self) -> None:
        self.root = TkinterDnD.Tk()
        self.root.title("LogCatch")
        self.root.geometry("1080x900")
        self.root.minsize(820, 650)
        self.files: list[Path] = []
        self.running = False
        self.cancel_event = threading.Event()
        self.events: queue.Queue[tuple[str, dict]] = queue.Queue(maxsize=EVENT_QUEUE_LIMIT)
        self.result_path: Path | None = None
        self.result_paths: list[Path] = []
        self.result_names: list[str] = []
        self.result_display_names: list[str] = []
        self.match_counts: list[int] = []
        self.preview_buffers: list[deque[str]] = []
        self.selected_result_index = 0
        self.match_count = 0
        self.file_error_count = 0
        self.preview_line_count = 0
        self.started_at: float | None = None
        self.elapsed_seconds = 0.0
        self.condition_sets: list[dict] = []
        self.next_condition_number = 1
        self._build_style()
        self._build_ui()
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.root.after(50, self.poll_events)

    def _build_style(self) -> None:
        style = ttk.Style(self.root)
        if "vista" in style.theme_names():
            style.theme_use("vista")
        style.configure("Header.TFrame", background="#202b36")
        style.configure("Header.TLabel", background="#202b36", foreground="white", font=("Segoe UI", 15, "bold"))
        style.configure("SubHeader.TLabel", background="#202b36", foreground="#bac5cf", font=("Segoe UI", 9))
        style.configure("Section.TLabel", font=("Yu Gothic UI", 10, "bold"))
        style.configure("Accent.TButton", font=("Yu Gothic UI", 10, "bold"))

    def _build_ui(self) -> None:
        header = ttk.Frame(self.root, style="Header.TFrame", height=60)
        header.pack(fill="x")
        header.pack_propagate(False)
        ttk.Label(header, text="LogCatch", style="Header.TLabel").pack(side="left", padx=(22, 12), pady=14)
        ttk.Label(header, text="Large log line extractor", style="SubHeader.TLabel").pack(side="left", pady=18)

        body = ttk.Frame(self.root, padding=(22, 18, 22, 20))
        body.pack(fill="both", expand=True)

        file_head = ttk.Frame(body)
        file_head.pack(fill="x")
        ttk.Label(file_head, text="1. ログファイル", style="Section.TLabel").pack(side="left")
        self.file_summary = ttk.Label(file_head, text="未選択", foreground="#66717e")
        self.file_summary.pack(side="right", padx=(8, 0))
        self.clear_button = ttk.Button(file_head, text="すべてクリア", command=self.clear_files, state="disabled")
        self.clear_button.pack(side="right", padx=(8, 0))
        self.add_button = ttk.Button(file_head, text="ファイルを追加", command=self.choose_files)
        self.add_button.pack(side="right", padx=(8, 0))

        list_frame = ttk.Frame(body)
        list_frame.pack(fill="x", pady=(8, 16))
        self.file_list = tk.Listbox(list_frame, height=5, font=("Consolas", 9), activestyle="none", selectmode="extended")
        file_y = ttk.Scrollbar(list_frame, orient="vertical", command=self.file_list.yview)
        file_x = ttk.Scrollbar(list_frame, orient="horizontal", command=self.file_list.xview)
        self.file_list.configure(yscrollcommand=file_y.set, xscrollcommand=file_x.set)
        self.file_list.grid(row=0, column=0, sticky="nsew")
        file_y.grid(row=0, column=1, sticky="ns")
        file_x.grid(row=1, column=0, sticky="ew")
        list_frame.columnconfigure(0, weight=1)
        self.file_list.drop_target_register(DND_FILES)
        self.file_list.dnd_bind("<<Drop>>", self.on_drop)

        search_head = ttk.Frame(body)
        search_head.pack(fill="x")
        ttk.Label(search_head, text="2. 検索条件", style="Section.TLabel").pack(side="left")
        self.start_button = ttk.Button(search_head, text="抽出を開始", style="Accent.TButton", command=self.start_search, state="disabled")
        self.start_button.pack(side="right")
        self.delete_condition_set_button = ttk.Button(
            search_head,
            text="出力条件を削除",
            command=self.delete_condition_set,
            state="disabled",
        )
        self.delete_condition_set_button.pack(side="right", padx=(8, 0))
        self.add_condition_set_button = ttk.Button(
            search_head,
            text="＋ 出力条件を追加",
            command=self.add_condition_set,
        )
        self.add_condition_set_button.pack(side="right", padx=(8, 0))

        self.condition_notebook = ttk.Notebook(body)
        self.condition_notebook.pack(fill="x", pady=(8, 6))
        self.condition_notebook.bind("<<NotebookTabChanged>>", self.on_condition_tab_changed)

        options = ttk.Frame(body)
        options.pack(fill="x", pady=(2, 16))
        self.case_var = tk.BooleanVar(value=False)
        self.case_check = ttk.Checkbutton(options, text="大文字・小文字を区別", variable=self.case_var)
        self.case_check.pack(side="left")
        ttk.Label(options, text="文字コード:").pack(side="left", padx=(18, 5))
        self.encoding_var = tk.StringVar(value="auto")
        self.encoding_combo = ttk.Combobox(options, textvariable=self.encoding_var, values=("auto", "utf-8", "cp932"), state="readonly", width=10)
        self.encoding_combo.pack(side="left")
        ttk.Label(options, text="※ カンマと先頭・末尾の空白も検索文字として扱います", foreground="#66717e").pack(side="left", padx=(18, 0))

        self.add_condition_set(term_count=3)

        progress_head = ttk.Frame(body)
        progress_head.pack(fill="x")
        ttk.Label(progress_head, text="3. 抽出状況", style="Section.TLabel").pack(side="left")
        self.status_label = ttk.Label(progress_head, text="待機中", foreground="#66717e")
        self.status_label.pack(side="right")
        self.elapsed_label = ttk.Label(progress_head, text="経過 00:00:00", foreground="#66717e")
        self.elapsed_label.pack(side="right", padx=(0, 14))
        self.progress_var = tk.DoubleVar(value=0)
        self.progress = ttk.Progressbar(body, variable=self.progress_var, maximum=100)
        self.progress.pack(fill="x", pady=(8, 4))
        info = ttk.Frame(body)
        info.pack(fill="x", pady=(0, 10))
        self.current_label = ttk.Label(info, text="ファイルを選択してください", foreground="#66717e")
        self.current_label.pack(side="left")
        self.progress_label = ttk.Label(info, text="0 B / 0 B", foreground="#66717e")
        self.progress_label.pack(side="right")

        result_head = ttk.Frame(body)
        result_head.pack(fill="x")
        ttk.Label(result_head, text="4. 抽出結果", style="Section.TLabel").pack(side="left")
        ttk.Label(result_head, text="表示:").pack(side="left", padx=(14, 5))
        self.result_selection_var = tk.StringVar()
        self.result_selection_combo = ttk.Combobox(
            result_head,
            textvariable=self.result_selection_var,
            state="disabled",
            width=24,
        )
        self.result_selection_combo.pack(side="left")
        self.result_selection_combo.bind("<<ComboboxSelected>>", self.on_result_selected)
        self.cancel_button = ttk.Button(result_head, text="中止", command=self.cancel_search, state="disabled")
        self.cancel_button.pack(side="right")
        self.save_button = ttk.Button(result_head, text="名前を付けて保存", command=self.save_result, state="disabled")
        self.save_button.pack(side="right", padx=(0, 8))
        self.copy_button = ttk.Button(result_head, text="全結果をコピー", command=self.copy_all, state="disabled")
        self.copy_button.pack(side="right", padx=(0, 8))
        self.open_button = ttk.Button(result_head, text="結果ファイルを開く", command=self.open_result, state="disabled")
        self.open_button.pack(side="right", padx=(0, 8))
        self.count_label = ttk.Label(result_head, text="0 行", foreground="#0d5145")
        self.count_label.pack(side="right", padx=(0, 12))

        preview_frame = ttk.Frame(body)
        preview_frame.pack(fill="both", expand=True, pady=(8, 0))
        self.preview = tk.Text(preview_frame, height=12, wrap="none", state="disabled", background="#151b21", foreground="#d9e1e8", insertbackground="white", font=("Consolas", 9), padx=10, pady=8)
        preview_y = ttk.Scrollbar(preview_frame, orient="vertical", command=self.preview.yview)
        preview_x = ttk.Scrollbar(preview_frame, orient="horizontal", command=self.preview.xview)
        self.preview.configure(yscrollcommand=preview_y.set, xscrollcommand=preview_x.set)
        self.preview.grid(row=0, column=0, sticky="nsew")
        preview_y.grid(row=0, column=1, sticky="ns")
        preview_x.grid(row=1, column=0, sticky="ew")
        preview_frame.rowconfigure(0, weight=1)
        preview_frame.columnconfigure(0, weight=1)

    def current_condition_set(self) -> dict | None:
        if not self.condition_sets:
            return None
        try:
            index = self.condition_notebook.index("current")
        except tk.TclError:
            index = 0
        return self.condition_sets[index]

    def condition_set_name(self, condition_set: dict) -> str:
        fallback = f"条件{self.condition_sets.index(condition_set) + 1}"
        return condition_set["name_var"].get().strip() or fallback

    def add_condition_set(self, term_count: int = 1) -> None:
        number = self.next_condition_number
        self.next_condition_number += 1
        tab = ttk.Frame(self.condition_notebook, padding=(8, 7))

        settings = ttk.Frame(tab)
        settings.pack(fill="x", pady=(0, 6))
        ttk.Label(settings, text="出力名:").pack(side="left")
        name_var = tk.StringVar(value=f"条件{number}")
        name_entry = ttk.Entry(settings, textvariable=name_var, width=22)
        name_entry.pack(side="left", padx=(6, 20))
        ttk.Label(settings, text="複数の条件グループがある場合:").pack(side="left")
        overall_mode_var = tk.StringVar(value=OVERALL_ALL_LABEL)
        overall_mode_combo = ttk.Combobox(
            settings,
            textvariable=overall_mode_var,
            values=(OVERALL_ALL_LABEL, OVERALL_ANY_LABEL),
            state="readonly",
            width=34,
        )
        overall_mode_combo.pack(side="left", padx=(7, 0))

        condition_area = ttk.Frame(tab)
        condition_area.pack(fill="x")
        canvas = tk.Canvas(
            condition_area,
            height=150,
            highlightthickness=1,
            highlightbackground="#aeb8c2",
        )
        scrollbar = ttk.Scrollbar(condition_area, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.grid(row=0, column=0, sticky="nsew")
        scrollbar.grid(row=0, column=1, sticky="ns")
        condition_area.columnconfigure(0, weight=1)
        container = ttk.Frame(canvas, padding=(6, 3))
        window = canvas.create_window((0, 0), window=container, anchor="nw")

        actions = ttk.Frame(tab)
        actions.pack(fill="x", pady=(6, 0))
        summary = ttk.Label(actions, text="", foreground="#52606d")
        summary.pack(side="left", padx=(14, 0))

        condition_set: dict = {
            "tab": tab,
            "name_var": name_var,
            "name_entry": name_entry,
            "overall_mode_var": overall_mode_var,
            "overall_mode_combo": overall_mode_combo,
            "canvas": canvas,
            "container": container,
            "window": window,
            "summary": summary,
            "groups": [],
        }
        add_group_button = ttk.Button(
            actions,
            text="＋ 条件グループを追加",
            command=lambda: self.add_condition_group(condition_set),
        )
        add_group_button.pack(side="left")
        condition_set["add_group_button"] = add_group_button

        container.bind(
            "<Configure>",
            lambda _event, item=condition_set: self._resize_condition_scroll(item),
        )
        canvas.bind(
            "<Configure>",
            lambda event, item=condition_set: self._resize_condition_width(item, event),
        )
        overall_mode_combo.bind(
            "<<ComboboxSelected>>",
            lambda _event, item=condition_set: self.update_condition_summary(item),
        )
        name_var.trace_add("write", lambda *_args, item=condition_set: self.on_condition_name_changed(item))

        self.condition_sets.append(condition_set)
        self.condition_notebook.add(tab, text=f"条件{number}")
        if term_count:
            self.add_condition_group(condition_set, term_count=term_count, refresh=False)
        self.refresh_condition_groups(condition_set)
        self.refresh_condition_set_tabs()
        self.condition_notebook.select(tab)
        self.root.after_idle(lambda: canvas.yview_moveto(1.0))

    def delete_condition_set(self) -> None:
        condition_set = self.current_condition_set()
        if condition_set is None or len(self.condition_sets) == 1:
            return
        index = self.condition_sets.index(condition_set)
        self.condition_notebook.forget(condition_set["tab"])
        condition_set["tab"].destroy()
        self.condition_sets.remove(condition_set)
        self.refresh_condition_set_tabs()
        self.condition_notebook.select(max(0, index - 1))
        self.update_controls()

    def refresh_condition_set_tabs(self) -> None:
        for condition_set in self.condition_sets:
            title = self.condition_set_name(condition_set)
            if len(title) > 18:
                title = title[:17] + "…"
            self.condition_notebook.tab(condition_set["tab"], text=title)
        self.delete_condition_set_button.configure(
            state="normal" if len(self.condition_sets) > 1 and not self.running else "disabled"
        )

    def on_condition_name_changed(self, condition_set: dict) -> None:
        if condition_set in self.condition_sets:
            self.refresh_condition_set_tabs()
            self.update_controls()

    def on_condition_tab_changed(self, _event: tk.Event | None = None) -> None:
        self.refresh_condition_set_tabs()

    def _resize_condition_scroll(self, condition_set: dict) -> None:
        canvas = condition_set["canvas"]
        canvas.configure(scrollregion=canvas.bbox("all"))

    def _resize_condition_width(self, condition_set: dict, event: tk.Event) -> None:
        condition_set["canvas"].itemconfigure(condition_set["window"], width=event.width)

    def add_condition_group(
        self,
        condition_set: dict | None = None,
        term_count: int = 1,
        refresh: bool = True,
    ) -> None:
        condition_set = condition_set or self.current_condition_set()
        if condition_set is None:
            return
        frame = ttk.LabelFrame(condition_set["container"], padding=(8, 6))
        frame.pack(fill="x", pady=3)
        header = ttk.Frame(frame)
        header.pack(fill="x")
        ttk.Label(header, text="このグループでは:").pack(side="left")
        mode_var = tk.StringVar(value=GROUP_ALL_LABEL)
        mode_combo = ttk.Combobox(
            header,
            textvariable=mode_var,
            values=(GROUP_ALL_LABEL, GROUP_ANY_LABEL),
            state="readonly",
            width=22,
        )
        mode_combo.pack(side="left", padx=(7, 0))
        terms_frame = ttk.Frame(frame)
        terms_frame.pack(fill="x", pady=(5, 0))
        group: dict = {
            "frame": frame,
            "mode_var": mode_var,
            "mode_combo": mode_combo,
            "terms_frame": terms_frame,
            "terms": [],
        }
        delete_button = ttk.Button(
            header,
            text="グループを削除",
            command=lambda: self.delete_condition_group(condition_set, group),
        )
        delete_button.pack(side="right")
        group["delete_button"] = delete_button
        add_button = ttk.Button(
            header,
            text="＋ 検索語を追加",
            command=lambda: self.add_condition_term(condition_set, group),
        )
        add_button.pack(side="right", padx=(0, 7))
        group["add_button"] = add_button
        mode_combo.bind(
            "<<ComboboxSelected>>",
            lambda _event: self.update_condition_summary(condition_set),
        )
        condition_set["groups"].append(group)
        for _ in range(term_count):
            self.add_condition_term(condition_set, group, refresh=False)
        if refresh:
            self.refresh_condition_groups(condition_set)
            self.root.after_idle(lambda: condition_set["canvas"].yview_moveto(1.0))

    def add_condition_term(self, condition_set: dict, group: dict, refresh: bool = True) -> None:
        row = ttk.Frame(group["terms_frame"])
        row.pack(fill="x", pady=2)
        type_variable = tk.StringVar(value=TERM_INCLUDE_LABEL)
        type_combo = ttk.Combobox(
            row,
            textvariable=type_variable,
            values=(TERM_INCLUDE_LABEL, TERM_EXCLUDE_LABEL),
            state="readonly",
            width=14,
        )
        type_combo.pack(side="left", padx=(0, 7))
        variable = tk.StringVar()
        entry = ttk.Entry(row, textvariable=variable)
        entry.pack(side="left", fill="x", expand=True)
        entry.bind("<<Paste>>", self.paste_condition_term)
        delete_button = ttk.Button(row, text="削除", width=7)
        delete_button.pack(side="left", padx=(7, 0))
        term = {
            "row": row,
            "type_variable": type_variable,
            "type_combo": type_combo,
            "variable": variable,
            "entry": entry,
            "delete_button": delete_button,
        }
        delete_button.configure(command=lambda: self.delete_condition_term(condition_set, group, term))
        type_combo.bind(
            "<<ComboboxSelected>>",
            lambda _event: self.on_condition_changed(condition_set),
        )
        variable.trace_add("write", lambda *_args: self.on_condition_changed(condition_set))
        group["terms"].append(term)
        if refresh:
            self.refresh_condition_groups(condition_set)
            entry.focus_set()

    def delete_condition_term(self, condition_set: dict, group: dict, term: dict) -> None:
        if len(group["terms"]) == 1:
            term["variable"].set("")
            return
        term["row"].destroy()
        group["terms"].remove(term)
        self.refresh_condition_groups(condition_set)

    def delete_condition_group(self, condition_set: dict, group: dict) -> None:
        if len(condition_set["groups"]) == 1:
            for term in group["terms"]:
                term["variable"].set("")
            return
        group["frame"].destroy()
        condition_set["groups"].remove(group)
        self.refresh_condition_groups(condition_set)

    def refresh_condition_groups(self, condition_set: dict) -> None:
        for index, group in enumerate(condition_set["groups"], start=1):
            group["frame"].configure(text=f"条件グループ {index}")
            group["delete_button"].configure(
                state="normal" if len(condition_set["groups"]) > 1 else "disabled"
            )
        self._resize_condition_scroll(condition_set)
        self.on_condition_changed(condition_set)

    def on_condition_changed(self, condition_set: dict) -> None:
        self.update_condition_summary(condition_set)
        self.update_controls()

    def paste_condition_term(self, event: tk.Event) -> str | None:
        entry = event.widget
        try:
            pasted_text = self.root.clipboard_get()
        except tk.TclError:
            return None

        pasted_text = sanitize_search_term(pasted_text)
        try:
            insert_at = entry.index("sel.first")
            entry.delete("sel.first", "sel.last")
        except tk.TclError:
            insert_at = entry.index("insert")
        entry.insert(insert_at, pasted_text)
        entry.icursor(insert_at + len(pasted_text))
        return "break"

    def collect_search_groups(self, condition_set: dict) -> list[SearchGroup]:
        groups: list[SearchGroup] = []
        for group in condition_set["groups"]:
            terms: list[str] = []
            excluded_terms: list[str] = []
            for term in group["terms"]:
                value = sanitize_search_term(term["variable"].get())
                if not value.strip():
                    continue
                target = excluded_terms if term["type_variable"].get() == TERM_EXCLUDE_LABEL else terms
                target.append(value)
            if terms or excluded_terms:
                mode = "and" if group["mode_var"].get() == GROUP_ALL_LABEL else "or"
                groups.append(SearchGroup(terms, mode, excluded_terms))
        return groups

    def update_condition_summary(self, condition_set: dict) -> None:
        groups = self.collect_search_groups(condition_set)
        if not groups:
            text = "検索語を1つ以上入力してください"
        elif len(groups) == 1:
            relation = "すべて満たす" if groups[0].mode == "and" else "いずれかを満たす"
            condition_count = len(groups[0].terms) + len(groups[0].excluded_terms)
            not_count = len(groups[0].excluded_terms)
            not_text = f"（NOT {not_count}件）" if not_count else ""
            text = f"検索方法: {condition_count}条件を{relation}行{not_text}"
        else:
            relation = (
                "すべて満たす"
                if condition_set["overall_mode_var"].get() == OVERALL_ALL_LABEL
                else "いずれかを満たす"
            )
            text = f"検索方法: {len(groups)}個の条件グループを{relation}行"
        condition_set["summary"].configure(text=text)

    def choose_files(self) -> None:
        selected = filedialog.askopenfilenames(title="ログファイルを選択", filetypes=(("ログファイル", "*.log"), ("すべてのファイル", "*.*")))
        self.add_files(Path(path) for path in selected)

    def on_drop(self, event: tk.Event) -> str:
        self.add_files(Path(path) for path in self.root.tk.splitlist(event.data))
        return "break"

    def add_files(self, paths: Iterable[Path]) -> None:
        known = {str(path).casefold() for path in self.files}
        for path in paths:
            if path.is_file() and path.suffix.casefold() == ".log" and str(path).casefold() not in known:
                self.files.append(path.resolve())
                known.add(str(path).casefold())
        self.render_files()

    def render_files(self) -> None:
        self.file_list.delete(0, "end")
        for path in self.files:
            self.file_list.insert("end", str(path))
        total = 0
        for path in self.files:
            try:
                total += path.stat().st_size
            except OSError:
                pass
        self.file_summary.configure(text=f"{len(self.files)}ファイル・{format_bytes(total)}" if self.files else "未選択")
        self.update_controls()

    def clear_files(self) -> None:
        self.files.clear()
        self.render_files()

    def update_controls(self) -> None:
        has_search = any(self.collect_search_groups(item) for item in self.condition_sets)
        ready = bool(self.files and has_search) and not self.running
        self.start_button.configure(state="normal" if ready else "disabled")
        self.add_button.configure(state="disabled" if self.running else "normal")
        self.clear_button.configure(state="normal" if self.files and not self.running else "disabled")
        self.set_condition_controls_enabled(not self.running)

    def set_condition_controls_enabled(self, enabled: bool) -> None:
        normal_state = "normal" if enabled else "disabled"
        combo_state = "readonly" if enabled else "disabled"
        self.add_condition_set_button.configure(state=normal_state)
        self.delete_condition_set_button.configure(
            state="normal" if enabled and len(self.condition_sets) > 1 else "disabled"
        )
        self.case_check.configure(state=normal_state)
        self.encoding_combo.configure(state=combo_state)
        for condition_set in self.condition_sets:
            condition_set["name_entry"].configure(state=normal_state)
            condition_set["overall_mode_combo"].configure(state=combo_state)
            condition_set["add_group_button"].configure(state=normal_state)
            for group in condition_set["groups"]:
                group["mode_combo"].configure(state=combo_state)
                group["add_button"].configure(state=normal_state)
                can_delete_group = enabled and len(condition_set["groups"]) > 1
                group["delete_button"].configure(state="normal" if can_delete_group else "disabled")
                for term in group["terms"]:
                    term["type_combo"].configure(state=combo_state)
                    term["entry"].configure(state=normal_state)
                    term["delete_button"].configure(state=normal_state)

    def new_result_path(self) -> Path:
        return create_result_path(application_directory())

    def new_result_paths(self, output_names: list[str]) -> list[Path]:
        return create_result_paths(application_directory(), output_names)

    def collect_active_searches(self) -> list[tuple[str, SearchOptions]]:
        searches: list[tuple[str, SearchOptions]] = []
        for condition_set in self.condition_sets:
            groups = self.collect_search_groups(condition_set)
            if not groups:
                continue
            group_mode = (
                "and"
                if condition_set["overall_mode_var"].get() == OVERALL_ALL_LABEL
                else "or"
            )
            searches.append(
                (
                    self.condition_set_name(condition_set),
                    SearchOptions(
                        groups,
                        group_mode,
                        self.case_var.get(),
                        self.encoding_var.get(),
                    ),
                )
            )
        return searches

    def start_search(self) -> None:
        searches = self.collect_active_searches()
        if not self.files or not searches:
            return
        try:
            self.result_names = [name for name, _options in searches]
            self.result_paths = self.new_result_paths(self.result_names)
        except OSError as error:
            messagebox.showerror("保存先エラー", f"抽出結果ファイルを作成できません。\n\n{error}", parent=self.root)
            return
        self.result_path = self.result_paths[0]
        search_rules = [
            MultiSearchRule(name, options, result_path)
            for (name, options), result_path in zip(searches, self.result_paths)
        ]
        self.running = True
        self.started_at = time.monotonic()
        self.elapsed_seconds = 0.0
        self.cancel_event.clear()
        self.match_counts = [0] * len(search_rules)
        self.match_count = 0
        self.file_error_count = 0
        self.preview_buffers = [deque(maxlen=PREVIEW_LIMIT) for _rule in search_rules]
        self.selected_result_index = 0
        self.preview_line_count = 0
        self.preview.configure(state="normal")
        self.preview.delete("1.0", "end")
        self.preview.configure(state="disabled")
        self.count_label.configure(text="0 行")
        self.status_label.configure(text="抽出中")
        self.current_label.configure(
            text=(
                f"出力先: {self.result_path}"
                if len(self.result_paths) == 1
                else f"出力先: {self.result_paths[0].parent}（{len(self.result_paths)}ファイル）"
            )
        )
        self.result_display_names = [
            f"{index}. {name}" for index, name in enumerate(self.result_names, start=1)
        ]
        self.result_selection_combo.configure(values=self.result_display_names, state="readonly")
        self.result_selection_combo.current(0)
        self.elapsed_label.configure(text="経過 00:00:00")
        self.progress_var.set(0)
        self.cancel_button.configure(state="normal")
        for button in (self.copy_button, self.save_button, self.open_button):
            button.configure(state="disabled")
        self.update_controls()
        paths = list(self.files)
        threading.Thread(target=self.run_search, args=(paths, search_rules), daemon=True).start()

    def run_search(self, paths: list[Path], rules: list[MultiSearchRule]) -> None:
        def emit(kind: str, payload: dict) -> None:
            event = (kind, payload)
            if kind in {"preview", "progress"}:
                try:
                    self.events.put_nowait(event)
                except queue.Full:
                    pass
            else:
                self.events.put(event)
        try:
            if len(rules) == 1:
                single_result = extract_logs(
                    paths,
                    rules[0].options,
                    rules[0].output_path,
                    self.cancel_event,
                    emit,
                )
                matches = [single_result.matches]
                file_errors = single_result.file_errors
            else:
                multi_result = extract_logs_multi(paths, rules, self.cancel_event, emit)
                matches = multi_result.matches
                file_errors = multi_result.file_errors
            emit(
                "finished",
                {
                    "matches": matches,
                    "file_errors": file_errors,
                    "cancelled": self.cancel_event.is_set(),
                },
            )
        except Exception as error:
            emit("error", {"message": str(error)})

    def poll_events(self) -> None:
        for _ in range(EVENTS_PER_POLL):
            try:
                kind, payload = self.events.get_nowait()
                if kind in {"preview", "marker"}:
                    rule_index = payload.get("rule", 0)
                    self.append_preview(rule_index, payload["lines"])
                    if "matches" in payload:
                        self.match_counts[rule_index] = payload["matches"]
                        if rule_index == self.selected_result_index:
                            self.match_count = payload["matches"]
                            self.count_label.configure(text=f"{self.match_count:,} 行")
                elif kind == "file":
                    label = "Shift_JIS" if payload["encoding"] == "cp932" else payload["encoding"].upper()
                    speed = "・高速" if payload.get("fast_path") else ""
                    self.current_label.configure(text=f"{payload['index']} / {payload['count']}  {payload['path']}  [{label}{speed}]")
                elif kind == "progress":
                    total = payload["total"]
                    self.progress_var.set(payload["done"] / total * 100 if total else 0)
                    self.progress_label.configure(text=f"{format_bytes(payload['done'])} / {format_bytes(total)}")
                elif kind == "file_error":
                    self.file_error_count += 1
                    self.status_label.configure(text=f"抽出中（{self.file_error_count}ファイルでエラー）")
                    self.current_label.configure(text=f"読み込みエラー: {payload['path']}")
                elif kind == "finished":
                    self.finish_search(payload["matches"], payload["file_errors"], payload["cancelled"])
                elif kind == "error":
                    self.fail_search(payload["message"])
            except queue.Empty:
                break
        if self.running and self.started_at is not None:
            self.elapsed_seconds = time.monotonic() - self.started_at
            self.elapsed_label.configure(text=f"経過 {format_elapsed(self.elapsed_seconds)}")
        self.root.after(1 if not self.events.empty() else 50, self.poll_events)

    def append_preview(self, rule_index: int, lines: list[str]) -> None:
        if not lines or not 0 <= rule_index < len(self.preview_buffers):
            return
        self.preview_buffers[rule_index].extend(lines)
        if rule_index != self.selected_result_index:
            return
        self.preview.configure(state="normal")
        self.preview.insert("end", "\n".join(lines) + "\n")
        self.preview_line_count += len(lines)
        if self.preview_line_count > PREVIEW_LIMIT:
            remove = self.preview_line_count - PREVIEW_LIMIT
            self.preview.delete("1.0", f"{remove + 1}.0")
            self.preview_line_count = PREVIEW_LIMIT
        self.preview.see("end")
        self.preview.configure(state="disabled")

    def render_selected_preview(self) -> None:
        lines = (
            list(self.preview_buffers[self.selected_result_index])
            if 0 <= self.selected_result_index < len(self.preview_buffers)
            else []
        )
        self.preview.configure(state="normal")
        self.preview.delete("1.0", "end")
        if lines:
            self.preview.insert("end", "\n".join(lines) + "\n")
            self.preview.see("end")
        self.preview.configure(state="disabled")
        self.preview_line_count = len(lines)

    def on_result_selected(self, _event: tk.Event | None = None) -> None:
        index = self.result_selection_combo.current()
        if index < 0 or index >= len(self.result_paths):
            return
        self.selected_result_index = index
        self.result_path = self.result_paths[index]
        self.match_count = self.match_counts[index] if index < len(self.match_counts) else 0
        self.count_label.configure(text=f"{self.match_count:,} 行")
        self.render_selected_preview()
        if not self.running:
            self.update_result_action_buttons()

    def selected_result_path(self) -> Path | None:
        if 0 <= self.selected_result_index < len(self.result_paths):
            return self.result_paths[self.selected_result_index]
        return None

    def update_result_action_buttons(self) -> None:
        path = self.selected_result_path()
        enabled = bool(path and path.exists() and not self.running)
        for button in (self.copy_button, self.save_button, self.open_button):
            button.configure(state="normal" if enabled else "disabled")

    def finish_search(self, matches: list[int], file_errors: int, cancelled: bool) -> None:
        self.freeze_elapsed_time()
        self.running = False
        self.match_counts = matches
        self.match_count = matches[self.selected_result_index]
        self.count_label.configure(text=f"{self.match_count:,} 行")
        if cancelled:
            status = "中止しました"
        elif file_errors:
            status = f"完了（{file_errors}ファイルでエラー）"
        else:
            status = "完了"
        self.status_label.configure(text=status)
        self.cancel_button.configure(state="disabled")
        self.update_controls()
        self.update_result_action_buttons()

    def fail_search(self, message: str) -> None:
        self.freeze_elapsed_time()
        self.running = False
        self.status_label.configure(text="エラー")
        result_note = ""
        if self.result_paths:
            saved_paths = "\n".join(str(path) for path in self.result_paths)
            result_note = f"\n\n途中までの抽出結果は保存されています。\n{saved_paths}"
        self.current_label.configure(text=f"エラー: {message}")
        self.cancel_button.configure(state="disabled")
        self.update_controls()
        self.update_result_action_buttons()
        messagebox.showerror("抽出エラー", message + result_note, parent=self.root)

    def cancel_search(self) -> None:
        self.cancel_event.set()
        self.cancel_button.configure(state="disabled")
        self.status_label.configure(text="中止処理中")

    def freeze_elapsed_time(self) -> None:
        if self.started_at is not None:
            self.elapsed_seconds = time.monotonic() - self.started_at
            self.started_at = None
        self.elapsed_label.configure(text=f"所要時間 {format_elapsed(self.elapsed_seconds)}")

    def save_result(self) -> None:
        result_path = self.selected_result_path()
        if not result_path:
            return
        destination = filedialog.asksaveasfilename(
            title="抽出結果を保存",
            defaultextension=".log",
            filetypes=(("ログファイル", "*.log"),),
            initialfile=result_path.name,
        )
        if destination:
            try:
                shutil.copyfile(result_path, destination)
                self.status_label.configure(text=f"保存しました: {destination}")
            except OSError as error:
                messagebox.showerror("保存エラー", str(error), parent=self.root)

    def copy_all(self) -> None:
        result_path = self.selected_result_path()
        if not result_path or not result_path.exists():
            return
        size = result_path.stat().st_size
        if size > COPY_WARNING_BYTES and not messagebox.askyesno(
            "大きな結果をコピー",
            f"結果は{format_bytes(size)}あります。クリップボードへのコピーに時間とメモリを使用します。続行しますか？",
            parent=self.root,
        ):
            return
        try:
            text = result_path.read_text(encoding="utf-8")
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
            self.root.update()
            self.status_label.configure(text=f"全結果をコピーしました（{format_bytes(size)}）")
        except Exception as error:
            messagebox.showerror("コピーエラー", str(error), parent=self.root)

    def open_result(self) -> None:
        result_path = self.selected_result_path()
        if result_path and result_path.exists():
            try:
                os.startfile(result_path)
            except OSError as error:
                messagebox.showerror("ファイルを開けません", str(error), parent=self.root)

    def on_close(self) -> None:
        if self.running and not messagebox.askyesno("終了", "抽出処理中です。中止して終了しますか？", parent=self.root):
            return
        if self.running:
            self.cancel_event.set()
            self.status_label.configure(text="結果を保存して終了中")
            self.cancel_button.configure(state="disabled")
            self.root.after(50, self.wait_for_worker_before_close)
            return
        self.root.destroy()

    def wait_for_worker_before_close(self) -> None:
        if self.running:
            self.root.after(50, self.wait_for_worker_before_close)
        else:
            self.root.destroy()

    def run(self) -> None:
        self.root.mainloop()


if __name__ == "__main__":
    LogCatchApp().run()
