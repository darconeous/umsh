#!/usr/bin/env python3
"""mdBook preprocessor for the UEP book in docs/protocol.

Replaces the TOML header at the top of each UEP or draft with its title and
a summary table, and fails the build on a header that breaks the rules in
UEP-0001. Chapters without a header pass through unchanged.
"""

import json
import os
import re
import sys
import tomllib

TYPES = {"standards", "informational", "profile", "process"}
DRAFT_STATUSES = {"draft", "abandoned"}
UEP_STATUSES = {"experimental", "final", "active", "withdrawn", "superseded"}
LIST_FIELDS = ["requires", "see-also", "obsoletes", "superseded-by"]
UEP_FIELDS = {"uep", "title", "type", "status", "revision", "draft", *LIST_FIELDS}
DRAFT_FIELDS = {"name", "title", "type", "status", "revision", "requires", "see-also"}
DRAFT_NAME = re.compile(r"draft-uep-[a-z0-9]+-[a-z0-9]+(?:-[a-z0-9]+)*")


class HeaderError(Exception):
    pass


def split_header(content):
    if content.startswith("+++\r\n"):
        content = content.replace("\r\n", "\n")
    if not content.startswith("+++\n"):
        if content.lstrip("﻿ \t\r\n").startswith("+++"):
            raise HeaderError("header does not begin on the first line")
        return None, content
    end = content.find("\n+++\n", 3)
    if end < 0:
        raise HeaderError("header has no closing +++")
    try:
        header = tomllib.loads(content[4 : end + 1])
    except tomllib.TOMLDecodeError as e:
        raise HeaderError(f"header is not valid TOML: {e}")
    return header, content[end + 5 :]


def is_number(value):
    return isinstance(value, int) and not isinstance(value, bool)


def is_reference(value):
    if is_number(value):
        return 1 <= value <= 9999
    return isinstance(value, str) and DRAFT_NAME.fullmatch(value) is not None


def check(header, path):
    is_uep = "uep" in header
    allowed = UEP_FIELDS if is_uep else DRAFT_FIELDS
    statuses = UEP_STATUSES if is_uep else DRAFT_STATUSES
    for key in ("uep" if is_uep else "name", "title", "type", "status", "revision"):
        if key not in header:
            raise HeaderError(f"missing field `{key}`")
    unknown = set(header) - allowed
    if unknown:
        raise HeaderError(f"unknown fields: {', '.join(sorted(unknown))}")
    for key in ("name", "title", "type", "status", "draft"):
        if key in header and not isinstance(header[key], str):
            raise HeaderError(f"`{key}` is not a string")
    if not is_number(header["revision"]) or header["revision"] < (1 if is_uep else 0):
        raise HeaderError("`revision` is not a revision number")
    if is_uep:
        if not is_number(header["uep"]) or not 1 <= header["uep"] <= 9999:
            raise HeaderError("`uep` is not a number from 1 to 9999")
        expected = f"uep-{header['uep']:04}.md"
    else:
        if not DRAFT_NAME.fullmatch(header["name"]):
            raise HeaderError("`name` is not of the form draft-uep-<editor>-<title>")
        expected = os.path.join("drafts", f"{header['name']}.md")
    if os.path.normpath(path) != expected:
        raise HeaderError(f"the header names this file `{expected}`")
    if "draft" in header and not DRAFT_NAME.fullmatch(header["draft"]):
        raise HeaderError("`draft` is not of the form draft-uep-<editor>-<title>")
    if header["type"] not in TYPES:
        raise HeaderError(f"unknown type `{header['type']}`")
    if header["status"] not in statuses:
        raise HeaderError(f"status `{header['status']}` does not apply here")
    if header["status"] == "active" and header["type"] != "process":
        raise HeaderError("only a process UEP can be active")
    if header["status"] == "superseded" and not header.get("superseded-by"):
        raise HeaderError("a superseded UEP needs `superseded-by`")
    for key in LIST_FIELDS:
        values = header.get(key, [])
        if not isinstance(values, list) or not all(is_reference(v) for v in values):
            raise HeaderError(f"`{key}` is not a list of UEP numbers and draft names")
    if is_uep:
        later = [n for n in header.get("requires", []) if is_number(n) and n >= header["uep"]]
        if later:
            raise HeaderError(
                "requires UEPs that come after it: " + ", ".join(f"UEP-{n:04}" for n in later)
            )


def link(value, src, chapter_dir):
    if isinstance(value, int):
        label, target = f"UEP-{value:04}", f"uep-{value:04}.md"
    else:
        label, target = value, f"drafts/{value}.md"
    if not os.path.exists(os.path.join(src, target)):
        return label
    return f"[{label}]({os.path.relpath(target, chapter_dir or '.')})"


def render(header, src, chapter_dir):
    if "uep" in header:
        title = f"# UEP-{header['uep']:04}: {header['title']}"
        cells = [("Type", header["type"]), ("Status", header["status"]), ("Revision", header["revision"])]
    else:
        title = f"# {header['title']}"
        cells = [
            ("Draft", f"`{header['name']}-{header['revision']:02}`"),
            ("Type", header["type"]),
            ("Status", header["status"]),
        ]
    cells = [(k, str(v).capitalize() if k in ("Type", "Status") else v) for k, v in cells]
    for key in LIST_FIELDS:
        if header.get(key):
            label = key.replace("-", " ").capitalize()
            cells.append((label, ", ".join(link(v, src, chapter_dir) for v in header[key])))
    if header.get("draft"):
        cells.append(("Accepted from", f"`{header['draft']}`"))
    head = "| " + " | ".join(k for k, _ in cells) + " |"
    rule = "|" + "---|" * len(cells)
    row = "| " + " | ".join(str(v) for _, v in cells) + " |"
    return f"{title}\n\n{head}\n{rule}\n{row}\n\n"


def walk(items, src, errors):
    for item in items:
        chapter = item.get("Chapter") if isinstance(item, dict) else None
        if not chapter:
            continue
        path = chapter.get("source_path") or chapter.get("path")
        if path:
            try:
                header, body = split_header(chapter["content"])
                if header is not None:
                    check(header, path)
                    chapter["content"] = render(header, src, os.path.dirname(path)) + body
            except HeaderError as e:
                errors.append(f"{path}: {e}")
        walk(chapter.get("sub_items", []), src, errors)


def main():
    if len(sys.argv) > 1:
        # `supports <renderer>`: the rendered output is plain Markdown.
        sys.exit(0)
    context, book = json.load(sys.stdin)
    src = os.path.join(context["root"], context["config"]["book"].get("src", "src"))
    errors = []
    walk(book.get("items", book.get("sections", [])), src, errors)
    if errors:
        for error in errors:
            print(f"uep: {error}", file=sys.stderr)
        sys.exit(1)
    json.dump(book, sys.stdout)


if __name__ == "__main__":
    main()
