#!/usr/bin/env python3
"""mdBook preprocessor for the UEP book in docs/protocol.

Replaces the TOML header at the top of each UEP or draft with its title and
a summary table, and fails the build on a header that breaks the rules in
UEP-0001. Replaces each `{{#registry NAME}}` with the registry kept in
registries/NAME.toml, rendered as a table. Other chapters pass through
unchanged.
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
REGISTRY = re.compile(r"\{\{#registry ([a-z0-9-]+)\}\}")
LOOSE_REGISTRY = re.compile(r"\{\{\s*#\s*registry\b[^}]*\}\}", re.IGNORECASE)
CODE = re.compile(r"(?ms)^ {0,3}(```|~~~).*?^ {0,3}\1[^\n]*$|`[^`\n]+`")


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


def link(value, src, chapter_dir, anchor=None):
    if isinstance(value, int):
        label, target = f"UEP-{value:04}", f"uep-{value:04}.md"
    else:
        label, target = value, f"drafts/{value}.md"
    if not os.path.exists(os.path.join(src, target)):
        return label
    fragment = f"#{anchor}" if anchor else ""
    return f"[{label}]({os.path.relpath(target, chapter_dir or '.')}{fragment})"


def need(table, key, kind, where, optional=False):
    if key not in table:
        if optional:
            return None
        raise HeaderError(f"{where}: missing `{key}`")
    value = table[key]
    ok = is_number(value) if kind is int else isinstance(value, kind)
    if not ok:
        raise HeaderError(f"{where}: `{key}` has the wrong type")
    return value


def only(table, keys, where):
    if not isinstance(table, dict):
        raise HeaderError(f"{where}: is not a table")
    unknown = set(table) - keys
    if unknown:
        raise HeaderError(f"{where}: unknown fields: {', '.join(sorted(unknown))}")


def render_registry(name, root, src, chapter_dir):
    """Renders registries/<name>.toml as a page: its title, the UEP that
    created it, its allocation policy, and one row per value or range.

    A registry file holds `title`, `created-by` (a UEP number), an optional
    `anchor` in that UEP, `policy` (Markdown), and `min` and `max`, the
    bounds of its value space. Each `[[range]]` has `from`, `to`, and `use`
    (`reserved`, `experimental`, or `private`); ranges do not overlap. Each
    `[[value]]` has `value`, `name`, one of `uep` or `draft`, and an optional
    `anchor` and `deprecated`; no value is allocated twice or inside a range.

    Each `[[source]]` lists values the project assigns outside the series,
    from a JSON file: `file` (relative to the book's root), `list` (the key
    of its array of objects), `value` and `name` (the keys of each object's
    value and name), and `from` and `to`, the span its values must fall in.
    Their rows carry no reference."""
    path = os.path.join(root, "registries", f"{name}.toml")
    try:
        with open(path, "rb") as f:
            registry = tomllib.load(f)
    except FileNotFoundError:
        raise HeaderError(f"no registry file `registries/{name}.toml`")
    except tomllib.TOMLDecodeError as e:
        raise HeaderError(f"registries/{name}.toml is not valid TOML: {e}")
    where = f"registries/{name}.toml"
    only(registry, {"title", "created-by", "anchor", "policy", "min", "max", "range", "value",
                    "source"}, where)
    title = need(registry, "title", str, where)
    created_by = need(registry, "created-by", int, where)
    policy = need(registry, "policy", str, where)
    anchor = need(registry, "anchor", str, where, optional=True)
    lowest = need(registry, "min", int, where)
    highest = need(registry, "max", int, where)
    if not 1 <= created_by <= 9999:
        raise HeaderError(f"{where}: `created-by` is not a UEP number")
    if not 0 <= lowest <= highest:
        raise HeaderError(f"{where}: `min` and `max` are not a valid span")

    def within(value):
        return lowest <= value <= highest

    rows = []
    ranges = []
    for item in need(registry, "range", list, where, optional=True) or []:
        only(item, {"from", "to", "use"}, f"{where} range")
        low = need(item, "from", int, f"{where} range")
        high = need(item, "to", int, f"{where} range")
        use = need(item, "use", str, f"{where} range")
        if use not in ("reserved", "experimental", "private") or low > high or not (within(low) and within(high)):
            raise HeaderError(f"{where}: range {low}–{high} is not valid")
        if any(low <= other_high and other_low <= high for other_low, other_high in ranges):
            raise HeaderError(f"{where}: range {low}–{high} overlaps another")
        ranges.append((low, high))
        span = str(low) if low == high else f"{low}–{high}"
        label = "Private use" if use == "private" else use.capitalize()
        rows.append((low, span, f"*{label}*", ""))
    seen = set()
    for item in need(registry, "value", list, where, optional=True) or []:
        only(item, {"value", "name", "uep", "draft", "anchor", "deprecated"}, f"{where} value")
        value = need(item, "value", int, f"{where} value")
        here = f"{where} value {value}"
        if not within(value):
            raise HeaderError(f"{here}: outside {lowest}–{highest}")
        label = need(item, "name", str, here).replace("|", "\\|")
        uep = need(item, "uep", int, here, optional=True)
        draft = need(item, "draft", str, here, optional=True)
        if (uep is None) == (draft is None) or not is_reference(uep if uep is not None else draft):
            raise HeaderError(f"{here}: needs one `uep` number or `draft` name")
        if value in seen or any(low <= value <= high for low, high in ranges):
            raise HeaderError(f"{here}: allocated twice, or inside a range")
        seen.add(value)
        if need(item, "deprecated", bool, here, optional=True):
            label += " (deprecated)"
        reference = link(uep if uep is not None else draft, src, chapter_dir,
                         need(item, "anchor", str, here, optional=True))
        rows.append((value, str(value), label, reference))

    for item in need(registry, "source", list, where, optional=True) or []:
        only(item, {"file", "list", "value", "name", "from", "to"}, f"{where} source")
        file = need(item, "file", str, f"{where} source")
        here = f"{where} source `{file}`"
        low = need(item, "from", int, here)
        high = need(item, "to", int, here)
        try:
            with open(os.path.join(root, file), encoding="utf-8") as f:
                entries = json.load(f)[need(item, "list", str, here)]
        except (OSError, ValueError, KeyError, TypeError) as e:
            raise HeaderError(f"{here}: cannot read its list: {e}")
        value_key = need(item, "value", str, here)
        name_key = need(item, "name", str, here)
        for entry in entries:
            value = entry.get(value_key) if isinstance(entry, dict) else None
            name = entry.get(name_key) if isinstance(entry, dict) else None
            if not is_number(value) or not isinstance(name, str):
                raise HeaderError(f"{here}: an entry lacks `{value_key}` or `{name_key}`")
            if not (low <= value <= high and within(value)):
                raise HeaderError(f"{here}: value {value} outside {low}–{high}")
            if value in seen or any(a <= value <= b for a, b in ranges):
                raise HeaderError(f"{here}: value {value} allocated twice, or inside a range")
            seen.add(value)
            rows.append((value, str(value), name.replace("|", "\\|"), ""))

    rows.sort(key=lambda row: row[0])
    table = ["| Value | Name | Reference |", "|---:|---|---|"]
    table += [f"| {span} | {label} | {reference} |" for _, span, label, reference in rows]
    created = link(created_by, src, chapter_dir, anchor)
    return f"# {title}\n\nCreated by {created}. {policy}\n\n" + "\n".join(table) + "\n"


def code_spans(content):
    """The spans of `content` inside fenced code blocks or inline code."""
    return [m.span() for m in CODE.finditer(content)]


def expand_registries(content, root, src, chapter_dir, rendered):
    spans = code_spans(content)

    def in_code(position):
        return any(start <= position < end for start, end in spans)

    for m in LOOSE_REGISTRY.finditer(content):
        if not in_code(m.start()) and not REGISTRY.fullmatch(m.group(0)):
            raise HeaderError(f"malformed registry directive `{m.group(0)}`")

    def replace(m):
        if in_code(m.start()):
            return m.group(0)
        rendered.add(m.group(1))
        return render_registry(m.group(1), root, src, chapter_dir)

    return REGISTRY.sub(replace, content)


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


def walk(items, root, src, errors, rendered):
    for item in items:
        chapter = item.get("Chapter") if isinstance(item, dict) else None
        if not chapter:
            continue
        path = chapter.get("source_path") or chapter.get("path")
        if path:
            chapter_dir = os.path.dirname(path)
            try:
                header, body = split_header(chapter["content"])
                if header is not None:
                    check(header, path)
                    chapter["content"] = render(header, src, chapter_dir) + body
                chapter["content"] = expand_registries(
                    chapter["content"], root, src, chapter_dir, rendered
                )
            except HeaderError as e:
                errors.append(f"{path}: {e}")
        walk(chapter.get("sub_items", []), root, src, errors, rendered)


def main():
    if len(sys.argv) > 1:
        # `supports <renderer>`: the rendered output is plain Markdown.
        sys.exit(0)
    context, book = json.load(sys.stdin)
    src = os.path.join(context["root"], context["config"]["book"].get("src", "src"))
    errors = []
    rendered = set()
    walk(book.get("items", book.get("sections", [])), context["root"], src, errors, rendered)
    # A registry no page includes is still checked.
    registry_dir = os.path.join(context["root"], "registries")
    for file in sorted(os.listdir(registry_dir)) if os.path.isdir(registry_dir) else []:
        name, ext = os.path.splitext(file)
        if ext == ".toml" and name not in rendered:
            try:
                render_registry(name, context["root"], src, "registries")
            except HeaderError as e:
                errors.append(str(e))
    if errors:
        for error in errors:
            print(f"uep: {error}", file=sys.stderr)
        sys.exit(1)
    json.dump(book, sys.stdout)


if __name__ == "__main__":
    main()
