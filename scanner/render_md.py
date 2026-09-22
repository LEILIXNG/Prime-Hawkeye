"""G': the verified-candidates list rendered as Markdown, for export.

Kept out of render.py, which is the HTML page plus its inline CSS and JS and
is long enough already. The two share the classification helpers --
verdict_of, risk_level, vuln_type_label -- so a finding is graded identically
in both, and nothing else.

Markdown is generated on demand from the stored report.json rather than
written by the pipeline: an export format that only exists for scans run
after it shipped would be useless on the reports already on disk.
"""
from scanner.cvss import score_for, vector_for
from scanner.render import RISK_LEVELS, build_summary, risk_level, vuln_type_label
from scanner.report_i18n import DEFAULT_LANG, REPORT_I18N


def _t(lang: str, path: str) -> str:
    node = REPORT_I18N[lang]
    for key in path.split("."):
        node = node[key]
    return node


def _prose(finding: dict, field: str, lang: str) -> str:
    """One LLM free-text field in the requested language, falling back to the
    original when 04_translate.py never ran for this report."""
    # str() guards the same way scanner/render/cards.py's _bilingual does --
    # some providers have been seen putting a bare number in a field the
    # rest of this pipeline assumes is always prose.
    return str(finding.get(f"{field}_{lang}") or finding.get(field) or "").strip()


def _one_line(text: str) -> str:
    """LLM prose can carry newlines, which would break out of a table cell or
    a list item. Collapse it to one line."""
    return " ".join(text.split())


def _path(path: str, line: int) -> str:
    """A file:line reference with forward slashes.

    Paths are stored with whatever separator the scanning machine used, so a
    Windows scan exports `src\\main\\java\\A.java`. An exported report gets
    read and pasted somewhere else; the separator should not advertise which
    machine produced it.
    """
    return f'`{path.replace(chr(92), "/")}:{line}`'


def _cwe_text(item: dict) -> str:
    cwe = item.get("cwe")
    if isinstance(cwe, list):
        return cwe[0] if cwe else ""
    return cwe or ""


def _summary_table(verified: list[dict], lang: str) -> list[str]:
    summary = build_summary(verified)
    headers = [
        (_t(lang, "stats.total"), summary["total"]),
        (_t(lang, "stats.reachable"), summary["reachable"]),
        (_t(lang, "stats.safe"), summary["not_reachable"]),
        (_t(lang, "stats.needsReview"),
         summary["uncertain"] + summary["verifier_failed"] + summary.get("unverified", 0)),
    ]
    return [
        "| " + " | ".join(label for label, _ in headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
        "| " + " | ".join(str(value) for _, value in headers) + " |",
    ]


def _finding_lines(item: dict, index: int, lang: str) -> list[str]:
    finding = item.get("finding") or {}
    lines = [f'### {index}. {vuln_type_label(item)} — {_path(item["sink_file"], item["sink_line"])}', ""]

    def field(label_key: str, value: str) -> None:
        if value:
            lines.append(f"- **{_t(lang, label_key)}** {value}")

    field("card.source", _path(item["source_file"], item["source_line"]))
    field("card.cvss", f'{score_for(item):.1f} (`CVSS:3.1/{vector_for(item)}`)')
    field("card.cwe", _cwe_text(item))
    field("card.rule", _one_line(" / ".join(item.get("messages", [item.get("message", "")]))))
    confidence = finding.get("confidence")
    if confidence is not None:
        field("card.confidence", str(confidence))
    duplicates = item.get("duplicate_locations") or []
    if duplicates:
        field("card.duplicates", ", ".join(f'`{path.replace(chr(92), "/")}`' for path in duplicates))
    field("card.reasoning", _one_line(_prose(finding, "reasoning", lang)))
    field("card.exploit", _one_line(_prose(finding, "exploit_scenario", lang)))
    field("card.remediation", _one_line(_prose(finding, "remediation", lang)))
    lines.append("")
    return lines


def render_markdown(verified: list[dict], project_name: str, lang: str = DEFAULT_LANG) -> str:
    if lang not in REPORT_I18N:
        lang = DEFAULT_LANG

    lines = [f'# {_t(lang, "reportTitle")} — {project_name}', ""]
    lines += _summary_table(verified, lang)
    lines.append("")

    # Grouped by risk rather than listed flat: the point of an exported
    # report is that someone reads it top to bottom, and the 致命 findings
    # are the ones that have to be at the top.
    by_level: dict[str, list[dict]] = {level: [] for level in RISK_LEVELS}
    for item in verified:
        by_level[risk_level(item)].append(item)

    for level in RISK_LEVELS:
        items = by_level[level]
        if not items:
            continue
        lines.append(f'## {_t(lang, f"risk.{level}")} ({len(items)})')
        lines.append("")
        for index, item in enumerate(sorted(items, key=lambda i: (i["sink_file"], i["sink_line"])), start=1):
            lines += _finding_lines(item, index, lang)

    if not verified:
        lines.append(_t(lang, "empty.noFindings"))
        lines.append("")

    return "\n".join(lines)
