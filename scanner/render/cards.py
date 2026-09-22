"""The per-finding <details> card, plus the two free-text helpers it needs."""
import html

from scanner.cvss import score_for, vector_for
from scanner.render.verdicts import _cwe_text, risk_level, short_location, verdict_of, vuln_type_label

def _card_html(item: dict) -> str:
    finding = item.get("finding") or {}
    badge_key = filter_bucket = verdict_of(item)
    label_key = "static" if finding.get("verdict_kind") == "static" else badge_key
    badge_class = {"yes": "badge-yes", "no": "badge-no", "failed": "badge-failed",
                   "unverified": "badge-unverified"}.get(badge_key, "badge-uncertain")

    rule_ids = ", ".join(item.get("rule_ids", [item.get("rule_id", "")]))
    message = " / ".join(item.get("messages", [item.get("message", "")]))
    confidence = finding.get("confidence")
    vuln_type = vuln_type_label(item)
    severity = item.get("severity") or "UNKNOWN"
    risk = risk_level(item)
    score = score_for(item)
    vector = vector_for(item)

    return f"""
    <details class="card" data-bucket="{filter_bucket}" data-type="{html.escape(vuln_type)}"
              data-file="{html.escape(item["sink_file"])}" data-severity="{risk}">
      <summary title="{html.escape(item["sink_file"])}:{item["sink_line"]}">
        <span class="badge {badge_class}" data-i18n="reachable.{label_key}"></span>
        <span class="vuln-type">{html.escape(vuln_type)}</span>
        <span class="severity risk-{risk}" data-i18n="risk.{risk}" title="CVSS {score:.1f} (CVSS:3.1/{html.escape(vector)}) · Semgrep: {html.escape(severity)}"></span>
        <span class="cvss" title="CVSS:3.1/{html.escape(vector)}">CVSS {score:.1f}</span>
        <span class="location"><span class="loc-path">{html.escape(short_location(item["sink_file"]))}</span><span class="loc-line">:{item["sink_line"]}</span></span>
        <span class="rule" title="{html.escape(rule_ids)}">{html.escape(rule_ids)}</span>
      </summary>
      <div class="card-body">
        <p><strong data-i18n="card.type"></strong> {html.escape(vuln_type)}</p>
        <p><strong data-i18n="card.rule"></strong> {html.escape(message)}</p>
        <p><strong data-i18n="card.cwe"></strong> {html.escape(_cwe_text(item) or "-")}
           &nbsp;·&nbsp; <strong data-i18n="card.source"></strong> {html.escape(item["source_file"])}:{item["source_line"]}</p>
        {f'<p><strong data-i18n="card.confidence"></strong> {html.escape(str(confidence))}</p>' if confidence is not None else ""}
        {_duplicates_html(item)}
        {f'<p class="unverified-note" data-i18n="card.unverifiedNote"></p>' if not finding
          else f'<p><strong data-i18n="card.reasoning"></strong> {_bilingual(finding, "reasoning")}</p>'}
        {f'<p><strong data-i18n="card.exploit"></strong> {_bilingual(finding, "exploit_scenario")}</p>' if finding.get("exploit_scenario") else ""}
        {f'<p class="remediation"><strong data-i18n="card.remediation"></strong> {_bilingual(finding, "remediation")}</p>' if finding.get("remediation") else ""}
      </div>
    </details>
    """


def _bilingual(finding: dict, field: str) -> str:
    """A span carrying both languages of one LLM free-text field, swapped by
    the page's applyI18n() exactly like a data-i18n label.

    Falls back to the single original on both sides when 04_translate.py has
    not run, so an untranslated report renders precisely as it did before --
    the stage is optional and the reader should not be able to tell it was
    skipped except by the language not changing.
    """
    # LLM free-text fields are usually strings, but some providers have been
    # seen putting a bare number in one instead of the expected prose (see
    # scanner/render/verdicts.py's verifier_failed check for the same class
    # of bug) -- str() here keeps html.escape() from crashing on that.
    original = str(finding.get(field) or "")
    zh = str(finding.get(f"{field}_zh") or original)
    en = str(finding.get(f"{field}_en") or original)
    if not original:
        return ""
    return (f'<span data-text-zh="{html.escape(zh)}" data-text-en="{html.escape(en)}">'
            f'{html.escape(original)}</span>')


def _duplicates_html(item: dict) -> str:
    """The other paths carrying this exact code, when dedup_copies() merged
    a copied module. Verified once, but the reader still has to be told
    every place it lives, or the merge reads as a missing finding."""
    paths = item.get("duplicate_locations") or []
    if not paths:
        return ""
    joined = ", ".join(html.escape(p) for p in paths)
    return f'<p><strong data-i18n="card.duplicates"></strong> {joined}</p>'


