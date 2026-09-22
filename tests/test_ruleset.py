"""Guards for rules/ruleset.yml and the hand-written rules under
rules/custom/.

None of this needs an LLM or a scan target -- it is all things that
currently only surface as a broken (or silently degraded) scan:

  - a typo'd path in ruleset.yml makes semgrep skip that whole config
    with a warning the pipeline does not treat as fatal;
  - a custom rule with malformed YAML is rejected by semgrep at scan time,
    not at edit time;
  - a custom rule missing metadata.cwe still fires, but render.py's
    vuln_type_label() falls back to "Uncategorized", so the finding is
    quietly unlabelled in the report instead of erroring;
  - an exclude_paths glob that matches nothing (see the anchoring trap in
    ruleset.yml) excludes nothing, and a scan that got noisier is not a
    failure anyone notices.
"""
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from scanner.common import (
    ROOT,
    RULESET_PATH,
    load_default_configs,
    load_excluded_paths,
    load_excluded_rules,
    load_out_of_scope_cwes,
)
from scanner.core import drop_excluded_paths, path_is_excluded

CUSTOM_RULES_DIR = ROOT / "rules" / "custom"
REQUIRED_RULE_FIELDS = ("id", "languages", "severity", "message")


def decoded(stream):
    return stream.decode("utf-8", errors="replace") if isinstance(stream, bytes) else (stream or "")


def semgrep_env(settings_dir: Path):
    env = os.environ.copy()
    env["PYTHONUTF8"] = "1"
    env["SEMGREP_SETTINGS_FILE"] = str(settings_dir / "semgrep-settings.yml")
    return env


def custom_rule_files():
    return sorted(p for p in CUSTOM_RULES_DIR.rglob("*") if p.suffix in (".yml", ".yaml"))


# A rule's fixture is the sibling file with the same stem. The extension
# follows the rule's target language rather than being assumed: the MyBatis
# rule matches mapper XML, so hard-coding .java would have silently reported
# it as having no fixture.
FIXTURE_SUFFIXES = (".java", ".xml", ".cpp", ".cc", ".cxx", ".hpp", ".hh", ".hxx", ".h", ".py", ".rs", ".kt", ".cs")


def fixture_for(rule_path):
    for suffix in FIXTURE_SUFFIXES:
        candidate = rule_path.with_suffix(suffix)
        if candidate.exists():
            return candidate
    return None


def custom_rules():
    for path in custom_rule_files():
        doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        for rule in doc.get("rules", []):
            yield path, rule


class TestRulesetFile:
    def test_configs_is_a_non_empty_list_of_strings(self):
        ruleset = yaml.safe_load(RULESET_PATH.read_text(encoding="utf-8"))
        configs = ruleset["configs"]
        assert isinstance(configs, list) and configs
        assert all(isinstance(c, str) and c for c in configs)

    def test_paths_are_repo_relative(self):
        """An absolute path here would work on whoever added it and break
        for everyone else."""
        ruleset = yaml.safe_load(RULESET_PATH.read_text(encoding="utf-8"))
        for entry in ruleset["configs"]:
            assert not entry.startswith(("/", "\\")) and ":" not in entry, entry
            assert ".." not in entry.split("/"), entry

    def test_exclude_rules_is_a_list_of_strings(self):
        ruleset = yaml.safe_load(RULESET_PATH.read_text(encoding="utf-8"))
        excluded = ruleset.get("exclude_rules") or []
        assert isinstance(excluded, list)
        assert all(isinstance(r, str) and r.strip() for r in excluded)
        assert len(set(excluded)) == len(excluded), "duplicate ids in exclude_rules"

    def test_excluded_rules_are_loaded_verbatim(self):
        """`--exclude-rule` matches on the exact id, so anything that looks
        like a path or a glob here would silently exclude nothing."""
        for rule_id in load_excluded_rules():
            assert "/" not in rule_id and "*" not in rule_id, rule_id

    def test_out_of_scope_cwes_are_bare_ids(self):
        """Compared against the id Semgrep reports ("CWE-327: Use of a Broken
        ... Algorithm"), so a description or a lowercase id here would match
        nothing and silently widen the scope back."""
        ruleset = yaml.safe_load(RULESET_PATH.read_text(encoding="utf-8"))
        listed = ruleset.get("out_of_scope_cwes") or []
        assert isinstance(listed, list)
        assert len(set(listed)) == len(listed), "duplicate ids in out_of_scope_cwes"
        for entry in listed:
            assert isinstance(entry, str) and re.fullmatch(r"CWE-\d+", entry.strip()), entry

    def test_no_dataflow_weakness_is_declared_out_of_scope(self):
        """The scope rule is that a weakness needs a source -> sink path, so
        the injection and traversal CWEs are what this list must never
        contain -- putting one here would delete the tool's whole purpose."""
        dataflow = {"CWE-22", "CWE-77", "CWE-78", "CWE-79", "CWE-89", "CWE-90",
                    "CWE-94", "CWE-95", "CWE-434", "CWE-470", "CWE-502",
                    "CWE-601", "CWE-611", "CWE-643", "CWE-918"}
        assert not (load_out_of_scope_cwes() & dataflow)

    def test_exclude_paths_is_a_list_of_strings(self):
        ruleset = yaml.safe_load(RULESET_PATH.read_text(encoding="utf-8"))
        excluded = ruleset.get("exclude_paths") or []
        assert isinstance(excluded, list)
        assert all(isinstance(g, str) and g.strip() for g in excluded)
        assert len(set(excluded)) == len(excluded), "duplicate globs in exclude_paths"

    def test_multi_segment_globs_carry_no_globstar_prefix(self):
        """The inverse of what this asserted until 2026-09-09.

        `**/src/it` was believed to lift semgrep's anchoring. Measured
        against the pinned 1.173.0 it does the opposite: the pattern then
        matches nothing at all, which is why both integration-test entries
        had been dead since they were written. Depth is handled by
        scanner/core.py:drop_excluded_paths instead, which reads a glob as a
        run of consecutive path segments -- so the prefix is not just
        useless here, it would be a second thing to strip.
        """
        for glob in load_excluded_paths():
            assert not glob.startswith("**/"), (
                f"{glob!r} starts with `**/`, which semgrep matches against nothing. "
                "Write it as `" + glob.removeprefix("**/") + "`."
            )

    def test_exclude_paths_are_relative_globs(self):
        """An absolute path, or one climbing out of the target, cannot match
        anything inside an uploaded workspace."""
        for glob in load_excluded_paths():
            assert not glob.startswith(("/", "\\")) and ":" not in glob, glob
            assert ".." not in glob.split("/"), glob

    def test_every_config_path_exists(self):
        missing = [c for c in load_default_configs() if not (ROOT / c).exists()]
        assert not missing, (
            f"ruleset.yml points at paths that do not exist: {missing}. "
            "If these are under rules/vendor/, the submodule is probably not "
            "checked out -- run `git submodule update --init --recursive`."
        )


class TestCustomRules:
    def test_there_is_at_least_one_custom_rule(self):
        assert list(custom_rules()), "rules/custom is listed in ruleset.yml but holds no rules"

    def test_required_fields_are_present(self):
        for path, rule in custom_rules():
            for field in REQUIRED_RULE_FIELDS:
                assert rule.get(field), f"{path.name}: rule is missing `{field}`"

    def test_rule_ids_are_unique(self):
        seen = {}
        for path, rule in custom_rules():
            rule_id = rule["id"]
            assert rule_id not in seen, f"duplicate rule id `{rule_id}` in {path.name} and {seen[rule_id]}"
            seen[rule_id] = path.name

    def test_cwe_metadata_is_usable_by_the_renderer(self):
        """render.py derives the report's vulnerability-type label from this
        field, so a rule without it lands under "Uncategorized" silently."""
        for path, rule in custom_rules():
            cwe = (rule.get("metadata") or {}).get("cwe")
            assert isinstance(cwe, list) and cwe, f"{path.name}: `{rule['id']}` has no metadata.cwe list"
            for entry in cwe:
                assert entry.startswith("CWE-"), f"{path.name}: cwe entry does not start with CWE-: {entry!r}"


@pytest.mark.skipif(shutil.which("semgrep") is None, reason="semgrep is not installed")
def test_semgrep_accepts_the_whole_ruleset(tmp_path):
    """Catches malformed custom rules, and vendored rules that the pinned
    semgrep version can no longer parse after a submodule bump."""
    cmd = ["semgrep", "scan", "--validate", "--metrics=off"]
    for config in load_default_configs():
        cmd += ["--config", config]

    proc = subprocess.run(cmd, capture_output=True, env=semgrep_env(tmp_path))
    stdout, stderr = decoded(proc.stdout), decoded(proc.stderr)
    assert proc.returncode == 0, f"semgrep rejected the ruleset:\n{stdout}\n{stderr}"


@pytest.mark.skipif(shutil.which("semgrep") is None, reason="semgrep is not installed")
def test_semgrep_exclude_covers_the_bare_name_globs(tmp_path):
    """What semgrep's own --exclude does keep out, so the pipeline is not
    paying to scan it. Only the entries without a slash: a pattern
    containing one is anchored to the scan root, which an ingested zip
    always sits below -- those are enforced by drop_excluded_paths instead,
    and covered by the test below.
    """
    def plant(rel: str):
        target = tmp_path / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("class V {}\n", encoding="utf-8")

    plant("src/main/java/Kept.java")  # control: must survive every exclusion
    expected_excluded = set()
    for glob in load_excluded_paths():
        if "/" in glob:
            continue
        if "*" in glob:  # file glob, e.g. *.min.js or *_test.go
            paths = [f"a{glob[1:]}", f"moduleA/b{glob[1:]}"]
        else:
            paths = [f"{glob}/V.java", f"moduleA/{glob}/V.java"]
        for rel in paths:
            plant(rel)
            expected_excluded.add(rel)

    cmd = ["semgrep", "--json", "--metrics=off", "--no-git-ignore",
           "--config", str(ROOT / "rules" / "custom")]
    for glob in load_excluded_paths():
        cmd += ["--exclude", glob]
    cmd.append(str(tmp_path))

    proc = subprocess.run(cmd, capture_output=True, env=semgrep_env(tmp_path))
    assert proc.returncode in (0, 1), f"semgrep failed:\n{decoded(proc.stderr)}"

    scanned = {
        str(Path(p).resolve().relative_to(tmp_path.resolve())).replace("\\", "/")
        for p in json.loads(decoded(proc.stdout)).get("paths", {}).get("scanned", [])
    }
    assert "src/main/java/Kept.java" in scanned, (
        "the exclusions swallowed ordinary source code: " + repr(sorted(scanned))
    )
    leaked = sorted(expected_excluded & scanned)
    assert not leaked, f"exclude_paths did not keep these out of the scan: {leaked}"


def test_every_configured_glob_excludes_at_any_depth():
    """The guarantee the ruleset file states, which is the tool's to keep.

    A zip is unpacked one or more levels below the scan root, so an entry
    that only works at the top level does nothing on a real target -- which
    is exactly what `**/src/it` had been doing.
    """
    for glob in load_excluded_paths():
        stem = glob.removeprefix("**/")
        if stem.startswith("*."):
            leaf = f"a{stem[1:]}"
        else:
            leaf = f"{stem}/V.java"
        for prefix in ("", "moduleA/", "p14/b/nested/"):
            assert path_is_excluded(prefix + leaf, load_excluded_paths()), (
                f"{glob!r} does not exclude {prefix + leaf!r}"
            )


def test_exclusions_do_not_swallow_ordinary_source():
    kept = [
        "src/main/java/Kept.java",
        "src/itx/V.java",          # not a segment match for src/it
        "it/core/V.java",          # a package named it, not src/it
        "app.js",
    ]
    for rel in kept:
        assert not path_is_excluded(rel, load_excluded_paths()), f"{rel!r} was excluded"


def test_drop_excluded_paths_judges_the_sink():
    """Taint arriving from a test helper into production code is still a
    finding about the production code."""
    candidates = [
        {"sink_file": "src/it/V.java", "source_file": "src/main/java/A.java"},
        {"sink_file": "src/main/java/A.java", "source_file": "src/it/V.java"},
    ]

    kept = drop_excluded_paths(candidates, load_excluded_paths())

    assert [c["sink_file"] for c in kept] == ["src/main/java/A.java"]


def test_every_custom_rule_file_has_an_annotated_fixture():
    """A custom rule with no fixture is a rule nothing checks. Kept separate
    from the semgrep-backed test below so the gap is reported even on a
    machine without semgrep installed."""
    for path in custom_rule_files():
        assert fixture_for(path) is not None, (
            f"{path.name} has no {' or '.join(path.stem + s for s in FIXTURE_SUFFIXES)} "
            "next to it -- every rule under rules/custom/ needs an annotated fixture "
            "(see the vendored rules for the ruleid: / ok: convention)"
        )


def test_every_custom_rule_is_exercised_by_its_fixture():
    """`semgrep --test` reports a rule with zero annotations as passing, so a
    rule can be added to an existing file and be covered by nothing."""
    for path, rule in custom_rules():
        fixture_path = fixture_for(path)
        assert fixture_path is not None, path.name
        fixture = fixture_path.read_text(encoding="utf-8")
        assert f"ruleid: {rule['id']}" in fixture, (
            f"{fixture_path.name} has no `ruleid: {rule['id']}` case"
        )
        # `todook:` counts: it is a negative case the rule is known to fail,
        # recorded on purpose, and it still fails loudly once fixed.
        assert any(f"{marker}: {rule['id']}" in fixture for marker in ("ok", "todook")), (
            f"{fixture_path.name} has no `ok: {rule['id']}` case -- "
            "a rule with only positive cases cannot catch over-matching"
        )


@pytest.mark.skipif(shutil.which("semgrep") is None, reason="semgrep is not installed")
def test_custom_rules_match_their_fixtures(tmp_path):
    """Run one real scan and check Semgrep's ruleid/ok annotations.

    Semgrep 1.173.0's `--test` starts a Windows process pool per config. A
    single JSON scan exercises the same parser and matcher without leaving
    dozens of workers behind. Fixtures are copied to a temporary target so
    filename-scoped rules see production-shaped names (notably *Mapper.xml).
    """
    staging = tmp_path / "fixtures"
    staged_to_source = {}
    for rule_path in custom_rule_files():
        source = fixture_for(rule_path)
        assert source is not None
        suffix = "Mapper.xml" if source.suffix == ".xml" else source.suffix
        staged = staging / rule_path.parent.relative_to(CUSTOM_RULES_DIR) / f"{source.stem}{suffix}"
        staged.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, staged)
        staged_to_source[staged.resolve()] = source.resolve()

    proc = subprocess.run(
        ["semgrep", "--json", "--metrics=off", "--no-git-ignore",
         "--config", str(CUSTOM_RULES_DIR), str(staging)],
        capture_output=True,
        env=semgrep_env(tmp_path),
    )
    stdout, stderr = decoded(proc.stdout), decoded(proc.stderr)
    assert proc.returncode in (0, 1), f"semgrep fixture scan failed:\n{stdout}\n{stderr}"

    from scanner.core import normalize

    matches = {
        (staged_to_source[(staging / candidate["sink_file"]).resolve()], candidate["sink_line"],
         candidate["rule_id"].split(".")[-1])
        for candidate in normalize(json.loads(stdout), staging)
    }

    annotation = re.compile(
        r"^\s*(?://|#|<!--|/\*)\s*(ruleid|ok|todook):\s*([A-Za-z0-9_.-]+)"
    )
    for rule_path in custom_rule_files():
        fixture = fixture_for(rule_path)
        assert fixture is not None
        for line_no, line in enumerate(fixture.read_text(encoding="utf-8").splitlines(), 1):
            found = annotation.search(line)
            if not found or found.group(1) == "todook":
                continue
            key = (fixture.resolve(), line_no + 1, found.group(2))
            if found.group(1) == "ruleid":
                assert key in matches, f"{fixture.name}:{line_no + 1} should match {found.group(2)}"
            else:
                assert key not in matches, f"{fixture.name}:{line_no + 1} unexpectedly matched {found.group(2)}"


def pinned_semgrep_version():
    for line in (ROOT / "requirements.txt").read_text(encoding="utf-8").splitlines():
        line = line.split("#")[0].strip()
        if line.startswith("semgrep=="):
            return line.removeprefix("semgrep==")
    raise AssertionError("requirements.txt no longer pins semgrep to an exact version")


def test_semgrep_is_pinned_to_an_exact_version():
    """Standing decision: the engine stays on one version and detection
    improves through rules/custom/ instead. A floating `semgrep>=x` would let
    a fresh install pick up a release whose matching, constant propagation or
    taint behaviour differs, moving findings with no change to this repo."""
    version = pinned_semgrep_version()
    assert version.count(".") == 2 and all(p.isdigit() for p in version.split(".")), version


@pytest.mark.skipif(shutil.which("semgrep") is None, reason="semgrep is not installed")
def test_installed_semgrep_matches_the_pin(tmp_path):
    """Pinning requirements.txt does nothing for a machine that already had a
    different semgrep on PATH, which is the case that silently shifts results:
    every number in eval/labels.json was measured against the pinned engine."""
    proc = subprocess.run(["semgrep", "--version"], capture_output=True,
                          env=semgrep_env(tmp_path))
    assert proc.returncode == 0, decoded(proc.stderr)
    # The CLI prints an upgrade notice on its own line before the version.
    reported = [ln.strip() for ln in decoded(proc.stdout).splitlines() if ln.strip()][-1]
    expected = pinned_semgrep_version()
    assert reported == expected, (
        f"semgrep on PATH is {reported}, requirements.txt pins {expected}. "
        "The engine is deliberately frozen -- reinstall the pinned version "
        "rather than re-baselining, unless the pin was changed on purpose."
    )
