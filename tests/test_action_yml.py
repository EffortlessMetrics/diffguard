#!/usr/bin/env python3
"""
Red tests for action.yml hardening changes.

These tests verify the acceptance criteria for Issue #37:
P1: Hardened production-ready GitHub Action.

These tests MUST fail on the current implementation (before hardening)
and pass after the hardening changes are applied.
"""

import os
import re
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ACTION_YML_PATH = os.path.join(REPO_ROOT, "action.yml")


def load_action_yml_raw():
    """Load action.yml as raw text for regex-based tests."""
    with open(ACTION_YML_PATH, "r") as f:
        return f.read()


class TestAC1_WindowsTargetTripleResolution:
    """
    AC-1: Windows Target Triple Resolution

    Given a GitHub Actions workflow running on windows-latest
    When the diffguard action executes the Resolve target triple step
    Then TARGET is set to x86_64-pc-windows-msvc

    Verification: The case pattern MINGW*|MSYS* matches and sets the correct triple.
    """

    def test_windows_target_triple_detection_present(self):
        """The resolve target triple step must detect Windows via MINGW*/MSYS* pattern."""
        content = load_action_yml_raw()

        # The run block for "Resolve target triple" must contain MINGW*|MSYS* pattern
        # This pattern is how GitHub Actions Windows runners report OS in bash
        assert re.search(r"MINGW\*\|MSYS\*", content), (
            "action.yml must detect Windows via 'MINGW*|MSYS*' pattern in uname -s case statement. "
            "Expected: MINGW*|MSYS*) TARGET=\"x86_64-pc-windows-msvc\" ;;"
        )

    def test_windows_target_triple_value(self):
        """The resolve target triple step must set TARGET to x86_64-pc-windows-msvc for Windows."""
        content = load_action_yml_raw()

        # When MINGW*|MSYS* is matched, TARGET must be set to x86_64-pc-windows-msvc
        windows_block = re.search(
            r"MINGW\*\|MSYS\*\).*?TARGET=\"([^\"]+)\"",
            content,
            re.DOTALL
        )
        assert windows_block is not None, (
            "Windows detection must set TARGET variable. "
            "Expected: MINGW*|MSYS*) TARGET=\"x86_64-pc-windows-msvc\" ;;"
        )
        target_value = windows_block.group(1)
        assert target_value == "x86_64-pc-windows-msvc", (
            f"Windows TARGET must be 'x86_64-pc-windows-msvc', got '{target_value}'"
        )


class TestAC2_ThirdPartyActionsPinnedToShas:
    """
    AC-2: Third-Party Actions Pinned to Immutable SHAs

    Given the Upload SARIF step and Post PR comment step
    When the action is used
    Then github/codeql-action/upload-sarif and actions/github-script
    are referenced by full commit SHA (40 hex characters), not by mutable tag (@v7, @v3)

    Verification: No mutable tags (@v7, @v3) remain in the file.
    """

    def test_no_mutable_version_tags(self):
        """Third-party actions must not use mutable version tags like @v7 or @v3."""
        content = load_action_yml_raw()

        # Check for the specific mutable tags mentioned in the issue
        mutable_tags = [
            (r"@v7\b", "actions/github-script@v7"),
            (r"@v3\b", "github/codeql-action/upload-sarif@v3"),
        ]

        for pattern, tag_name in mutable_tags:
            match = re.search(pattern, content)
            assert match is None, (
                f"Mutable tag '{tag_name}' found. "
                f"Third-party actions must be pinned to immutable commit SHAs, not version tags. "
                f"Expected format: actions/github-script@{{40-char-sha}}"
            )

    def test_github_script_uses_sha_reference(self):
        """actions/github-script must use SHA reference, not version tag."""
        content = load_action_yml_raw()

        # Find the actions/github-script usage
        # Accept both full SHA (40 chars) or short SHA (7+ chars that aren't version tags)
        # Version tags like @v7 or @v3 should NOT match this pattern
        script_action_match = re.search(
            r"uses:\s*actions/github-script@([a-f0-9]{7,})",
            content
        )
        assert script_action_match is not None, (
            "actions/github-script must use SHA reference. "
            "Expected: uses: actions/github-script@{40-char-sha}"
        )

        ref = script_action_match.group(1)
        # If it starts with 'v' followed by digits, it's a version tag (not allowed)
        assert not re.match(r"^v[0-9]+$", ref), (
            f"actions/github-script uses version tag '@{ref}' instead of SHA. "
            f"Must use immutable commit SHA."
        )

    def test_codeql_upload_sarif_uses_sha_reference(self):
        """github/codeql-action/upload-sarif must use SHA reference, not version tag."""
        content = load_action_yml_raw()

        # Find the codeql-action/upload-sarif usage
        sarif_action_match = re.search(
            r"uses:\s*github/codeql-action/upload-sarif@([a-f0-9]{7,})",
            content
        )
        assert sarif_action_match is not None, (
            "github/codeql-action/upload-sarif must use SHA reference. "
            "Expected: uses: github/codeql-action/upload-sarif@{40-char-sha}"
        )

        ref = sarif_action_match.group(1)
        assert not re.match(r"^v[0-9]+$", ref), (
            f"github/codeql-action/upload-sarif uses version tag '@{ref}' instead of SHA. "
            f"Must use immutable commit SHA."
        )


class TestAC3_ExplicitPermissionsBlock:
    """
    AC-3: Explicit Permissions Block Declared

    Given the runs: block in action.yml
    When the action is parsed
    Then a top-level permissions: block exists with at minimum:
    - contents: read
    - pull-requests: write
    - security-events: write

    Verification: permissions: key is at the same indentation level as using: composite.
    """

    def test_permissions_block_exists(self):
        """The runs: block must have a top-level permissions: block."""
        content = load_action_yml_raw()

        # The permissions block must be at the same indentation level as "using: composite"
        # It must come after "using: composite" and before "steps:"
        #
        # Looking for pattern:
        # runs:
        #   using: composite
        #   permissions:
        #     contents: read
        #     ...

        # Find the runs: section
        runs_match = re.search(r"^runs:\s*$", content, re.MULTILINE)
        assert runs_match is not None, "Could not find 'runs:' block"

        # Find "using: composite" line and get its indentation
        using_match = re.search(r"^(\s*)using:\s*composite\s*$", content, re.MULTILINE)
        assert using_match is not None, "Could not find 'using: composite' in runs block"

        using_indent = len(using_match.group(1))

        # Now look for permissions: at the same indentation level as using:
        permissions_pattern = re.search(
            rf"^(\{{{using_indent}}})permissions:\s*$",
            content,
            re.MULTILINE
        )
        assert permissions_pattern is not None, (
            "runs: block must contain a 'permissions:' key at the same indentation level as 'using: composite'. "
            "This declares minimal required permissions for the action."
        )

    def test_permissions_block_has_required_scopes(self):
        """The permissions block must declare contents: read, pull-requests: write, and security-events: write."""
        content = load_action_yml_raw()

        # Find the permissions block and verify it has the three required scopes
        # permissions block should be at same indent as "using: composite"

        using_match = re.search(r"^(\s*)using:\s*composite\s*$", content, re.MULTILINE)
        assert using_match is not None, "Could not find 'using: composite'"
        indent = len(using_match.group(1))

        # Find permissions block header
        perms_match = re.search(
            rf"^(\{{{indent}}})permissions:\s*$",
            content,
            re.MULTILINE
        )
        assert perms_match is not None, "permissions: block not found"

        # Now extract the permissions block content (should be indented more than permissions: line)
        perms_start = perms_match.end()
        # Find next line at same or less indentation
        next_section_match = re.search(rf"\n[^\s]|{{1,{indent}}}", content[perms_start:])
        if next_section_match:
            perms_content = content[perms_start:perms_start + next_section_match.start()]
        else:
            perms_content = content[perms_start:]

        required_permissions = {
            "contents:": "read",
            "pull-requests:": "write",
            "security-events:": "write",
        }

        for perm_key, expected_val in required_permissions.items():
            # Look for "  contents: read" or similar indented under permissions
            pattern = rf"^\s*{re.escape(perm_key)}\s*{expected_val}\s*$"
            assert re.search(pattern, perms_content, re.MULTILINE), (
                f"permissions block must contain '{perm_key} {expected_val}'. "
                f"Required for least-privilege GitHub Actions security."
            )


class TestAC4_SarifUploadHasConcurrencyControl:
    """
    AC-4: SARIF Upload Has Concurrency Control

    Given the Upload SARIF step
    When multiple PR runs or workflow dispatches target the same github.ref
    Then only one SARIF upload runs at a time; older runs are cancelled via cancel-in-progress: true

    Verification: The step includes concurrency: block with:
    - group: ${{ github.workflow }}-${{ github.ref }}
    - cancel-in-progress: true
    """

    def test_sarif_upload_step_has_concurrency_block(self):
        """The Upload SARIF step must have a concurrency: block."""
        content = load_action_yml_raw()

        # Find the Upload SARIF step
        sarif_section = re.search(
            r"- name: Upload SARIF\s*\n(.*?)(?=\n\s*-\s*name:|\Z)",
            content,
            re.DOTALL
        )
        assert sarif_section is not None, "Could not find 'Upload SARIF' step"

        sarif_content = sarif_section.group(1)

        assert "concurrency:" in sarif_content, (
            "Upload SARIF step must have a 'concurrency:' block to prevent race conditions. "
            "This prevents concurrent SARIF uploads on the same ref from clobbering each other."
        )

    def test_sarif_upload_concurrency_has_cancel_in_progress(self):
        """The concurrency block must have cancel-in-progress: true."""
        content = load_action_yml_raw()

        # Find the Upload SARIF step
        sarif_section = re.search(
            r"- name: Upload SARIF\s*\n(.*?)(?=\n\s*-\s*name:|\Z)",
            content,
            re.DOTALL
        )
        assert sarif_section is not None, "Could not find 'Upload SARIF' step"

        sarif_content = sarif_section.group(1)

        # Look for cancel-in-progress: true
        assert re.search(r"cancel-in-progress:\s*true", sarif_content), (
            "concurrency.cancel-in-progress must be true to cancel outdated runs."
        )

    def test_sarif_upload_concurrency_uses_correct_group(self):
        """The concurrency block must use the correct group expression."""
        content = load_action_yml_raw()

        # Find the Upload SARIF step
        sarif_section = re.search(
            r"- name: Upload SARIF\s*\n(.*?)(?=\n\s*-\s*name:|\Z)",
            content,
            re.DOTALL
        )
        assert sarif_section is not None, "Could not find 'Upload SARIF' step"

        sarif_content = sarif_section.group(1)

        # Look for group: expression with github.workflow and github.ref
        group_match = re.search(r"group:\s*([^\n]+)", sarif_content)
        assert group_match is not None, (
            "Upload SARIF concurrency block must define 'group:' expression"
        )

        group_expr = group_match.group(1).strip()
        # The group should reference github.workflow and github.ref
        assert "github.workflow" in group_expr, (
            f"concurrency.group must reference github.workflow, got '{group_expr}'"
        )
        assert "github.ref" in group_expr, (
            f"concurrency.group must reference github.ref, got '{group_expr}'"
        )


class TestAC5_PrCommentIncludesAnnotationReportLink:
    """
    AC-5: PR Comment Includes Annotation Report Link

    Given a PR with findings
    When inputs.post-comment is true and findings exist
    Then the posted comment includes, after the findings table, a link:
    [View full diffguard annotation report](https://github.com/{owner}/{repo}/runs/{run_id}#annotations)

    Verification: Comment body contains the string #annotations and references ${{ github.run_id }}
    """

    def test_pr_comment_script_includes_annotation_link(self):
        """The Post PR comment step's script must include the annotation report link."""
        content = load_action_yml_raw()

        # The script block for Post PR comment must include #annotations link
        # This link allows reviewers to jump from the PR comment to the full inline annotation view
        assert "#annotations" in content, (
            "PR comment script must include '#annotations' link to the full annotation report. "
            "Expected: [View full diffguard annotation report](${{ github.server_url }}/...)#annotations"
        )

    def test_pr_comment_script_includes_run_id_reference(self):
        """The Post PR comment step's script must reference github.run_id."""
        content = load_action_yml_raw()

        # Must include ${{ github.run_id }} to link to the specific run
        # Use a pattern that matches the template syntax
        assert re.search(r"run_id", content), (
            "PR comment script must include '${{ github.run_id }}' to link to the specific run. "
            "Expected: ${{ github.server_url }}/${{ github.repository }}/runs/${{ github.run_id }}#annotations"
        )

    def test_pr_comment_annotation_link_uses_correct_template(self):
        """The annotation link must use the correct URL template format."""
        content = load_action_yml_raw()

        # Look for the complete template pattern with server_url, repository, run_id, and #annotations
        # The GitHub Actions template expressions use ${{ }} syntax
        has_server_url = "server_url" in content
        has_repository = "github.repository" in content
        has_run_id = "run_id" in content
        has_annotations = "#annotations" in content

        assert has_server_url and has_repository and has_run_id and has_annotations, (
            "Annotation link must use complete format with: "
            "${{ github.server_url }}, ${{ github.repository }}, "
            "${{ github.run_id }}, and #annotations suffix"
        )


class TestAC6_InstallFallbackEmitsVisibleWarning:
    """
    AC-6: Install Fallback Emits Visible Warning

    Given the pre-built binary is unavailable for the detected platform
    When the Fallback to cargo install step runs
    Then a visible warning is emitted before cargo install begins:
    ::warning::Pre-built binary unavailable for {TARGET}. Installing via cargo (slower, ~2-5 min)

    Verification: The fallback step's run: block contains a ::warning:: directive
    that mentions the platform/triple and mentions cargo install is slower.
    """

    def test_fallback_step_has_warning_directive(self):
        """The Fallback to cargo install step must emit a ::warning:: directive."""
        content = load_action_yml_raw()

        # Find the Fallback step
        fallback_section = re.search(
            r"- name: Fallback to cargo install\s*\n(.*?)(?=\n\s*-\s*name:|\Z)",
            content,
            re.DOTALL
        )
        assert fallback_section is not None, "Could not find 'Fallback to cargo install' step"

        fallback_content = fallback_section.group()

        assert "::warning::" in fallback_content, (
            "Fallback step must emit a ::warning:: directive so users understand why installation is slow. "
            "Expected: ::warning::Pre-built binary unavailable for ${TARGET}. Installing via cargo (slower, ~2-5 min)"
        )

    def test_fallback_warning_mentions_target(self):
        """The warning must mention the target platform/triple."""
        content = load_action_yml_raw()

        # Find the Fallback step
        fallback_section = re.search(
            r"- name: Fallback to cargo install\s*\n(.*?)(?=\n\s*-\s*name:|\Z)",
            content,
            re.DOTALL
        )
        assert fallback_section is not None, "Could not find 'Fallback to cargo install' step"

        fallback_content = fallback_section.group()

        # Must mention TARGET or the specific triple
        assert "${TARGET}" in fallback_content or "x86_64-pc-windows-msvc" in fallback_content, (
            "Warning must mention the target platform (${TARGET}) so users know which binary is missing."
        )

    def test_fallback_warning_mentions_cargo_install(self):
        """The warning must mention that cargo install is being used (slower)."""
        content = load_action_yml_raw()

        # Find the Fallback step
        fallback_section = re.search(
            r"- name: Fallback to cargo install\s*\n(.*?)(?=\n\s*-\s*name:|\Z)",
            content,
            re.DOTALL
        )
        assert fallback_section is not None, "Could not find 'Fallback to cargo install' step"

        fallback_content = fallback_section.group()

        # Must indicate that cargo install is slower
        # Look for the warning message
        warning_match = re.search(r"::warning::([^\n]+)", fallback_content)
        if warning_match:
            warning_text = warning_match.group(1)
            assert re.search(r"cargo|slower", warning_text, re.IGNORECASE), (
                f"Warning must mention 'cargo install' and indicate it's slower. "
                f"Got warning: {warning_text}"
            )
        else:
            # Fallback to checking the entire section
            assert re.search(r"cargo.*install|slower", fallback_content, re.IGNORECASE), (
                "Warning must mention 'cargo install' and indicate it's slower. "
                "Expected: Installing via cargo (slower, ~2-5 min)"
            )


class TestAC7_NoRegressionExistingInputsOutputsUnchanged:
    """
    AC-7: No Regression — Existing Inputs/Outputs Unchanged

    Given the existing action usage with documented inputs
    When the action is updated
    Then all existing inputs and outputs behave identically; no breaking changes

    Verification:
    - inputs: block still defines all 8 inputs with same names and defaults
    - outputs: block still defines outcome, findings-count, receipt-file
    """

    def test_all_eight_inputs_present(self):
        """All 8 existing inputs must still be defined with their original names."""
        content = load_action_yml_raw()

        expected_inputs = [
            "base", "head", "config", "fail-on",
            "sarif-file", "version", "github-annotations", "post-comment"
        ]

        for input_name in expected_inputs:
            # Match input: (at start of line with potential leading whitespace)
            pattern = rf"^\s*{input_name}:"
            assert re.search(pattern, content, re.MULTILINE), (
                f"Input '{input_name}' must still exist. "
                f"Hardening changes must not break existing action interface."
            )

    def test_all_three_outputs_present(self):
        """All 3 existing outputs must still be defined with their original value references."""
        content = load_action_yml_raw()

        expected_outputs = {
            "outcome": "steps.check.outcome",
            "findings-count": "steps.check.outputs.findings-count",
            "receipt-file": "steps.check.outputs.receipt-file",
        }

        for output_name, expected_value_ref in expected_outputs.items():
            # Check the output is defined
            pattern = rf"^\s*{output_name}:"
            assert re.search(pattern, content, re.MULTILINE), (
                f"Output '{output_name}' must still exist. "
                f"Hardening changes must not break existing action interface."
            )
            # Check the value reference is preserved
            value_pattern = rf"{output_name}:.*?value:\s*\${{.*{expected_value_ref}.*}}"
            assert re.search(value_pattern, content, re.DOTALL), (
                f"Output '{output_name}' value reference must be preserved. "
                f"Expected to find '{expected_value_ref}' in value expression."
            )


class TestAC8_NoRegressionLinuxMacosDetectionUnchanged:
    """
    AC-8: No Regression — Linux and macOS Detection Unchanged

    Given a GitHub Actions workflow running on ubuntu-latest or macos-latest
    When the action resolves the target triple
    Then x86_64-unknown-linux-gnu is selected for Linux and
    x86_64-apple-darwin/aarch64-apple-darwin is selected for macOS (existing behavior preserved)
    """

    def test_linux_detection_still_present(self):
        """Linux detection (x86_64-unknown-linux-gnu) must still be present."""
        content = load_action_yml_raw()

        # Linux detection must still exist
        assert re.search(r"Linux\).*?TARGET=\"x86_64-unknown-linux-gnu\"", content, re.DOTALL), (
            "Linux detection must still set TARGET to 'x86_64-unknown-linux-gnu'. "
            "Existing behavior must be preserved."
        )

    def test_macos_detection_still_present(self):
        """macOS detection (x86_64-apple-darwin and aarch64-apple-darwin) must still be present."""
        content = load_action_yml_raw()

        # macOS Intel detection
        assert re.search(r"Darwin\).*?\*\).*?TARGET=\"x86_64-apple-darwin\"", content, re.DOTALL), (
            "macOS Intel detection must still set TARGET to 'x86_64-apple-darwin'. "
            "Existing behavior must be preserved."
        )

        # macOS ARM detection
        assert re.search(r"arm64.*?TARGET=\"aarch64-apple-darwin\"", content), (
            "macOS ARM detection must still set TARGET to 'aarch64-apple-darwin'. "
            "Existing behavior must be preserved."
        )


def run_tests():
    """Run all test classes and report results."""
    import traceback

    test_classes = [
        TestAC1_WindowsTargetTripleResolution,
        TestAC2_ThirdPartyActionsPinnedToShas,
        TestAC3_ExplicitPermissionsBlock,
        TestAC4_SarifUploadHasConcurrencyControl,
        TestAC5_PrCommentIncludesAnnotationReportLink,
        TestAC6_InstallFallbackEmitsVisibleWarning,
        TestAC7_NoRegressionExistingInputsOutputsUnchanged,
        TestAC8_NoRegressionLinuxMacosDetectionUnchanged,
    ]

    total = 0
    failed = 0
    passed = 0
    failures = []

    for test_class in test_classes:
        instance = test_class()
        for method_name in dir(instance):
            if method_name.startswith("test_"):
                total += 1
                try:
                    getattr(instance, method_name)()
                    passed += 1
                    print(f"  PASS {test_class.__name__}.{method_name}")
                except AssertionError as e:
                    failed += 1
                    failures.append((test_class.__name__, method_name, str(e)))
                    print(f"  FAIL {test_class.__name__}.{method_name}")
                    print(f"       {e}")
                except Exception as e:
                    failed += 1
                    failures.append((test_class.__name__, method_name, f"Unexpected error: {e}"))
                    print(f"  ERROR {test_class.__name__}.{method_name}")
                    print(f"       Error: {e}")

    print()
    print("=" * 70)
    print(f"Results: {passed} passed, {failed} failed, {total} total")
    print("=" * 70)

    if failed > 0:
        print()
        print("Failed tests (these define the acceptance criteria):")
        for class_name, method_name, msg in failures:
            print(f"\n  {class_name}.{method_name}")
            # Print first 200 chars of message
            print(f"    {msg[:200]}")

    return failed == 0


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
