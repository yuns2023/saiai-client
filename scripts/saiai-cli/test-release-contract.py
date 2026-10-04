#!/usr/bin/env python3
"""Positive and negative checks for the optional Claude release contract."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch


SCRIPT_DIR = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("saiai_release_contract", SCRIPT_DIR / "verify-release.py")
VERIFIER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFIER)


class OptionalClaudeContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.main = VERIFIER.text("tools/saiai-cli/src/main.rs")
        self.launcher = VERIFIER.text("tools/saiai-cli/src/claude_launcher.rs")
        self.original_text = VERIFIER.text

    def verify(self, main: str | None = None, launcher: str | None = None) -> None:
        def read(relative: str) -> str:
            if relative == "tools/saiai-cli/src/main.rs":
                return self.main if main is None else main
            if relative == "tools/saiai-cli/src/claude_launcher.rs":
                return self.launcher if launcher is None else launcher
            return self.original_text(relative)

        with patch.object(VERIFIER, "text", side_effect=read):
            VERIFIER.verify_cli()

    def inject(self, behavior: str) -> str:
        return self.launcher.replace("#[cfg(test)]\nmod tests", behavior + "\n#[cfg(test)]\nmod tests", 1)

    def test_accepts_optional_launcher_under_existing_local_proxy_contract(self) -> None:
        self.verify()

    def test_all_real_v2_markers_remain_rejected(self) -> None:
        markers = (
            "mod v2", "mod claude_proxy", "saiai setup [claude|codex]",
            "saiai revoke --all", "client/bootstrap", "run_claude",
            'include_str!("../../piproxy/internal/certs/assets/piproxy-ca.key")',
        )
        self.assertEqual(VERIFIER.WITHDRAWN_V2_MARKERS, markers)
        for marker in markers:
            with self.subTest(marker=marker):
                with self.assertRaisesRegex(AssertionError, "withdrawn V2"):
                    self.verify(main=self.main + "\n" + marker)
                with self.assertRaisesRegex(AssertionError, "forbidden behavior"):
                    self.verify(launcher=self.inject(marker))

    def test_requires_explicit_dispatch(self) -> None:
        with self.assertRaisesRegex(AssertionError, "dispatch"):
            self.verify(main=self.main.replace("Command::Claude(args) => claude_launcher::run(&args)", "Command::Claude(_) => Ok(())"))

    def test_rejects_automatic_launcher_on_other_entrypoints(self) -> None:
        with self.assertRaisesRegex(AssertionError, "default entrypoint"):
            self.verify(main=self.main + "\nfn default_route() { claude_launcher::run(&[]); }")

    def test_keeps_normal_initialization_dispatch(self) -> None:
        with self.assertRaisesRegex(AssertionError, "dispatch"):
            self.verify(main=self.main.replace("Command::Init(init) => init_claude(init)", "Command::Init(_) => Ok(())"))

    def test_requires_launcher_module(self) -> None:
        with self.assertRaisesRegex(AssertionError, "dispatch"):
            self.verify(main=self.main.replace("mod claude_launcher;", ""))

    def test_rejects_parent_environment_mutation(self) -> None:
        for behavior in ('env::set_var("HOME", "alternate")', 'std::env::remove_var("HTTP_PROXY")'):
            with self.subTest(behavior=behavior):
                with self.assertRaisesRegex(AssertionError, "forbidden behavior"):
                    self.verify(launcher=self.inject(behavior))

    def test_rejects_persistent_file_mutation(self) -> None:
        for behavior in ("fs::write(path, bytes)", "File::create(path)", "create_dir_all(path)", "remove_file(path)", "rename(source, target)", "write_json_object(path, value)"):
            with self.subTest(behavior=behavior):
                with self.assertRaisesRegex(AssertionError, "forbidden behavior"):
                    self.verify(launcher=self.inject(behavior))

    def test_rejects_initialization_from_launcher(self) -> None:
        with self.assertRaisesRegex(AssertionError, "forbidden behavior"):
            self.verify(launcher=self.inject("init_claude(init)"))

    def test_rejects_isolated_profile_and_model_overrides(self) -> None:
        for name in ("HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "CLAUDE_CONFIG_DIR", "ANTHROPIC_MODEL"):
            with self.subTest(name=name):
                with self.assertRaisesRegex(AssertionError, "must not override"):
                    self.verify(launcher=self.inject(f'command.env("{name}", "alternate")'))

    def test_rejects_removal_of_user_profile_and_model(self) -> None:
        for name in ("HOME", "CLAUDE_CONFIG_DIR", "ANTHROPIC_MODEL"):
            with self.subTest(name=name):
                with self.assertRaisesRegex(AssertionError, "must not remove"):
                    self.verify(launcher=self.inject(f'command.env_remove("{name}")'))
                altered = self.launcher.replace('const CONFLICTING_ENV: &[&str] = &[', f'const CONFLICTING_ENV: &[&str] = &["{name}",', 1)
                with self.assertRaisesRegex(AssertionError, "must not remove"):
                    self.verify(launcher=altered)

    def test_rejects_auth_token_host_management_and_tls_bypass_injection(self) -> None:
        for name in ("ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_API_KEY", "CLAUDE_CODE_PROVIDER_MANAGED_BY_HOST", "NODE_TLS_REJECT_UNAUTHORIZED"):
            with self.subTest(name=name):
                with self.assertRaisesRegex(AssertionError, "must not override"):
                    self.verify(launcher=self.inject(f'command.env("{name}", "synthetic")'))

    def test_rejects_settings_and_api_key_helper_takeover(self) -> None:
        for behavior in ('command.arg("--settings")', 'command.arg("--setting-sources")', 'disable_apiKeyHelper()', 'read("settings.json")', 'read(".credentials.json")'):
            with self.subTest(behavior=behavior):
                with self.assertRaisesRegex(AssertionError, "forbidden behavior"):
                    self.verify(launcher=self.inject(behavior))

    def test_requires_loopback_validation(self) -> None:
        with self.assertRaisesRegex(AssertionError, "contract is missing"):
            self.verify(launcher=self.launcher.replace("validate_listen(&config.listen)?;", ""))

    def test_requires_oauth_instead_of_auth_token_mode(self) -> None:
        with self.assertRaisesRegex(AssertionError, "contract is missing"):
            self.verify(launcher=self.launcher.replace('.env("CLAUDE_CODE_OAUTH_TOKEN", token)', '.env("ANTHROPIC_AUTH_TOKEN", token)'))

    def test_requires_claude_specific_route_selection(self) -> None:
        with self.assertRaisesRegex(AssertionError, "contract is missing"):
            self.verify(launcher=self.launcher.replace("config.providers.claude.as_ref()", "config.providers.codex.as_ref()"))

    def test_requires_proxy_reuse_and_ca_validation(self) -> None:
        for marker in ("read_runtime_ca(&config)", "ensure_local_proxy_running_with_start(&config.listen"):
            with self.subTest(marker=marker):
                with self.assertRaisesRegex(AssertionError, "contract is missing"):
                    self.verify(launcher=self.launcher.replace(marker, "removed_guard"))

    def test_requires_child_argument_passthrough(self) -> None:
        with self.assertRaisesRegex(AssertionError, "contract is missing"):
            self.verify(launcher=self.launcher.replace("command.args(args)", "command.args([] as [String; 0])"))

    def test_requires_proxy_case_variants(self) -> None:
        for name in ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"):
            with self.subTest(name=name):
                with self.assertRaisesRegex(AssertionError, "child proxy"):
                    self.verify(launcher=self.launcher.replace(f'.env("{name}", &proxy)', ""))

    def test_requires_removing_conflicting_credentials(self) -> None:
        for name in ("ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_API_KEY", "CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR"):
            with self.subTest(name=name):
                with self.assertRaisesRegex(AssertionError, "conflicting environment"):
                    self.verify(launcher=self.launcher.replace(f'    "{name}",\n', "", 1))

    def test_rejects_public_no_proxy_bypass(self) -> None:
        with self.assertRaisesRegex(AssertionError, "local/private"):
            self.verify(launcher=self.launcher.replace('const LOCAL_NO_PROXY: &str = "localhost,', 'const LOCAL_NO_PROXY: &str = "api.anthropic.com,localhost,', 1))

    def test_rejects_provider_preflight_requests(self) -> None:
        for behavior in ('reqwest::Client::new()', 'TcpStream::connect(address)', 'post("/v1/messages")'):
            with self.subTest(behavior=behavior):
                with self.assertRaisesRegex(AssertionError, "forbidden behavior"):
                    self.verify(launcher=self.inject(behavior))

    def test_rejects_dynamic_secret_diagnostics(self) -> None:
        for behavior in ('eprintln!("{token}");', 'eprint!("{}", token);', 'dbg!(config);'):
            with self.subTest(behavior=behavior):
                with self.assertRaisesRegex(AssertionError, "interpolate credentials"):
                    self.verify(launcher=self.inject(behavior))

    def test_rejects_stdout_pollution(self) -> None:
        with self.assertRaisesRegex(AssertionError, "stdout"):
            self.verify(launcher=self.inject('println!("launcher started");'))

    def test_requires_real_child_regression(self) -> None:
        with self.assertRaisesRegex(AssertionError, "regression is missing"):
            self.verify(launcher=self.launcher.replace("claude_launcher_child_process_preserves_profile_and_parent_environment", "removed_test"))

    def test_ignores_only_fixture_mutation_in_rust_test_section(self) -> None:
        prefix, ending = self.launcher.rsplit("\n}", 1)
        self.verify(launcher=prefix + '\n    fn fixture_only() { std::fs::write("settings.json", b"synthetic"); }\n}' + ending)

    def test_rejects_production_after_test_module(self) -> None:
        with self.assertRaisesRegex(AssertionError, "final source item"):
            self.verify(launcher=self.launcher + '\nfn extra_production() { std::fs::write("settings.json", b"synthetic"); }')

    def test_rejects_working_directory_override(self) -> None:
        with self.assertRaisesRegex(AssertionError, "forbidden behavior"):
            self.verify(launcher=self.inject('command.current_dir("alternate")'))

    def test_contract_tests_are_wired_into_ci_release_and_pre_push(self) -> None:
        VERIFIER.verify_workflows_and_docs()
        for path in (".github/workflows/ci.yml", ".github/workflows/saiai-cli-release.yml", "scripts/git-hooks/pre-push"):
            with self.subTest(path=path):
                def read(relative: str) -> str:
                    contents = self.original_text(relative)
                    if relative == path:
                        return contents.replace("python3 scripts/saiai-cli/test-release-contract.py", "removed_regression_gate")
                    return contents

                with patch.object(VERIFIER, "text", side_effect=read):
                    with self.assertRaisesRegex(AssertionError, "does not run"):
                        VERIFIER.verify_workflows_and_docs()


if __name__ == "__main__":
    unittest.main()
