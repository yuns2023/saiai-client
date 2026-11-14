#!/usr/bin/env python3
"""Positive and negative checks for the optional Claude release contract."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


SCRIPT_DIR = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("saiai_release_contract", SCRIPT_DIR / "verify-release.py")
VERIFIER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFIER)


class CredentialScanTests(unittest.TestCase):
    def test_snake_case_identifiers_are_not_credentials(self) -> None:
        for identifier in ("use_authority_key_identifier_extension", "key_matches_certificate"):
            for match in VERIFIER.CREDENTIAL_PATTERN.findall(identifier):
                self.assertFalse(VERIFIER.is_possible_credential(match), match)

    def test_key_shaped_values_are_credentials(self) -> None:
        # Built by concatenation so this file does not trip the scan itself.
        for value in ("sk-ant-" + "api03-AbCdEf0123456789xyz", "sk_live_" + "0123456789abcdefgh", "key-" + "ABCDEFGHIJKLMNOPQR"):
            matches = VERIFIER.CREDENTIAL_PATTERN.findall(value)
            self.assertTrue(matches, value)
            self.assertTrue(all(VERIFIER.is_possible_credential(match) for match in matches), value)
        self.assertFalse(VERIFIER.is_possible_credential("sk-test-0123456789abcdefgh"))


class OptionalClaudeContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.main = VERIFIER.text("tools/saiai-cli/kernel/src/lib.rs")
        self.launcher = VERIFIER.text("tools/saiai-cli/kernel/src/claude_launcher.rs")
        self.original_text = VERIFIER.text

    def verify(self, main: str | None = None, launcher: str | None = None) -> None:
        def read(relative: str) -> str:
            if relative == "tools/saiai-cli/kernel/src/lib.rs":
                return self.main if main is None else main
            if relative == "tools/saiai-cli/kernel/src/claude_launcher.rs":
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

    def test_accepts_only_brand_names_in_diagnostics(self) -> None:
        self.verify(launcher=self.inject('eprintln!("{brand_product} via {brand_binary}", brand_product = BRAND.product_name, brand_binary = BRAND.binary_name);'))
        for behavior in (
            'eprintln!("{brand_product}", brand_product = config.api_key);',
            'eprintln!("{brand_product} {token}", brand_product = BRAND.product_name);',
            'eprintln!("{brand_product}");',
            'eprintln!("{brand_product} {brand_binary}", brand_product = BRAND.product_name);',
        ):
            with self.subTest(behavior=behavior):
                with self.assertRaisesRegex(AssertionError, "interpolate credentials"):
                    self.verify(launcher=self.inject(behavior))

    def test_rejects_dynamic_secret_diagnostics(self) -> None:
        for behavior in (
            'eprintln!("{token}");', 'eprint!("{}", token);', 'dbg!(config);',
            # Other macro delimiters, paths and spacing.
            'eprintln!["{}", token];', 'eprintln!{"{}", token}', 'std::eprintln!("{token}");',
            'eprintln ! ("{token}");', 'eprint![r"{token}"];',
            # Escapes that decode to a format capture.
            'eprintln!("\\x7btoken\\x7d");', 'eprintln!("\\u{7b}token\\u{7d}");',
            'eprintln!("{brand_product}\\x7btoken}", brand_product = BRAND.product_name);',
            # Comments between tokens and nested block comments.
            'eprintln /* note */ !("{token}");', 'eprintln! /* note */ ("{token}");',
            '/* outer /* inner */ " */\neprintln!("{token}");',
            'eprintln!(/* lead */ "{}", token);',
            # A quote inside a (byte) char literal does not start a string.
            'let quote = b\'"\';\neprintln!("{token}x");', 'let quote = \'"\';\neprintln!("{token}x");',
            'let quote = \'\\x22\';\neprintln!("{token}x");',
            # A format string that is not a literal.
            'eprintln!(concat!("{tok", "en}"));', 'eprintln!(MESSAGE);',
        ):
            with self.subTest(behavior=behavior):
                with self.assertRaisesRegex(AssertionError, "interpolate credentials"):
                    self.verify(launcher=self.inject(behavior))

    def test_accepts_plain_diagnostics_in_any_delimiter(self) -> None:
        self.verify(launcher=self.inject('eprintln!["plain notice; braces \\x41 decoded"];'))
        self.verify(launcher=self.inject('// eprintln!("{token}") in a comment is not code\nconst NOTE: &str = "eprintln!(\\"{token}\\")";'))

    def test_rejects_output_macro_aliases(self) -> None:
        for behavior in (
            'use std::eprintln as notice;\nnotice!("{token}");',
            'use std::{eprintln as notice, env};\nnotice!("{token}");',
            'use std::{\n    io,\n    eprint as note,\n};',
            'pub(crate) use std::dbg as inspect;',
            'use std::println as out;\nout!("plain");',
        ):
            with self.subTest(behavior=behavior):
                with self.assertRaisesRegex(AssertionError, "under another name"):
                    self.verify(launcher=self.inject(behavior))

    def test_accepts_c_strings_and_argument_comments(self) -> None:
        self.verify(launcher=self.inject('const NAME: &core::ffi::CStr = c"println!{}";\nconst RAW: &core::ffi::CStr = cr#"eprintln!("{token}")"#;'))
        self.verify(launcher=self.inject('eprintln!("plain" /* note */);'))
        self.verify(launcher=self.inject('eprintln!("{brand_product}" /* a */, /* b */ brand_product = BRAND.product_name);'))
        self.verify(launcher=self.inject('// use std::eprintln as notice;\nconst TEXT: &str = "use std::println as out;";'))
        self.verify(launcher=self.inject('fn r#use(eprintln: u8) -> u16 { eprintln as u16 }\nconst X: u8 = 0;'))

    def test_c_strings_do_not_hide_the_next_diagnostic(self) -> None:
        for behavior in (
            'const RAW: &core::ffi::CStr = cr#"a"b"#;\neprintln!("{token}");',
            'const TEXT: &core::ffi::CStr = c"a\\"b";\neprintln!("{token}");',
        ):
            with self.subTest(behavior=behavior):
                with self.assertRaisesRegex(AssertionError, "interpolate credentials"):
                    self.verify(launcher=self.inject(behavior))

    def test_rejects_extra_arguments_hidden_behind_comments(self) -> None:
        with self.assertRaisesRegex(AssertionError, "interpolate credentials"):
            self.verify(launcher=self.inject('eprintln!("plain" /* note */, "extra");'))

    def test_accepts_underscored_unicode_escape(self) -> None:
        self.verify(launcher=self.inject('eprintln!("notice \\u{4_1} \\u{4________1}");'))

    def test_rejects_unreadable_literals_with_a_clear_message(self) -> None:
        for behavior in ('eprintln!("\\xZZ");', 'eprintln!("\\u{12");', 'eprintln!("\\q");',
                         'eprintln!("\\u{110000}");', 'eprintln!("\\u{D800}");', 'eprintln!("\\u{1234567}");'):
            with self.subTest(behavior=behavior):
                with self.assertRaisesRegex(AssertionError, "unreadable"):
                    self.verify(launcher=self.inject(behavior))

    def test_rejects_stdout_in_any_delimiter(self) -> None:
        for behavior in ('println!["plain"];', 'print!{"plain"}', 'println /* x */ !("plain");',

                         'let quote = b\'"\';\nprintln!("plain");'):
            with self.subTest(behavior=behavior):
                with self.assertRaisesRegex(AssertionError, "stdout"):
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


class AitpArtifactTests(unittest.TestCase):
    """--aitp-artifact on synthetic programs: AITP brand data present, no
    other distribution name, no build machine path in any case or with
    either separator."""

    BUILD = Path("/home/builder/work/client")
    ENVIRON = {"HOME": "/home/builder", "CARGO_HOME": "/opt/cargo-home"}

    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.brand = b"\n".join(VERIFIER.aitp_brand_markers())

    def tearDown(self) -> None:
        self.directory.cleanup()

    def check(self, data: bytes, build_dirs: list[Path] | None = None) -> None:
        artifact = Path(self.directory.name) / "aitp"
        artifact.write_bytes(data)
        VERIFIER.verify_aitp_artifacts(
            [artifact], [self.BUILD] if build_dirs is None else build_dirs, self.ENVIRON
        )

    def test_accepts_remapped_program(self) -> None:
        self.check(self.brand + b"/aitp/cargo/registry/src/x/tokio/src/lib.rs /aitp/src/kernel/src/lib.rs")

    def test_rejects_missing_brand_data(self) -> None:
        with self.assertRaisesRegex(AssertionError, "lacks AITP brand data"):
            self.check(self.brand.replace(b"AITP local installation CA", b""))

    def test_rejects_other_distribution_name_in_any_case(self) -> None:
        for name in (b"saiai", b"SAIAI", b"SaiAi"):
            with self.subTest(name=name), self.assertRaisesRegex(AssertionError, "names the other distribution"):
                self.check(self.brand + b" " + name + b" ")

    def test_rejects_build_machine_paths(self) -> None:
        for leak in (
            b"/home/builder/work/client/tools/kernel/src/lib.rs",
            b"\\home\\BUILDER\\Work\\client\\target",
            b"/home/builder/.cargo/registry/src/x/tokio/src/lib.rs",
            b"/opt/cargo-home/registry/src/x/tokio/src/lib.rs",
            b"/home/builder/.rustup/toolchains/x/lib",
        ):
            with self.subTest(leak=leak), self.assertRaisesRegex(AssertionError, "build machine paths"):
                self.check(self.brand + leak)

    def test_requires_build_directory(self) -> None:
        with self.assertRaisesRegex(AssertionError, "needs at least one --build-dir"):
            self.check(self.brand, build_dirs=[])
        with self.assertRaisesRegex(AssertionError, "not absolute"):
            self.check(self.brand, build_dirs=[Path("relative/dir")])

    def test_never_treats_the_root_as_a_build_path(self) -> None:
        paths = VERIFIER.build_machine_paths([Path("/")], {"HOME": "/", "USERPROFILE": "C:\\"})
        self.assertNotIn("", paths)
        self.assertNotIn("/", paths)
        self.assertNotIn("C:", paths)

    def test_short_build_paths_are_checked(self) -> None:
        self.ENVIRON = {"HOME": "/zz"}
        for leak in (b"/x/src/lib.rs", b"/zz/private/file", b"/X"):
            with self.subTest(leak=leak), self.assertRaisesRegex(AssertionError, "build machine paths"):
                self.check(self.brand + b" " + leak, build_dirs=[Path("/x")])

    def test_a_path_matches_only_as_a_whole_directory(self) -> None:
        # The neutral prefixes do not count as a build directory that is
        # a prefix of their name.
        self.ENVIRON = {"HOME": "/ait"}
        self.check(self.brand + b" /aitp/src/lib.rs /aitp/home", build_dirs=[Path("/aitp/s")])

    def test_ci_checks_the_remapped_release_and_saiai_release_does_not(self) -> None:
        def broken(path: str, old: str, new: str):
            def read(relative: str) -> str:
                contents = ORIGINAL_TEXT(relative)
                return contents.replace(old, new) if relative == path else contents
            return read

        for path, old, new, message in (
            (".github/workflows/ci.yml", "--aitp-artifact tools/saiai-cli/target/release/aitp", "", "does not check the remapped"),
            (".github/workflows/ci.yml", "bash scripts/build-release.sh --locked", "cargo build --release --bin aitp", "does not check the remapped"),
            (".github/workflows/saiai-cli-release.yml", "python3 scripts/saiai-cli/verify-release.py \\", "bash tools/saiai-cli/kernel/scripts/build-release.sh\n          python3 scripts/saiai-cli/verify-release.py \\", "must not use"),
            (VERIFIER.AITP_RELEASE_BUILD, "--remap-path-prefix=", "--no-remap=", "build script is missing"),
        ):
            with self.subTest(path=path, old=old), patch.object(VERIFIER, "text", side_effect=broken(path, old, new)):
                with self.assertRaisesRegex(AssertionError, message):
                    VERIFIER.verify_workflows_and_docs()


ORIGINAL_TEXT = VERIFIER.text


if __name__ == "__main__":
    unittest.main()
