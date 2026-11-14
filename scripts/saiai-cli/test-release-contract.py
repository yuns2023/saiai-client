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

    def test_paths_overlapping_the_neutral_prefixes_are_refused(self) -> None:
        for build in ("/aitp", "/aitp/src", "/aitp/sr", "/AITP/Src/x", "/ait", "/aitp/target/release"):
            with self.subTest(build=build), self.assertRaisesRegex(AssertionError, "overlaps the neutral prefixes"):
                self.check(self.brand, build_dirs=[Path(build)])
        self.ENVIRON = {"HOME": "/aitp/hom"}
        with self.assertRaisesRegex(AssertionError, "overlaps the neutral prefixes"):
            self.check(self.brand)

    def test_a_path_ending_a_neutral_prefix_is_not_a_leak(self) -> None:
        # `/src` and `/home` (a container's mount point, a root HOME) end
        # the neutral prefixes `/aitp/src` and `/aitp/home` ...
        self.ENVIRON = {"HOME": "/home"}
        self.check(self.brand + b" /aitp/src/lib.rs\0/aitp/home/x /aitp/src", build_dirs=[Path("/src")])
        # A path inside a neutral prefix (`/sr` in `/aitp/src`) is the
        # prefix's own bytes.
        self.check(self.brand + b" /aitp/src/lib.rs", build_dirs=[Path("/sr")])
        # ... and are still found anywhere else, including past the end of a
        # neutral prefix or around one.
        for leak in (b"/src/lib.rs", b"/aitp/srcx/lib.rs", b"/aitp/src@x", b"/aitp/srcSTRING", b"/home/x", b"/x/aitp/src/lib.rs"):
            with self.subTest(leak=leak), self.assertRaisesRegex(AssertionError, "build machine paths"):
                self.check(self.brand + b" /aitp/src/lib.rs " + leak, build_dirs=[Path("/src"), Path("/x/aitp/src")])
        # A build path that holds a neutral prefix is found in full.
        for build, leak in (("/opt/aitp/src/build", b"\0/opt/aitp/src/build/lib.rs\0"), ("/opt/aitp/src-real", b"/opt/aitp/src-real/lib.rs")):
            with self.subTest(build=build), self.assertRaisesRegex(AssertionError, "build machine paths"):
                self.check(self.brand + leak, build_dirs=[Path(build)])

    def test_a_build_path_next_to_another_string_is_found(self) -> None:
        for data in (b"\0/home/builder/work/clientNextString\0", b"/home/builder/work/client@x"):
            with self.subTest(data=data), self.assertRaisesRegex(AssertionError, "build machine paths"):
                self.check(self.brand + data)

    def test_workflows_leave_aitp_releases_to_the_kernel_ci(self) -> None:
        def broken(path: str, old: str, new: str):
            def read(relative: str) -> str:
                contents = ORIGINAL_TEXT(relative)
                if relative == path:
                    self.assertIn(old, contents)
                    return contents.replace(old, new, 1)
                return contents
            return read

        verify = "          python3 scripts/saiai-cli/verify-release.py\n"
        check = "          python3 scripts/saiai-cli/check-kernel-submodule.py\n"
        for path, old, new, message in (
            (".github/workflows/saiai-cli-release.yml", verify, "          bash tools/saiai-cli/kernel/scripts/build-release.sh\n" + verify, "must not use"),
            (".github/workflows/ci.yml", verify, "          bash tools/saiai-cli/kernel/scripts/build-release.sh\n" + verify, "must not use"),
            (".github/workflows/ci.yml", verify, '          python3 scripts/saiai-cli/verify-release.py --aitp-artifact /tmp/aitp --build-dir "$GITHUB_WORKSPACE"\n' + verify, "must not use"),
            # The pinned kernel commit is checked in everyday CI, in every
            # release run and before every push.
            (".github/workflows/ci.yml", check, "", "kernel submodule check"),
            (".github/workflows/ci.yml", "          python3 scripts/saiai-cli/test-check-kernel-submodule.py\n", "", "kernel submodule check tests"),
            (".github/workflows/saiai-cli-release.yml", "        run: python3 scripts/saiai-cli/check-kernel-submodule.py\n", "        run: python3 scripts/saiai-cli/check-kernel-submodule.py --offline\n", "kernel submodule check"),
            ("scripts/git-hooks/pre-push", "(cd \"$repo_root\" && python3 scripts/saiai-cli/check-kernel-submodule.py)\n", "", "does not run"),
        ):
            with self.subTest(path=path, old=old), patch.object(VERIFIER, "text", side_effect=broken(path, old, new)):
                with self.assertRaisesRegex(AssertionError, message):
                    VERIFIER.verify_workflows_and_docs()


CI = ".github/workflows/ci.yml"
RELEASE = ".github/workflows/saiai-cli-release.yml"
CARGO_TEST = "        run: cargo test --locked --manifest-path tools/saiai-cli/Cargo.toml --workspace\n"


class WorkflowStructureTests(unittest.TestCase):
    """The division of work between the workflows is read from their
    structure: text that only looks like a check does not count."""

    def rejects(self, path: str, old: str, new: str, message: str, count: int = 1) -> None:
        original = ORIGINAL_TEXT(path)
        self.assertEqual(original.count(old), count, old)

        def read(relative: str) -> str:
            contents = ORIGINAL_TEXT(relative)
            return contents.replace(old, new) if relative == path else contents

        with patch.object(VERIFIER, "text", side_effect=read):
            with self.assertRaisesRegex(AssertionError, message):
                VERIFIER.verify_workflows_and_docs()

    def test_accepts_the_workflows(self) -> None:
        VERIFIER.verify_workflows_and_docs()

    def test_foreign_names_cannot_be_overridden(self) -> None:
        for value in ("''", "other", "saiai-x"):
            with self.subTest(level="step", value=value):
                self.rejects(CI, CARGO_TEST, CARGO_TEST + f"        env:\n          AITP_TEST_FOREIGN_NAMES: {value}\n", "overrides AITP_TEST_FOREIGN_NAMES")
        self.rejects(CI, "    name: Config client\n", "    name: Config client\n    env:\n      AITP_TEST_FOREIGN_NAMES: ''\n", "overrides AITP_TEST_FOREIGN_NAMES")
        self.rejects(CI, "  AITP_TEST_FOREIGN_NAMES: saiai\n", "  AITP_TEST_FOREIGN_NAMES: other\n", "overrides AITP_TEST_FOREIGN_NAMES")
        self.rejects(
            RELEASE, "          AITP_TEST_FOREIGN_NAMES: saiai\n", "          AITP_TEST_FOREIGN_NAMES: ''\n",
            "overrides AITP_TEST_FOREIGN_NAMES", count=2,
        )
        # Dropped from the environment entirely, or cleared in the script.
        self.rejects(CI, "env:\n  AITP_TEST_FOREIGN_NAMES: saiai\n", "", "does not name SAIAI")
        self.rejects(
            RELEASE, "        env:\n          # The kernel's tests also refuse this distribution's name (see ci.yml).\n          AITP_TEST_FOREIGN_NAMES: saiai\n", "",
            "workspace tests with SAIAI", count=2,
        )
        self.rejects(
            CI, CARGO_TEST,
            "        run: |\n          unset AITP_TEST_FOREIGN_NAMES\n          cargo test --locked --manifest-path tools/saiai-cli/Cargo.toml --workspace\n",
            "touches AITP_TEST_FOREIGN_NAMES",
        )
        self.rejects(
            CI, "      - name: Format\n",
            "      - name: Clear\n        run: echo AITP_TEST_FOREIGN_NAMES= >> $GITHUB_ENV\n\n      - name: Format\n",
            "touches",
        )

    def test_skipped_steps_do_not_count(self) -> None:
        for condition in ("false", "${{ false }}", "github.event_name == 'schedule'", "runner.os == 'Windows'", "failure()"):
            with self.subTest(condition=condition):
                self.rejects(CI, "      - name: Test\n", f"      - name: Test\n        if: {condition}\n", "does not run")
        self.rejects(
            RELEASE, "      - name: Verify native macOS environment lifecycle isolation\n        if: runner.os == 'macOS'\n",
            "      - name: Verify native macOS environment lifecycle isolation\n        if: matrix.target == 'aarch64-apple-darwin'\n",
            "does not run the macOS environment isolation on x86_64-apple-darwin",
        )
        # A condition this check cannot read is refused, not guessed.
        self.rejects(CI, "      - name: Test\n", "      - name: Test\n        if: contains(github.ref, 'main')\n", "unsupported function")
        self.rejects(CI, "      - name: Test\n", "      - name: Test\n        if: env.SKIP != 'yes'\n", "unknown here")

    def test_commented_or_masked_commands_do_not_count(self) -> None:
        cases = (
            ("# cargo test --locked --manifest-path tools/saiai-cli/Cargo.toml --workspace", "commented out"),
            ("cargo test --locked --manifest-path tools/saiai-cli/Cargo.toml --workspace || true", "|| true"),
            ("cargo test --locked --manifest-path tools/saiai-cli/Cargo.toml --workspace || :", "|| :"),
            ("cargo test --locked --manifest-path tools/saiai-cli/Cargo.toml --workspace; true", "; true"),
            ("cargo test --locked --manifest-path tools/saiai-cli/Cargo.toml --workspace | tee log", "pipe"),
            ("cargo test --locked --manifest-path tools/saiai-cli/Cargo.toml --workspace &", "background"),
            ("echo cargo test --locked --manifest-path tools/saiai-cli/Cargo.toml --workspace", "echo"),
        )
        for command, label in cases:
            with self.subTest(label=label):
                self.rejects(CI, CARGO_TEST, f"        run: |\n          {command}\n", "does not run")
        for script in (
            "set +e\n          cargo test --locked --manifest-path tools/saiai-cli/Cargo.toml --workspace\n          true",
            "trap 'exit 0' EXIT\n          cargo test --locked --manifest-path tools/saiai-cli/Cargo.toml --workspace",
            "exit 0\n          cargo test --locked --manifest-path tools/saiai-cli/Cargo.toml --workspace",
            "if true; then\n            cargo test --locked --manifest-path tools/saiai-cli/Cargo.toml --workspace\n          fi || true",
            "{\n          cargo test --locked --manifest-path tools/saiai-cli/Cargo.toml --workspace\n          } || echo skipped",
            "cat <<'NOTE'\n          cargo test --locked --manifest-path tools/saiai-cli/Cargo.toml --workspace\n          NOTE",
            "skip() {\n          cargo test --locked --manifest-path tools/saiai-cli/Cargo.toml --workspace\n          }",
        ):
            with self.subTest(script=script):
                self.rejects(CI, CARGO_TEST, f"        run: |\n          {script}\n", "does not run|unbalanced")
        self.rejects(CI, CARGO_TEST, CARGO_TEST + "        continue-on-error: true\n", "continues on error")
        self.rejects(CI, CARGO_TEST, CARGO_TEST + "        shell: bash {0}\n", "uses the shell")
        self.rejects(CI, CARGO_TEST, CARGO_TEST + "        working-directory: tools\n", "working directory")
        self.rejects(CI, "    timeout-minutes: 30\n", "    timeout-minutes: 30\n    continue-on-error: true\n", "continues on error")
        self.rejects(CI, "    timeout-minutes: 30\n", "    timeout-minutes: 30\n    defaults:\n      run:\n        shell: sh\n", "defaults")

    def test_windows_native_failures_stop_the_step(self) -> None:
        stop = "          $PSNativeCommandUseErrorActionPreference = $true\n"
        self.rejects(RELEASE, stop, "", "official Windows Codex 0.146.0 capture")
        self.rejects(RELEASE, stop, stop + "          $PSNativeCommandUseErrorActionPreference = $false\n", "official Windows Codex")
        self.rejects(
            RELEASE, '          npm install --global --prefix "$env:RUNNER_TEMP/codex-0.146.0" "@openai/codex@0.146.0"\n',
            '          try {\n          npm install --global --prefix "$env:RUNNER_TEMP/codex-0.146.0" "@openai/codex@0.146.0"\n          } catch {}\n',
            "official Windows Codex",
        )

    def test_everyday_ci_runs_each_job_on_its_system(self) -> None:
        for runner in ("macos-15", "windows-latest"):
            with self.subTest(runner=runner):
                self.rejects(CI, "    runs-on: ubuntu-22.04\n", f"    runs-on: {runner}\n", "must run on Linux")
        self.rejects(CI, "          - os: ubuntu-22.04\n", "          - os: macos-15\n", "must run on Linux")
        self.rejects(CI, "    runs-on: windows-latest\n", "    runs-on: ubuntu-22.04\n", "must run on Windows")
        self.rejects(CI, "          - os: macos-15-intel\n", "          - os: windows-latest\n", "must run on macOS")
        self.rejects(
            CI, "          - os: macos-15-intel\n            arch: x86_64\n", "", "native macOS matrix differs",
        )
        ci = ORIGINAL_TEXT(CI)
        start, end = ci.index("  client-windows:\n"), ci.index("  client-macos:\n")
        self.rejects(CI, ci[start:end], "", "jobs differ")

    def test_everyday_ci_keeps_the_native_checks(self) -> None:
        for old, new, message in (
            ("          cargo test --locked --manifest-path tools/saiai-cli/Cargo.toml -p saiai\n", "", "native (Windows|macOS) SAIAI tests"),
            ("          python3 scripts/saiai-cli/test-macos-environments.py\n", "          echo\n", "macOS environment isolation"),
            ("          python3 scripts/saiai-cli/test-macos-service.py\n", "          echo\n", "macOS LaunchAgent"),
            ("        if: matrix.arch == 'arm64'\n", "        if: matrix.arch == 'x86_64'\n", "official macOS Codex capture"),
            ("        run: python scripts/saiai-cli/test-windows-environments.py", "        run: echo skipped #", "Windows environment isolation"),
            ("        run: python scripts/saiai-cli/test-windows-self-update.py", "        run: echo skipped #", "Windows self-update"),
            ("          $PSNativeCommandUseErrorActionPreference = $true\n", "", "official Windows Codex 0.146.0 capture"),
            ("        run: python scripts/saiai-cli/verify-windows-reproducibility.py", "        run: echo skipped #", "reproducible Windows image"),
        ):
            with self.subTest(old=old):
                self.rejects(CI, old, new, message, count=ORIGINAL_TEXT(CI).count(old) or 1)
        self.rejects(CI, "  pull_request:\n    branches: [main]\n", "  pull_request:\n    branches: [main]\n    paths: [tools/**]\n", "every pull request")
        self.rejects(CI, "name: Client CI\n", "name: Client checks\n", "named 'Client CI'")

    def test_release_keeps_every_platform_check(self) -> None:
        for old, new, message in (
            ("          - os: macos-15\n            target: aarch64-apple-darwin\n            asset: saiai-macos-aarch64\n", "", "build matrix differs"),
            ("          python3 scripts/saiai-cli/test-macos-environments.py\n", "          echo\n", "macOS environment isolation"),
            ("        run: python scripts/saiai-cli/test-windows-environments.py", "        run: echo skipped #", "Windows environment isolation"),
            ("        run: python scripts/saiai-cli/test-windows-self-update.py", "        run: echo skipped #", "self-update"),
            ("          cargo test --locked --manifest-path tools/saiai-cli/Cargo.toml --workspace\n", "", "native workspace tests"),
            ("          cargo test --locked --manifest-path tools/saiai-cli/Cargo.toml -p proxy-cli --features contract --bin aitp\n", "", "AITP brand's platform services"),
            ('          "dist/${{ matrix.asset }}" --version\n', "", "Linux startup check"),
            ("          python3 scripts/saiai-cli/test-uninstall.py\n", "          echo\n", "uninstall"),
        ):
            with self.subTest(old=old):
                self.rejects(RELEASE, old, new, message)
        self.rejects(RELEASE, "name: SAIAI CLI Release\n", "name: Release\n", "named 'SAIAI CLI Release'")

    def test_release_publishes_only_on_confirmation(self) -> None:
        # A tag push alone may not publish, and nothing else may write.
        self.rejects(RELEASE, "    if: needs.mode.outputs.mode == 'publish'\n", "    if: needs.mode.outputs.mode != 'preview'\n", "runs .* for a draft run")
        self.rejects(RELEASE, "          draft: true\n", "          draft: false\n", "non-draft release")
        self.rejects(RELEASE, '      if [ "$CONFIRMATION" != "publish $REF_NAME" ]; then\n', '      if false; then\n', "release gate")
        self.rejects(RELEASE, "              mode=draft ;;\n", "              mode=publish ;;\n", "release gate")
        self.rejects(
            RELEASE, "    needs: [mode, build]\n    if: needs.mode.outputs.mode == 'draft'\n",
            "    needs: [mode, build]\n    if: always()\n", "regardless of its needs",
        )
        self.rejects(
            RELEASE, "    tags:\n      - 'saiai-v*'\n", "    tags:\n      - '*'\n", "only by hand or by a saiai-v",
        )
        self.rejects(RELEASE, "    environment: release\n", "", "lost its environment")
        self.rejects(
            RELEASE, "    permissions:\n      contents: write\n      actions: read\n",
            "    permissions:\n      contents: read\n      actions: read\n", "contents permission",
        )

    def test_yaml_tricks_are_refused(self) -> None:
        self.rejects(CI, CARGO_TEST, CARGO_TEST + "        run: echo skipped\n", "repeats the key")
        self.rejects(CI, "      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1\n", "      - uses: actions/checkout@v7\n", "not pinned", count=4)

    def test_review_bypasses_are_refused(self) -> None:
        c = "cargo test --locked --manifest-path tools/saiai-cli/Cargo.toml --workspace"
        for script in (
            f"true ||\n          {c}",
            f":; set +e\n          {c}\n          true",
            f"cat <<'123'\n          {c}\n          123",
            f":; cargo() {{ :; }}\n          {c}",
            f"export AITP_TEST_FOREIGN_''NAMES=\n          {c}",
            f"key=GITHUB_''PATH; printf '%s\\n' /x >> \"${{!key}}\"\n          {c}",
            f"set -n\n          {c}",
            f"set -o noexec\n          {c}",
            f"set -en\n          {c}",
            f"alias cargo=true; {c}",
        ):
            with self.subTest(script=script):
                self.rejects(CI, CARGO_TEST, f"        run: |\n          {script}\n", "does not run|unbalanced")
        self.rejects(CI, "      - name: Test\n", "      - name: Test\n        if: github.ref == 'refs/heads/main'\n", "does not run")
        for condition, message in (("null != ''", "not read here"), ("'0' != false", "not read here"), ("! 'x' == true", "not read here")):
            with self.subTest(condition=condition):
                self.rejects(CI, "      - name: Test\n", f"      - name: Test\n        if: \"{condition}\"\n", message)
        self.assertFalse(VERIFIER.evaluate("!(runner.os == 'Linux')", {"runner.os": "Linux"}))

    def test_release_publication_bypasses_are_refused(self) -> None:
        self.rejects(
            RELEASE, "      - name: Record the release digests\n",
            "      - name: Publish early\n        run: gh release edit \"$GITHUB_REF_NAME\" --draft=false\n\n      - name: Record the release digests\n",
            "must not publish",
        )
        self.rejects(
            RELEASE, "        id: upload\n        if: steps.preflight.outputs.already_published != 'true'\n",
            "        id: upload\n        if: false\n", "skips the draft upload",
        )
        self.rejects(
            RELEASE, '          python3 scripts/saiai-cli/verify-github-release-draft.py --dist dist --tag "$GITHUB_REF_NAME" --state published <"$release_json"\n',
            "", "published release check",
        )
        self.rejects(
            RELEASE, '          cmp "$RUNNER_TEMP/manifest.json" dist/manifest.json\n',
            '          cp "$RUNNER_TEMP/manifest.json" dist/manifest.json\n          cmp "$RUNNER_TEMP/manifest.json" dist/manifest.json\n',
            "rewrites the fetched release assets",
        )
        self.rejects(
            RELEASE, '          sha256sum --check --strict "$RUNNER_TEMP/release-digests/release-digests.sha256"\n', "",
            "checks the digests",
        )
        self.rejects(
            RELEASE, "          name: release-digests\n          path: release-digests.sha256\n",
            "          name: release-digests\n          path: dist/manifest.json\n", "keep the draft's digests",
        )
        submodules = "        with:\n          submodules: true\n"
        for path, count in ((CI, 4), (RELEASE, 5)):
            for new in (
                submodules + "          ref: main\n",
                "",
                "        with:\n          submodules: recursive\n",
                "        with:\n          submodules: false\n",
                submodules + "          fetch-depth: 0\n",
            ):
                with self.subTest(path=path, new=new):
                    self.rejects(path, submodules, new, "check out the commit that started the run, with the kernel submodule", count=count)
        self.rejects(
            RELEASE, "  build:\n    needs: verify\n",
            "  build:\n    needs: mode\n    if: needs.mode.outputs.mode != 'publish'\n", "must need",
        )

    def test_second_review_bypasses_are_refused(self) -> None:
        c = "cargo test --locked --manifest-path tools/saiai-cli/Cargo.toml --workspace"
        for script in (
            f"true || # optional check\n          {c}",
            f"printf '%s\\n' '\n          {c}\n          '",
        ):
            with self.subTest(script=script):
                self.rejects(CI, CARGO_TEST, f"        run: |\n          {script}\n", "does not run|unbalanced")
        release = ORIGINAL_TEXT(RELEASE)
        start = release.index("      - name: Publish immutable release\n")
        publish_step = release[start:].rstrip("\n") + "\n\n"
        moved = release[:start].rstrip("\n") + "\n"
        fetch_end = moved.index("      - name: Download the digests the tag run recorded\n")
        moved = moved[:fetch_end] + publish_step + moved[fetch_end:]
        self.rejects(RELEASE, release, moved, "before it publishes")
        self.rejects(
            RELEASE, "      - name: Download the digests the tag run recorded\n        uses:",
            "      - name: Download the digests the tag run recorded\n        if: false\n        uses:",
            "tag run it fetched",
        )
        self.rejects(RELEASE, "          run-id: ${{ steps.fetch.outputs.run_id }}\n", "          run-id: ${{ github.run_id }}\n", "tag run it fetched")
        self.rejects(
            RELEASE, '          sha256sum --check --strict "$RUNNER_TEMP/release-digests/release-digests.sha256"\n',
            '          sha256sum dist/* > "$RUNNER_TEMP/release-digests/release-digests.sha256"\n          sha256sum --check --strict "$RUNNER_TEMP/release-digests/release-digests.sha256"\n',
            "rewrites|touches the downloaded digests",
        )
        start = release.index("      - name: Download the digests the tag run recorded\n")
        end = release.index("      # The downloaded draft is this tag's release")
        self.rejects(RELEASE, release[start:end], "", "downloads the digests")
        record = release.index("      # The publish run accepts only assets with exactly these digests.\n")
        keep = release.index("      - name: Upload the release digests\n")
        keep_end = release.index("  publish:\n")
        swapped = release[:record] + release[keep:keep_end].rstrip("\n") + "\n\n" + release[record:keep] + release[keep_end:]
        self.rejects(RELEASE, release, swapped.replace("\n\n\n", "\n\n"), "then keep the digests")

    def test_publish_checks_stay_before_publishing(self) -> None:
        release = ORIGINAL_TEXT(RELEASE)
        bundle = "          python3 scripts/saiai-cli/test-release-bundle.py \\\n            --bundle dist \\\n            --setup-sh dist/setup.sh\n"
        start = release.index("      - name: Publish immutable release\n")
        self.assertIn(bundle, release[release.index("  publish:\n"):start])
        head, tail = release[:start], release[start:]
        head = head[: head.rindex(bundle)] + head[head.rindex(bundle) + len(bundle):]
        moved = head + tail.rstrip("\n") + "\n" + bundle.replace("          python3", "          python3", 1)
        self.rejects(RELEASE, release, moved, "before publishing")

    def test_third_review_bypasses_are_refused(self) -> None:
        # GITHUB_ENV is written once, by the AITP release hand-over only.
        self.rejects(
            CI, "      - name: Format\n",
            "      - name: Note\n        run: echo X=1 >> \"$GITHUB_ENV\"\n\n      - name: Format\n", "touches GITHUB_ENV",
        )
        # The publish step re-reads the release right before the PATCH.
        recheck = '          python3 scripts/saiai-cli/verify-github-release-draft.py --dist dist --tag "$GITHUB_REF_NAME" --state draft <"$RUNNER_TEMP/before-publish.json"\n'
        self.rejects(RELEASE, recheck, "", "re-check the release right before publishing")
        release = ORIGINAL_TEXT(RELEASE)
        start = release.index("          # Re-read this release right before publishing")
        end = release.index("          publish_status=0\n")
        tail_end = release.index('          echo "publish request status: $publish_status"\n')
        moved = release[:start] + release[end:tail_end] + release[start:end] + release[tail_end:]
        self.rejects(RELEASE, release, moved, "re-check the release right before publishing")

    def test_no_step_changes_directory(self) -> None:
        # Not even into the kernel submodule (cargo would read its own
        # .cargo/config.toml and rust-toolchain.toml there).
        self.rejects(CI, CARGO_TEST, "        run: |\n          cd tools/saiai-cli/kernel\n          cargo test --locked --manifest-path tools/saiai-cli/Cargo.toml --workspace\n", "changes directory")
        self.rejects(
            CI, CARGO_TEST,
            '        run: |\n          if [ -d tools/saiai-cli/kernel ]; then cd tools/saiai-cli/kernel; fi\n          cargo test --locked --manifest-path tools/saiai-cli/Cargo.toml --workspace\n',
            "changes directory",
        )
        self.rejects(CI, CARGO_TEST, "        run: |\n          cd tools && cd ..\n          cargo test --locked --manifest-path tools/saiai-cli/Cargo.toml --workspace\n", "changes directory")
        self.rejects(RELEASE, "        run: python3 scripts/saiai-cli/check-kernel-submodule.py\n", "        run: |\n          pushd tools\n          python3 scripts/saiai-cli/check-kernel-submodule.py\n", "changes directory")

    def test_quoted_shell_words_are_read_as_the_shell_reads_them(self) -> None:
        c = "cargo test --locked --manifest-path tools/saiai-cli/Cargo.toml --workspace"
        for script in (f"set '-n'\n          {c}", f'set -o "noexec"\n          {c}', f"s\"et\" -n\n          {c}"):
            with self.subTest(script=script):
                self.rejects(CI, CARGO_TEST, f"        run: |\n          {script}\n", "does not run")
        self.rejects(CI, CARGO_TEST, f'        run: |\n          "cd" /tmp\n          {c}\n', "changes directory")
        # No step changes directory or hands environment to the next.
        self.rejects(
            CI, "      - name: Format\n",
            '      - name: Kernel copy\n        run: |\n          standalone="$(mktemp -d)"\n          cd "$standalone/kernel"\n\n      - name: Format\n',
            "changes directory",
        )
        self.rejects(
            CI, "      - name: Format\n",
            '      - name: Hand over\n        run: |\n          aitp=/bin/true\n          echo "AITP_PROGRAM=$aitp" >> "$GITHUB_ENV"\n\n      - name: Format\n',
            "touches GITHUB_ENV",
        )

    def test_expression_reader(self) -> None:
        context = {"runner.os": "macOS", "matrix.target": "aarch64-apple-darwin"}
        for expression, expected in (
            ("runner.os == 'macos'", True),
            ("${{ runner.os != 'Linux' && matrix.target == 'aarch64-apple-darwin' }}", True),
            ("!(runner.os == 'macOS')", False),
            ("runner.os == 'Windows' || startsWith(matrix.target, 'aarch64')", True),
            ("success() && runner.os == 'macOS'", True),
            ("failure()", False),
            (False, False),
        ):
            with self.subTest(expression=expression):
                self.assertEqual(VERIFIER.evaluate(expression, context), expected)


ORIGINAL_TEXT = VERIFIER.text


if __name__ == "__main__":
    unittest.main()
