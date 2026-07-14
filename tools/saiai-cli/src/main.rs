use anyhow::{Result, bail};
use saiai_core::Product;
use std::env;

mod claude_proxy;
mod v2;

const USAGE: &str = "\
Usage:
  saiai setup [claude|codex] [--base-url <url>] [--api-key-stdin] # initialize one V2 client
  saiai claude [-- <args...>]                                    # launch Claude in its V2 home
  saiai claude revoke                                            # remove only V2 Claude state
  saiai codex [-- <args...>]                                     # launch Codex in its V2 home
  saiai codex revoke                                             # remove only V2 Codex state
  saiai revoke --all                                             # remove all V2-owned state
  saiai doctor                                                   # check V2 state without reading normal client homes
  saiai ui                                                       # open the V2 desktop app
  saiai --version                                                # print version";

fn main() -> Result<()> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    match parse_command(&args)? {
        Command::Help => print_help(),
        Command::Version => print_version(),
        Command::Setup(setup) => v2::run_setup(setup),
        Command::Claude(command) => v2::run_claude(command),
        Command::Codex(command) => v2::run_codex(command),
        Command::RevokeAll => v2::run_revoke_all(),
        Command::Doctor => v2::run_doctor(),
        Command::Ui => v2::run_ui(),
    }
}

#[derive(Debug)]
enum Command {
    Help,
    Version,
    Setup(V2SetupArgs),
    Claude(V2ClientCommand),
    Codex(V2ClientCommand),
    RevokeAll,
    Doctor,
    Ui,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct V2SetupArgs {
    product: Option<Product>,
    base_url: Option<String>,
    api_key_stdin: bool,
}

#[derive(Debug, Clone, Eq, PartialEq)]
enum V2ClientCommand {
    Launch(Vec<String>),
    Revoke,
}

fn parse_command(args: &[String]) -> Result<Command> {
    let Some(command) = args.first().map(String::as_str) else {
        return Ok(Command::Help);
    };

    match command {
        "-h" | "--help" | "help" => parse_no_arg_command(command, &args[1..], Command::Help),
        "-V" | "--version" | "version" => {
            parse_no_arg_command(command, &args[1..], Command::Version)
        }
        "setup" => Ok(Command::Setup(parse_v2_setup_args(&args[1..])?)),
        "claude" => Ok(Command::Claude(parse_v2_client_command(
            "claude",
            &args[1..],
        )?)),
        "codex" => Ok(Command::Codex(parse_v2_client_command(
            "codex",
            &args[1..],
        )?)),
        "revoke" if args.len() == 2 && args[1] == "--all" => Ok(Command::RevokeAll),
        "revoke" => bail!("`saiai revoke` requires exactly `--all`\n\n{USAGE}"),
        "doctor" => parse_no_arg_command("doctor", &args[1..], Command::Doctor),
        "ui" => parse_no_arg_command("ui", &args[1..], Command::Ui),
        _ => bail!("Unknown command. Run `saiai --help` for supported commands.\n\n{USAGE}"),
    }
}

fn parse_v2_setup_args(args: &[String]) -> Result<V2SetupArgs> {
    let mut product = None;
    let mut base_url = None;
    let mut api_key_stdin = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--base-url" => {
                i += 1;
                if i >= args.len() {
                    bail!("Missing value for --base-url");
                }
                if base_url.replace(args[i].clone()).is_some() {
                    bail!("--base-url may only be provided once");
                }
            }
            "--api-key-stdin" => {
                if api_key_stdin {
                    bail!("--api-key-stdin may only be provided once");
                }
                api_key_stdin = true;
            }
            "--api-key" => bail!(
                "V2 does not accept API keys in command arguments; omit this option for a hidden prompt or use --api-key-stdin"
            ),
            "-h" | "--help" => bail!(USAGE),
            "claude" | "codex" => {
                if product.is_some() {
                    bail!("`saiai setup` accepts exactly one product\n\n{USAGE}");
                }
                product = Some(if args[i] == "claude" {
                    Product::Claude
                } else {
                    Product::Codex
                });
            }
            _ => bail!(
                "Unsupported option or product for `saiai setup`; API keys are never accepted on the command line\n\n{USAGE}"
            ),
        }
        i += 1;
    }
    if api_key_stdin && product.is_none() {
        bail!("`--api-key-stdin` requires `saiai setup claude` or `saiai setup codex`");
    }
    Ok(V2SetupArgs {
        product,
        base_url,
        api_key_stdin,
    })
}

fn parse_v2_client_command(command: &str, args: &[String]) -> Result<V2ClientCommand> {
    if args.first().is_some_and(|argument| argument == "revoke") {
        if args.len() == 1 {
            return Ok(V2ClientCommand::Revoke);
        }
        bail!("`saiai {command} revoke` does not accept arguments\n\n{USAGE}");
    }

    let forwarded = match args.split_first() {
        Some((separator, rest)) if separator == "--" => rest.to_vec(),
        _ => args.to_vec(),
    };
    Ok(V2ClientCommand::Launch(forwarded))
}

fn parse_no_arg_command(command: &str, rest: &[String], parsed: Command) -> Result<Command> {
    if rest.is_empty() {
        return Ok(parsed);
    }
    bail!("`saiai {command}` does not accept arguments\n\n{USAGE}")
}

fn print_help() -> Result<()> {
    println!("{USAGE}");
    Ok(())
}

fn print_version() -> Result<()> {
    println!("saiai {}", env!("CARGO_PKG_VERSION"));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_arguments_and_help_flags_show_only_v2_help() {
        assert!(matches!(parse_command(&[]).unwrap(), Command::Help));
        for argument in ["-h", "--help", "help"] {
            assert!(matches!(
                parse_command(&[argument.to_string()]).unwrap(),
                Command::Help
            ));
        }
        for legacy in [
            "init",
            "init-codex",
            "start",
            "stop",
            "status",
            "logs",
            "update",
            "restart",
            "legacy-doctor",
        ] {
            assert!(parse_command(&[legacy.to_string()]).is_err());
        }
    }

    #[test]
    fn parses_v2_setup_without_accepting_a_key_in_argv() {
        match parse_command(&[
            "setup".to_string(),
            "claude".to_string(),
            "--base-url".to_string(),
            "https://api.example.test".to_string(),
            "--api-key-stdin".to_string(),
        ])
        .unwrap()
        {
            Command::Setup(args) => {
                assert_eq!(args.product, Some(Product::Claude));
                assert_eq!(args.base_url.as_deref(), Some("https://api.example.test"));
                assert!(args.api_key_stdin);
            }
            _ => panic!("expected V2 setup command"),
        }

        let secret = "sk-accidentally-pasted-secret";
        for arguments in [
            vec![
                "setup".to_string(),
                "--api-key".to_string(),
                secret.to_string(),
            ],
            vec!["setup".to_string(), secret.to_string()],
            vec![secret.to_string()],
            vec!["doctor".to_string(), secret.to_string()],
            vec!["ui".to_string(), secret.to_string()],
            vec![
                "claude".to_string(),
                "revoke".to_string(),
                secret.to_string(),
            ],
        ] {
            let error = parse_command(&arguments).unwrap_err().to_string();
            assert!(!error.contains(secret));
        }

        let error = parse_command(&["setup".to_string(), "--api-key-stdin".to_string()])
            .unwrap_err()
            .to_string();
        assert!(error.contains("requires `saiai setup claude` or `saiai setup codex`"));
    }

    #[test]
    fn parses_launch_revoke_version_and_literal_revoke_passthrough() {
        assert!(matches!(
            parse_command(&["--version".to_string()]).unwrap(),
            Command::Version
        ));
        assert_eq!(
            match parse_command(&["claude".to_string(), "revoke".to_string()]).unwrap() {
                Command::Claude(command) => command,
                _ => panic!("expected Claude command"),
            },
            V2ClientCommand::Revoke
        );
        assert_eq!(
            match parse_command(&[
                "codex".to_string(),
                "--".to_string(),
                "revoke".to_string(),
                "--help".to_string(),
            ])
            .unwrap()
            {
                Command::Codex(command) => command,
                _ => panic!("expected Codex command"),
            },
            V2ClientCommand::Launch(vec!["revoke".to_string(), "--help".to_string()])
        );
        assert!(matches!(
            parse_command(&["revoke".to_string(), "--all".to_string()]).unwrap(),
            Command::RevokeAll
        ));
        assert!(parse_command(&["revoke".to_string()]).is_err());
    }
}
