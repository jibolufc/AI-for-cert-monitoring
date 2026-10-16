use std::io::Write;
use std::process::ExitCode;
use std::time::Duration;

use kex_probe::{probe, serve, Group, LabServer, ProbeError, ProbeRequest};

const USAGE: &str = "usage:
  kex-probe probe --host <loopback-ip> --port <port> [--server-name <dns>] [--groups <list>] [--timeout-ms <ms>]
  kex-probe serve [--port <port>] [--groups <list>] [--connections <n>] [--tls12-only] [--dns-name <dns>]

groups: x25519mlkem768, x25519, secp256r1, secp384r1 (comma-separated)
exit codes: 0 observed, 1 handshake or network failure, 2 rejected input";

fn value<'a>(args: &'a [String], i: &mut usize, flag: &str) -> Result<&'a str, ProbeError> {
    *i += 1;
    args.get(*i)
        .map(String::as_str)
        .ok_or_else(|| ProbeError::Rejected(format!("{flag} requires a value")))
}

fn number<T: std::str::FromStr>(raw: &str, flag: &str) -> Result<T, ProbeError> {
    raw.parse()
        .map_err(|_| ProbeError::Rejected(format!("{flag} must be a number")))
}

fn run_probe(args: &[String]) -> Result<(), ProbeError> {
    let (mut host, mut port) = (None, None);
    let mut request = ProbeRequest::new("", 0);
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--host" => host = Some(value(args, &mut i, "--host")?.to_string()),
            "--port" => port = Some(number::<u16>(value(args, &mut i, "--port")?, "--port")?),
            "--server-name" => request.server_name = value(args, &mut i, "--server-name")?.into(),
            "--groups" => request.groups = Group::parse_list(value(args, &mut i, "--groups")?)?,
            "--timeout-ms" => {
                let ms: u64 = number(value(args, &mut i, "--timeout-ms")?, "--timeout-ms")?;
                request.timeout = Duration::from_millis(ms);
            }
            other => return Err(ProbeError::Rejected(format!("unknown argument: {other}"))),
        }
        i += 1;
    }
    request.host = host.ok_or_else(|| ProbeError::Rejected("--host is required".into()))?;
    request.port = port.ok_or_else(|| ProbeError::Rejected("--port is required".into()))?;
    let observation = probe(&request)?;
    println!("{observation}");
    Ok(())
}

fn run_serve(args: &[String]) -> Result<(), ProbeError> {
    let mut server = LabServer {
        groups: vec![Group::X25519Mlkem768, Group::X25519],
        tls12_only: false,
        dns_name: "localhost".into(),
    };
    let (mut port, mut connections) = (0u16, 1u32);
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--port" => port = number(value(args, &mut i, "--port")?, "--port")?,
            "--groups" => server.groups = Group::parse_list(value(args, &mut i, "--groups")?)?,
            "--connections" => {
                connections = number(value(args, &mut i, "--connections")?, "--connections")?
            }
            "--tls12-only" => server.tls12_only = true,
            "--dns-name" => server.dns_name = value(args, &mut i, "--dns-name")?.into(),
            other => return Err(ProbeError::Rejected(format!("unknown argument: {other}"))),
        }
        i += 1;
    }
    if !(1..=1000).contains(&connections) {
        return Err(ProbeError::Rejected(
            "--connections must be 1 to 1000".into(),
        ));
    }
    let (listener, config) = server.bind(port)?;
    let addr = listener
        .local_addr()
        .map_err(|e| ProbeError::Failed(format!("local address: {e}")))?;
    // One JSON line tells the caller where to connect.
    println!(
        "{}",
        serde_json::json!({ "listening": addr.to_string(), "port": addr.port() })
    );
    std::io::stdout().flush().ok();
    serve(&listener, config, connections);
    Ok(())
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("probe") => run_probe(&args[1..]),
        Some("serve") => run_serve(&args[1..]),
        Some("--help") | Some("-h") => {
            println!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        _ => Err(ProbeError::Rejected("expected a subcommand".into())),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{}", serde_json::json!({ "error": error.to_string() }));
            if matches!(error, ProbeError::Rejected(_)) {
                eprintln!("{USAGE}");
                ExitCode::from(2)
            } else {
                ExitCode::from(1)
            }
        }
    }
}
