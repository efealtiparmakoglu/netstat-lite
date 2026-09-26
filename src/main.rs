// netstat-lite — socket table with filters and live refresh.

use netstat_lite::table::{self, Filter};
use std::io::{self, Write};
use std::process::ExitCode;
use std::thread;
use std::time::Duration;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const HELP: &str = "\
netstat-lite — socket table with process mapping and live refresh

USAGE:
  netstat-lite [FLAGS]

FLAGS:
  --state STATE      filter: LISTEN, ESTABLISHED, TIME_WAIT...
  --port N           filter by local or remote port
  --proc NAME        filter by process name substring
  --once             print once and exit (no live refresh)
  --interval MS      refresh interval (default 1000)
  --proc-root DIR    read /proc-style files from DIR (Linux backend; tests)
  -h, --help         show this help
  -V, --version      show version";

fn main() -> ExitCode {
    let mut state: Option<String> = None;
    let mut port: Option<u16> = None;
    let mut process: Option<String> = None;
    let mut once = false;
    let mut interval = 1000u64;
    let mut proc_root: Option<String> = None;
    let mut file: Option<String> = None;

    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "-h" | "--help" => {
                println!("{HELP}");
                return ExitCode::SUCCESS;
            }
            "-V" | "--version" => {
                println!("netstat-lite {VERSION}");
                return ExitCode::SUCCESS;
            }
            "--state" => match args.next() {
                Some(v) => state = Some(v.to_ascii_uppercase()),
                None => return usage("--state needs a value"),
            },
            "--port" => match args.next().and_then(|v| v.parse().ok()) {
                Some(v) => port = Some(v),
                None => return usage("--port needs a number"),
            },
            "--proc" => match args.next() {
                Some(v) => process = Some(v),
                None => return usage("--proc needs a value"),
            },
            "--once" => once = true,
            "--interval" => match args.next().and_then(|v| v.parse().ok()) {
                Some(v) => interval = v,
                None => return usage("--interval needs milliseconds"),
            },
            "--proc-root" => match args.next() {
                Some(v) => proc_root = Some(v),
                None => return usage("--proc-root needs a directory"),
            },
            "--from-file" => match args.next() {
                Some(v) => file = Some(v),
                None => return usage("--from-file needs a file (netstat -anv output)"),
            },
            other => return usage(&format!("unknown option {other:?}")),
        }
    }

    let filter = Filter { state, port, process };
    let mut stdout = io::stdout();

    loop {
        let rows = if let Some(f) = &file {
            // fixture mode: parse netstat output from a file
            let Ok(text) = std::fs::read_to_string(f) else {
                eprintln!("netstat-lite: cannot read {f}");
                return ExitCode::FAILURE;
            };
            netstat_lite::netstat_darwin::parse_netstat(&text)
                .into_iter()
                .map(|e| netstat_lite::table::Row {
                    proto: e.proto,
                    local: e.local,
                    remote: e.remote,
                    state: e.state,
                    pid: None,
                    process: None,
                })
                .collect()
        } else {
            netstat_lite::table::gather(proc_root.as_deref())
        };

        let table = table::render(&rows, &filter);
        if once {
            println!("{table}");
            return ExitCode::SUCCESS;
        }
        // crude full-screen redraw
        write!(stdout, "\x1b[2J\x1b[H{table}").ok();
        writeln!(stdout).ok();
        stdout.flush().ok();
        thread::sleep(Duration::from_millis(interval));
    }
}

fn usage(msg: &str) -> ExitCode {
    eprintln!("netstat-lite: {msg}");
    ExitCode::from(2)
}
