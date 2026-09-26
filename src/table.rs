//! Table assembly + filters shared by both backends.

use crate::netstat_darwin;
use crate::proc_net;

#[derive(Debug, Clone, PartialEq)]
pub struct Row {
    pub proto: String,
    pub local: String,
    pub remote: String,
    pub state: String,
    pub pid: Option<u32>,
    pub process: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct Filter {
    pub state: Option<String>,
    pub port: Option<u16>,
    pub process: Option<String>,
}

impl Filter {
    pub fn matches(&self, row: &Row) -> bool {
        if let Some(state) = &self.state {
            if !row.state.eq_ignore_ascii_case(state) {
                return false;
            }
        }
        if let Some(port) = self.port {
            let port_str = format!("{port}");
            let local_hit = row.local.rsplit(':').next() == Some(&port_str[..]);
            let remote_hit = row.remote.rsplit(':').next() == Some(&port_str[..]);
            if !local_hit && !remote_hit {
                return false;
            }
        }
        if let Some(proc_name) = &self.process {
            match &row.process {
                Some(p) if p.contains(proc_name) => {}
                _ => return false,
            }
        }
        true
    }
}

/// Gather the socket table. `proc_root` injects /proc data for tests
/// (Linux backend); on macOS the netstat backend runs live.
pub fn gather(proc_root: Option<&str>) -> Vec<Row> {
    let mut rows = Vec::new();

    if let Some(root) = proc_root {
        for (file, family, proto) in [
            ("net/tcp", 4u8, "tcp"),
            ("net/tcp6", 6u8, "tcp6"),
            ("net/udp", 4u8, "udp"),
            ("net/udp6", 6u8, "udp6"),
        ] {
            let Ok(text) = std::fs::read_to_string(format!("{root}/{file}")) else {
                continue;
            };
            for e in proc_net::parse_proc_net(&text, family) {
                rows.push(Row {
                    proto: proto.into(),
                    local: e.local,
                    remote: e.remote,
                    state: if e.state.is_empty() { "-".into() } else { e.state },
                    pid: None,
                    process: None,
                });
            }
        }
    } else if cfg!(target_os = "macos") {
        let Ok(out) = std::process::Command::new("/usr/sbin/netstat")
            .args(["-anv", "-p", "tcp"])
            .output()
        else {
            return rows;
        };
        let text = String::from_utf8_lossy(&out.stdout);
        for e in netstat_darwin::parse_netstat(&text) {
            rows.push(Row {
                proto: e.proto,
                local: e.local,
                remote: e.remote,
                state: if e.state.is_empty() { "-".into() } else { e.state },
                pid: None,
                process: None,
            });
        }
        // enrich with lsof (best effort; may need permissions)
        if let Ok(out) = std::process::Command::new("/usr/sbin/lsof")
            .args(["-Fpcn", "-i"])
            .output()
        {
            let text = String::from_utf8_lossy(&out.stdout);
            let map = netstat_darwin::parse_lsof(&text);
            for row in &mut rows {
                let local_port = row.local.rsplit(':').next().unwrap_or("").to_string();
                for (pid, cmd, addr) in &map {
                    if addr.rsplit(':').next() == Some(&local_port[..]) && !pid.is_empty() {
                        row.pid = pid.parse().ok();
                        row.process = Some(cmd.clone());
                        break;
                    }
                }
            }
        }
    }
    rows
}

/// Apply the filter and render the table.
pub fn render(rows: &[Row], filter: &Filter) -> String {
    let mut head = format!(
        "{:<6} {:<28} {:<28} {:<14} {}",
        "PROTO", "LOCAL", "REMOTE", "STATE", "PROCESS"
    );
    head.truncate(100);
    let mut out = vec![head, "-".repeat(100)];
    for row in rows.iter().filter(|r| filter.matches(r)) {
        out.push(format!(
            "{:<6} {:<28} {:<28} {:<14} {}",
            row.proto,
            row.local,
            row.remote,
            row.state,
            row.process
                .as_ref()
                .map(|p| format!("{} ({})", p, row.pid.unwrap_or(0)))
                .unwrap_or_else(|| "-".into())
        ));
    }
    out.join("\n")
}
