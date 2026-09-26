//! macOS/BSD backend: parse `netstat -anv` output and `lsof -Fpcn` for
//! process mapping. Both parsers are fixture-tested; live calls shell out.

#[derive(Debug, Clone, PartialEq)]
pub struct SocketEntry {
    pub proto: String,
    pub local: String,
    pub remote: String,
    pub state: String,
}

/// Parse `netstat -anv -p tcp` body (header lines skipped).
pub fn parse_netstat(text: &str) -> Vec<SocketEntry> {
    let mut out = Vec::new();
    for line in text.lines() {
        let cols: Vec<&str> = line.split_whitespace().collect();
        // proto recv-q send-q local foreign state ... (udp has no state)
        if cols.len() < 5 || !cols[0].starts_with("tcp") && !cols[0].starts_with("udp") {
            continue;
        }
        if cols[1].chars().all(|c| !c.is_ascii_digit()) {
            continue; // header line
        }
        let state = if cols.len() >= 6 && !cols[5].starts_with('*') {
            cols[5].to_string()
        } else if cols[0].starts_with("udp") {
            "UNBOUND".to_string()
        } else {
            String::new()
        };
        out.push(SocketEntry {
            proto: cols[0].to_string(),
            local: cols[3].to_string(),
            remote: cols[4].to_string(),
            state,
        });
    }
    out
}

/// Parse `lsof -Fpcn -i` records into (pid, command, port-ish) triples.
/// lsof field output: p<pid> c<command> n<address> on consecutive lines.
pub fn parse_lsof(text: &str) -> Vec<(String, String, String)> {
    let mut out = Vec::new();
    let (mut pid, mut cmd) = (String::new(), String::new());
    for line in text.lines() {
        if line.len() < 2 {
            continue;
        }
        let (field, value) = line.split_at(1);
        match field {
            "p" => pid = value.to_string(),
            "c" => cmd = value.to_string(),
            "n" => out.push((pid.clone(), cmd.clone(), value.to_string())),
            _ => {}
        }
    }
    out
}
