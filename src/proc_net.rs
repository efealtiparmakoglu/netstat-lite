//! /proc/net/tcp{,6} parser (Linux) — hex address:port pairs and states.

#[derive(Debug, Clone, PartialEq)]
pub struct SocketEntry {
    /// "127.0.0.1:8080" or "[::1]:22"
    pub local: String,
    pub remote: String,
    pub state: String, // LISTEN, ESTABLISHED, ...
    pub inode: u64,
}

/// Decode the little-endian hex address:port format of /proc/net/tcp.
/// IPv4: "0100007F:1F90"; IPv6: 4 little-endian u32 words + port.
pub fn decode_addr(field: &str, family: u8) -> Option<String> {
    let (addr_hex, port_hex) = field.split_once(':')?;
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    if family == 4 {
        // the kernel prints the in-memory (little-endian) u32 — bytes reverse
        let raw = u32::from_str_radix(addr_hex, 16).ok()?;
        let b = raw.to_le_bytes();
        Some(format!("{}.{}.{}.{}:{}", b[0], b[1], b[2], b[3], port))
    } else {
        if addr_hex.len() != 32 {
            return Some(format!("[::]:{port}"));
        }
        // tcp6 prints the 16 in6_addr bytes as plain hex pairs (big-endian)
        let mut octets = [0u8; 16];
        for (i, pair) in addr_hex.as_bytes().chunks(2).enumerate() {
            octets[i] = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
        }
        Some(format!("[{}]:{}", format_v6(&octets), port))
    }
}

/// RFC 5952-ish compression for display.
fn format_v6(b: &[u8; 16]) -> String {
    let groups: Vec<String> = (0..8).map(|i| format!("{:x}", u16::from_be_bytes([b[i * 2], b[i * 2 + 1]]))).collect();
    // find the longest zero run
    let (mut best, mut best_len, mut cur, mut cur_len) = (0usize, 0usize, None, 0usize);
    for (i, g) in groups.iter().enumerate() {
        if g == "0" {
            if cur.is_none() {
                cur = Some(i);
            }
            cur_len += 1;
            if cur_len > best_len {
                best_len = cur_len;
                best = cur.unwrap();
            }
        } else {
            cur = None;
            cur_len = 0;
        }
    }
    if best_len < 2 {
        return groups.join(":");
    }
    format!("{}::{}", groups[..best].join(":"), groups[best + best_len..].join(":"))
}

/// Map /proc state codes to names (subset — the rest shows as-is).
pub fn state_name(code: &str) -> String {
    match code {
        "01" => "ESTABLISHED",
        "02" => "SYN_SENT",
        "03" => "SYN_RECV",
        "04" => "FIN_WAIT1",
        "05" => "FIN_WAIT2",
        "06" => "TIME_WAIT",
        "07" => "CLOSE",
        "08" => "CLOSE_WAIT",
        "09" => "LAST_ACK",
        "0A" => "LISTEN",
        "0B" => "CLOSING",
        _ => "",
    }
    .to_string()
}

/// Parse one /proc/net/tcp (or tcp6) body, skipping the header line.
pub fn parse_proc_net(text: &str, family: u8) -> Vec<SocketEntry> {
    let mut out = Vec::new();
    for line in text.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 10 {
            continue;
        }
        let (Some(local), Some(remote)) = (decode_addr(cols[1], family), decode_addr(cols[2], family)) else {
            continue;
        };
        out.push(SocketEntry {
            local,
            remote,
            state: state_name(cols[3]),
            inode: cols[9].parse().unwrap_or(0),
        });
    }
    out
}
