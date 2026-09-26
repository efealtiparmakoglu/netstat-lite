use netstat_lite::netstat_darwin;
use netstat_lite::proc_net;
use netstat_lite::table::{self, Filter, Row};

const PROC_TCP: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 12345\n\
   1: 0100007F:BB8C 8EFBB24D:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 23456\n";

const NETSTAT: &str = "Active Internet connections (including servers)\n\
Proto Recv-Q Send-Q  Local Address      Foreign Address    (state)\n\
tcp4       0      0  127.0.0.1.8080     *.*                LISTEN\n\
tcp4       0      0  10.0.0.5.52100     142.250.74.238.443 ESTABLISHED\n\
udp4       0      0  *.5353             *.*\n";

#[test]
fn proc_net_parses_hex_addresses_and_states() {
    let entries = proc_net::parse_proc_net(PROC_TCP, 4);
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].local, "127.0.0.1:8080");
    assert_eq!(entries[0].state, "LISTEN");
    assert_eq!(entries[0].inode, 12345);
    // 8EFBB24D little-endian → 77.178.251.142
    assert_eq!(entries[1].remote, "77.178.251.142:443");
    assert_eq!(entries[1].state, "ESTABLISHED");
}

#[test]
fn netstat_parses_tcp_and_udp() {
    let entries = netstat_darwin::parse_netstat(NETSTAT);
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[0].local, "127.0.0.1.8080");
    assert_eq!(entries[0].state, "LISTEN");
    assert_eq!(entries[2].proto, "udp4");
    assert_eq!(entries[2].state, "UNBOUND");
}

#[test]
fn filter_state_port_process() {
    let rows = [
        Row {
            proto: "tcp".into(),
            local: "127.0.0.1:8080".into(),
            remote: "0.0.0.0:*".into(),
            state: "LISTEN".into(),
            pid: Some(42),
            process: Some("myapp".into()),
        },
        Row {
            proto: "tcp".into(),
            local: "10.0.0.5:52100".into(),
            remote: "1.2.3.4:443".into(),
            state: "ESTABLISHED".into(),
            pid: None,
            process: None,
        },
    ];
    let mut f = Filter { state: Some("LISTEN".into()), ..Default::default() };
    assert_eq!(rows.iter().filter(|r| f.matches(r)).count(), 1);

    f = Filter { port: Some(443), ..Default::default() };
    assert_eq!(rows.iter().filter(|r| f.matches(r)).count(), 1);

    f = Filter { process: Some("my".into()), ..Default::default() };
    assert_eq!(rows.iter().filter(|r| f.matches(r)).count(), 1);

    f = Filter { state: Some("TIME_WAIT".into()), ..Default::default() };
    assert_eq!(rows.iter().filter(|r| f.matches(r)).count(), 0);
}

#[test]
fn render_has_headers_and_rows() {
    let rows = vec![Row {
        proto: "tcp".into(),
        local: "127.0.0.1:80".into(),
        remote: "0.0.0.0:*".into(),
        state: "LISTEN".into(),
        pid: None,
        process: None,
    }];
    let out = table::render(&rows, &Filter::default());
    assert!(out.contains("PROTO"));
    assert!(out.contains("LISTEN"));
}

#[test]
fn v6_compression() {
    let e = proc_net::decode_addr(
        "00000000000000000000000000000001:0050",
        6,
    );
    assert_eq!(e, Some("[::1]:80".to_string()));
}
