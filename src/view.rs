use bytesize::ByteSize;
use comfy_table::{Cell, Table};
use comfy_table::presets::ASCII_MARKDOWN;
use serde_json::json;
use std::cmp::Ordering;
use std::collections::HashMap;
use std::fmt::Display;

use crate::stats::{Counter, ParseResult};

pub fn print_json(input: &ParseResult, output: &ParseResult, undefined: &ParseResult) {
    println!(
        "{}",
        json!({
            "input": input.to_json(),
            "output": output.to_json(),
            "undefined": undefined.to_json(),
        })
        .to_string()
    );
}

pub fn print_human(title: &str, r: &ParseResult, seconds: u64, sort_by_count: bool, top: u64) {
    println!("=== {title} ===");
    println!("  TOTAL COUNT: {}", r.total_count);
    println!("  TOTAL SIZE : {} ({})",
        ByteSize(r.total_size),
        bytes_per_second(r.total_size, seconds)
    );
    println!("  TOTAL PPS  : {:.2}", r.total_count as f64 / seconds as f64);

    section("L2 (EtherType)", &r.eth_protocols, r, seconds, sort_by_count, top);
    section("L3 (IP Protocol)", &r.ip_protocols, r, seconds, sort_by_count, top);
    section("IPv4 TTL", &r.ip4_ttl, r, seconds, sort_by_count, top);
    section("TCP Flags", &r.tcp_flags, r, seconds, sort_by_count, top);
    section("SRC Ports", &r.src_ports, r, seconds, sort_by_count, top);
    section("DST Ports", &r.dst_ports, r, seconds, sort_by_count, top);
    section("SRC IP", &r.src_addr, r, seconds, sort_by_count, top);
    section("DST IP", &r.dst_addr, r, seconds, sort_by_count, top);
}

fn bytes_per_second(size: u64, seconds: u64) -> String {
    let bps = 8f64 * size as f64 / seconds as f64;
    let mbps = bps / 1_000_000f64;
    format!("{mbps:.2} Mb/s")
}

fn section<K: Display + Eq + std::hash::Hash>(
    title: &str,
    data: &HashMap<K, Counter>,
    r: &ParseResult,
    seconds: u64,
    sort_by_count: bool,
    top: u64,
) {
    if data.is_empty() {
        return;
    }
    println!("\n-- {title}");

    let mut rows: Vec<(&K, &Counter)> = data.iter().collect();
    rows.sort_by(|a, b| {
        let (ka, kb) = (a.0, b.0);
        let (va, vb) = (a.1, b.1);
        let ord = if sort_by_count {
            va.count.cmp(&vb.count)
        } else {
            va.size.cmp(&vb.size)
        };
        if ord == Ordering::Equal {
            format!("{ka}").cmp(&format!("{kb}"))
        } else {
            ord
        }
    });
    rows.reverse();

    let mut table = Table::new();
    table.load_preset(ASCII_MARKDOWN);
    table.set_header(vec!["Key", "PPS", "Mb/s", "COUNT %", "SIZE %"]);

    let mut other = Counter::default();
    for (idx, (k, v)) in rows.into_iter().enumerate() {
        if (idx as u64) < top {
            let pps = v.count as f64 / seconds as f64;
            let mbs = (8f64 * v.size as f64 / seconds as f64) / 1_000_000f64;
            let c_perc = 100f64 * v.count as f64 / r.total_count.max(1) as f64;
            let s_perc = 100f64 * v.size as f64 / r.total_size.max(1) as f64;

            table.add_row(vec![
                Cell::new(format!("{k}")),
                Cell::new(format!("{pps:.2}")),
                Cell::new(format!("{mbs:.2}")),
                Cell::new(format!("{c_perc:.2}")),
                Cell::new(format!("{s_perc:.2}")),
            ]);
        } else {
            other.count += v.count;
            other.size += v.size;
        }
    }

    if other.count > 0 {
        let pps = other.count as f64 / seconds as f64;
        let mbs = (8f64 * other.size as f64 / seconds as f64) / 1_000_000f64;
        let c_perc = 100f64 * other.count as f64 / r.total_count.max(1) as f64;
        let s_perc = 100f64 * other.size as f64 / r.total_size.max(1) as f64;
        table.add_row(vec![
            Cell::new("Other"),
            Cell::new(format!("{pps:.2}")),
            Cell::new(format!("{mbs:.2}")),
            Cell::new(format!("{c_perc:.2}")),
            Cell::new(format!("{s_perc:.2}")),
        ]);
    }

    println!("{table}");
}

