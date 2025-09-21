use serde::Serialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::fmt::Display;
use std::hash::Hash;

#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct Counter {
    pub count: u64,
    pub size: u64,
}

#[derive(Debug, Default)]
pub struct ParseResult {
    pub total_count: u64,
    pub total_size: u64,
    pub eth_protocols: HashMap<String, Counter>,
    pub ip_protocols: HashMap<String, Counter>,
    pub ip4_ttl: HashMap<u8, Counter>,
    pub tcp_flags: HashMap<String, Counter>,
    pub src_ports: HashMap<u16, Counter>,
    pub dst_ports: HashMap<u16, Counter>,
    pub src_addr: HashMap<String, Counter>,
    pub dst_addr: HashMap<String, Counter>,
}

impl ParseResult {
    pub fn add_total(&mut self, size: u64) {
        self.total_count += 1;
        self.total_size += size;
    }

    pub fn to_json(&self) -> Value {
        fn to_map<K: Display>(m: &HashMap<K, Counter>) -> serde_json::Map<String, Value> {
            m.iter()
                .map(|(k, v)| (k.to_string(), json!({"count": v.count, "size": v.size})))
                .collect()
        }

        json!({
            "total_count": self.total_count,
            "total_size": self.total_size,
            "eth_protocols": to_map(&self.eth_protocols),
            "ip_protocols": to_map(&self.ip_protocols),
            "ip4_ttl": to_map(&self.ip4_ttl),
            "tcp_flags": to_map(&self.tcp_flags),
            "src_ports": to_map(&self.src_ports),
            "dst_ports": to_map(&self.dst_ports),
            "src_addr": to_map(&self.src_addr),
            "dst_addr": to_map(&self.dst_addr),
        })
    }
}

/// Свободная функция без заимствования `self` — избегаем двойного `&mut` на `target`
pub fn bump<K: Eq + Hash>(map: &mut HashMap<K, Counter>, key: K, sz: u64) {
    let e = map.entry(key).or_insert(Counter::default());
    e.count += 1;
    e.size += sz;
}

