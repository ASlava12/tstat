use pktparse::{
    ethernet::{parse_ethernet_frame, EtherType},
    ip::IPProtocol,
    ipv4::parse_ipv4_header,
    ipv6::parse_ipv6_header,
    tcp::{parse_tcp_header, TcpHeader},
    udp::parse_udp_header,
};

use crate::stats::{bump, ParseResult};

fn eth_name(proto: &EtherType) -> &'static str {
    use EtherType::*;
    match proto {
        IPv4 => "IPv4",
        IPv6 => "IPv6",
        ARP => "ARP",
        VLAN => "VLAN",
        LLDP => "LLDP",
        _ => "Other",
    }
}

fn ip_name(p: &IPProtocol) -> &'static str {
    use IPProtocol::*;
    match p {
        TCP => "TCP",
        UDP => "UDP",
        ICMP => "ICMP",
        ICMP6 => "ICMP6",
        IPV6 => "IPV6",
        _ => "Other",
    }
}

fn tcp_flag_name(h: &TcpHeader) -> &'static str {
    if h.flag_syn {
        "SYN"
    } else if h.flag_fin {
        "FIN"
    } else if h.flag_rst {
        "RST"
    } else if h.flag_psh {
        "PSH"
    } else if h.flag_urg {
        "URG"
    } else if h.flag_ack {
        "ACK"
    } else {
        "UNK"
    }
}

#[inline]
fn matches_any_mac(list: &[[u8; 6]], mac: &[u8; 6]) -> bool {
    list.iter().any(|m| m == mac)
}

/// Парсинг одного пакета
pub fn parse_packet(
    data: &[u8],
    local_macs: &Option<Vec<[u8; 6]>>,
    verbose: bool,
    input: &mut ParseResult,
    output: &mut ParseResult,
    undefined: &mut ParseResult,
) {
    let size = data.len() as u64;

    // Ethernet
    let (rem, eth) = match parse_ethernet_frame(data) {
        Ok(ok) => ok,
        Err(e) => {
            if verbose {
                eprintln!("Ethernet parse error: {e}");
            }
            return;
        }
    };

    // Направление
    let dir = if let Some(list) = local_macs {
        if matches_any_mac(list, &eth.dest_mac.0) {
            input.add_total(size);
            0 // in
        } else if matches_any_mac(list, &eth.source_mac.0) {
            output.add_total(size);
            1 // out
        } else {
            undefined.add_total(size);
            2 // undef
        }
    } else {
        undefined.add_total(size);
        2
    };

    let target = match dir {
        0 => input,
        1 => output,
        _ => undefined,
    };

    // L2
    bump(&mut target.eth_protocols, eth_name(&eth.ethertype).to_string(), size);

    // L3
    let (proto, rem) = if eth.ethertype == EtherType::IPv4 {
        match parse_ipv4_header(rem) {
            Ok((rem2, ip4)) => {
                bump(&mut target.ip_protocols, ip_name(&ip4.protocol).to_string(), size);
                bump(&mut target.ip4_ttl, ip4.ttl, size);
                bump(&mut target.src_addr, ip4.source_addr.to_string(), size);
                bump(&mut target.dst_addr, ip4.dest_addr.to_string(), size);
                (ip4.protocol, rem2)
            }
            Err(e) => {
                if verbose {
                    eprintln!("IPv4 parse error: {e}");
                }
                return;
            }
        }
    } else if eth.ethertype == EtherType::IPv6 {
        match parse_ipv6_header(rem) {
            Ok((rem2, ip6)) => {
                bump(
                    &mut target.ip_protocols,
                    ip_name(&ip6.next_header).to_string(),
                    size,
                );
                bump(&mut target.src_addr, ip6.source_addr.to_string(), size);
                bump(&mut target.dst_addr, ip6.dest_addr.to_string(), size);
                (ip6.next_header, rem2)
            }
            Err(e) => {
                if verbose {
                    eprintln!("IPv6 parse error: {e}");
                }
                return;
            }
        }
    } else {
        (IPProtocol::Other(255), &[][..])
    };

    // L4
    if proto == IPProtocol::TCP {
        match parse_tcp_header(rem) {
            Ok((_r, tcp)) => {
                bump(
                    &mut target.tcp_flags,
                    tcp_flag_name(&tcp).to_string(),
                    size,
                );
                bump(&mut target.src_ports, tcp.source_port, size);
                bump(&mut target.dst_ports, tcp.dest_port, size);
            }
            Err(e) => {
                if verbose {
                    eprintln!("TCP parse error: {e}");
                }
            }
        }
    } else if proto == IPProtocol::UDP {
        match parse_udp_header(rem) {
            Ok((_r, udp)) => {
                bump(&mut target.src_ports, udp.source_port, size);
                bump(&mut target.dst_ports, udp.dest_port, size);
            }
            Err(e) => {
                if verbose {
                    eprintln!("UDP parse error: {e}");
                }
            }
        }
    }
}

