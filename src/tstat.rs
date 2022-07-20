
use std::collections::HashMap;

use std::fmt::Display;

use pcap::Device;
use pktparse::{
    ethernet::{parse_ethernet_frame, EtherType, EthernetFrame},
    ip::IPProtocol,
    ipv4::{parse_ipv4_header, IPv4Header},
    ipv6::{parse_ipv6_header, IPv6Header},
    tcp::{parse_tcp_header, TcpHeader},
    udp::{parse_udp_header, UdpHeader},
};

#[derive(Debug)]
pub struct Counter {
    pub count: u64,
    pub size: u64,
}

#[derive(Debug)]
pub struct ParseResult {
    pub total_count: u64,
    pub total_size: u64,
    pub eth_protocols: HashMap<String, Counter>,
    pub ip_protocols: HashMap<String, Counter>,
    pub ip4_ttl: HashMap<u8, Counter>,
    pub tcp_flags: HashMap<String, Counter>,
    pub src_ports: HashMap<u16, Counter>,
    pub dst_ports: HashMap<u16, Counter>,
}

pub fn find_device_by_name(find_name: Option<String>) -> Result<pcap::Device, String> {
    let name: String = find_name.unwrap_or(String::from("any"));

    let interfaces: Vec<Device> = Device::list().unwrap();

    for interface in interfaces {
        if interface.name == name {
            return Ok(interface);
        }
    }

    let error: String = format!("Interface {} not found!", &name[..]);
    Err(error)
}

fn get_eth_protocol(proto: &EtherType) -> String {
    match proto {
        EtherType::LANMIN => String::from("LANMIN"),
        EtherType::LANMAX => String::from("LANMAX"),
        EtherType::IPv4 => String::from("IPv4"),
        EtherType::ARP => String::from("ARP"),
        EtherType::WOL => String::from("WOL"),
        EtherType::TRILL => String::from("TRILL"),
        EtherType::DECnet => String::from("DECnet"),
        EtherType::RARP => String::from("RARP"),
        EtherType::AppleTalk => String::from("AppleTalk"),
        EtherType::AARP => String::from("AARP"),
        EtherType::VLAN => String::from("VLAN"),
        EtherType::IPX => String::from("IPX"),
        EtherType::Qnet => String::from("Qnet"),
        EtherType::IPv6 => String::from("IPv6"),
        EtherType::FlowControl => String::from("FlowControl"),
        EtherType::CobraNet => String::from("CobraNet"),
        EtherType::MPLSuni => String::from("MPLSuni"),
        EtherType::MPLSmulti => String::from("MPLSmulti"),
        EtherType::PPPoEdiscovery => String::from("PPPoEdiscovery"),
        EtherType::PPPoEsession => String::from("PPPoEsession"),
        EtherType::HomePlug => String::from("HomePlug"),
        EtherType::EAPOL => String::from("EAPOL"),
        EtherType::PROFINET => String::from("PROFINET"),
        EtherType::HyperSCSI => String::from("HyperSCSI"),
        EtherType::ATAOE => String::from("ATAOE"),
        EtherType::EtherCAT => String::from("EtherCAT"),
        EtherType::QinQ => String::from("QinQ"),
        EtherType::Powerlink => String::from("Powerlink"),
        EtherType::GOOSE => String::from("GOOSE"),
        EtherType::GSE => String::from("GSE"),
        EtherType::LLDP => String::from("LLDP"),
        EtherType::SERCOS => String::from("SERCOS"),
        EtherType::HomePlugAV => String::from("HomePlugAV"),
        EtherType::MRP => String::from("MRP"),
        EtherType::MACsec => String::from("MACsec"),
        EtherType::PBB => String::from("PBB"),
        EtherType::PTP => String::from("PTP"),
        EtherType::PRP => String::from("PRP"),
        EtherType::CFM => String::from("CFM"),
        EtherType::FCoE => String::from("FCoE"),
        EtherType::FCoEi => String::from("FCoEi"),
        EtherType::RoCE => String::from("RoCE"),
        EtherType::TTE => String::from("TTE"),
        EtherType::HSR => String::from("HSR"),
        EtherType::CTP => String::from("CTP"),
        EtherType::VLANdouble => String::from("VLANdouble"),
        _ => String::from("Over"),
    }
}

fn get_ip_protocol(protocol: &IPProtocol) -> String {
    match protocol {
        IPProtocol::HOPOPT => String::from("HOPOPT"),
        IPProtocol::ICMP => String::from("ICMP"),
        IPProtocol::IGMP => String::from("IGMP"),
        IPProtocol::GGP => String::from("GGP"),
        IPProtocol::IPINIP => String::from("IPINIP"),
        IPProtocol::ST => String::from("ST"),
        IPProtocol::TCP => String::from("TCP"),
        IPProtocol::CBT => String::from("CBT"),
        IPProtocol::EGP => String::from("EGP"),
        IPProtocol::IGP => String::from("IGP"),
        IPProtocol::BBNRCCMON => String::from("BBNRCCMON"),
        IPProtocol::NVPII => String::from("NVPII"),
        IPProtocol::PUP => String::from("PUP"),
        IPProtocol::ARGUS => String::from("ARGUS"),
        IPProtocol::EMCON => String::from("EMCON"),
        IPProtocol::XNET => String::from("XNET"),
        IPProtocol::CHAOS => String::from("CHAOS"),
        IPProtocol::UDP => String::from("UDP"),
        IPProtocol::IPV6 => String::from("IPV6"),
        IPProtocol::ICMP6 => String::from("ICMP6"),
        _ => String::from("Over"),
    }
}

fn get_tcp_flag(header: &TcpHeader) -> String {
    if header.flag_syn {
        return String::from("Syn");
    }
    if header.flag_ack {
        return String::from("Ack");
    }
    if header.flag_rst {
        return String::from("Rst");
    }
    if header.flag_fin {
        return String::from("Fin");
    }
    if header.flag_psh {
        return String::from("Psh");
    }
    if header.flag_urg {
        return String::from("Urg");
    }
    String::from("Unknown")
}

pub fn parse(capture: Vec<Vec<u8>>) -> ParseResult {
    let mut packets_count: u64 = 0;
    let mut packets_size: u64 = 0;
    let mut eth_protocols: HashMap<String, Counter> = HashMap::new();
    let mut ip_protocols: HashMap<String, Counter> = HashMap::new();
    let mut ip4_ttl: HashMap<u8, Counter> = HashMap::new();
    let mut tcp_flags: HashMap<String, Counter> = HashMap::new();
    let mut src_ports: HashMap<u16, Counter> = HashMap::new();
    let mut dst_ports: HashMap<u16, Counter> = HashMap::new();

    for data in capture {
        packets_count += 1;
        let size: u64 = data.len() as u64;
        packets_size += size;

        let (data, eth): (&[u8], EthernetFrame) = parse_ethernet_frame(&data[..]).unwrap();

        let eth_type: String = get_eth_protocol(&eth.ethertype);

        let eth_proto: &Counter = eth_protocols
            .get(&eth_type)
            .unwrap_or(&Counter { size: 0, count: 0 });
        eth_protocols.insert(
            eth_type,
            Counter {
                size: eth_proto.size + &size,
                count: eth_proto.count + 1,
            },
        );

        let (proto, data): (IPProtocol, &[u8]) = if eth.ethertype == EtherType::IPv4 {
            let (data, ip4): (&[u8], IPv4Header) = parse_ipv4_header(data).unwrap();

            let ip4_type: String = get_ip_protocol(&ip4.protocol);
            let ip4_proto: &Counter = ip_protocols
                .get(&ip4_type)
                .unwrap_or(&Counter { size: 0, count: 0 });
            ip_protocols.insert(
                ip4_type,
                Counter {
                    size: &ip4_proto.size + &size,
                    count: ip4_proto.count + 1,
                },
            );

            let ip4_ttl_value: &Counter = ip4_ttl
                .get(&ip4.ttl)
                .unwrap_or(&Counter { size: 0, count: 0 });
            ip4_ttl.insert(
                ip4.ttl,
                Counter {
                    size: ip4_ttl_value.size + &size,
                    count: ip4_ttl_value.count + 1,
                },
            );

            (ip4.protocol, data)
        } else if eth.ethertype == EtherType::IPv6 {
            let (_, ip6): (&[u8], IPv6Header) = parse_ipv6_header(data).unwrap();

            let ip6_type: String = get_ip_protocol(&ip6.next_header);
            let ip6_proto: &Counter = ip_protocols
                .get(&ip6_type)
                .unwrap_or(&Counter { size: 0, count: 0 });
            ip_protocols.insert(
                ip6_type,
                Counter {
                    size: ip6_proto.size + &size,
                    count: ip6_proto.count + 1,
                },
            );

            (ip6.next_header, data)
        } else {
            (IPProtocol::Other(255), &[])
        };

        if proto == IPProtocol::TCP {
            let (_, tcp): (&[u8], TcpHeader) = parse_tcp_header(data).unwrap();

            let flag: String = get_tcp_flag(&tcp);

            let tcp_flags_value: &Counter = tcp_flags
                .get(&flag)
                .unwrap_or(&Counter { size: 0, count: 0 });
            tcp_flags.insert(
                flag,
                Counter {
                    size: tcp_flags_value.size + &size,
                    count: tcp_flags_value.count + 1,
                },
            );

            let src_port_value: &Counter = src_ports
                .get(&tcp.source_port)
                .unwrap_or(&Counter { size: 0, count: 0 });
            src_ports.insert(
                tcp.source_port,
                Counter {
                    size: src_port_value.size + &size,
                    count: src_port_value.count + 1,
                },
            );

            let dst_port_value: &Counter = dst_ports
                .get(&tcp.dest_port)
                .unwrap_or(&Counter { size: 0, count: 0 });
            dst_ports.insert(
                tcp.dest_port,
                Counter {
                    size: dst_port_value.size + &size,
                    count: dst_port_value.count + 1,
                },
            );
        }

        if proto == IPProtocol::UDP {
            let (_, udp): (&[u8], UdpHeader) = parse_udp_header(data).unwrap();

            let src_port_value: &Counter = src_ports
                .get(&udp.source_port)
                .unwrap_or(&Counter { size: 0, count: 0 });
            src_ports.insert(
                udp.source_port,
                Counter {
                    size: src_port_value.size + &size,
                    count: src_port_value.count + 1,
                },
            );

            let dst_port_value: &Counter = dst_ports
                .get(&udp.dest_port)
                .unwrap_or(&Counter { size: 0, count: 0 });
            dst_ports.insert(
                udp.dest_port,
                Counter {
                    size: dst_port_value.size + &size,
                    count: dst_port_value.count + 1,
                },
            );
        }
    }

    ParseResult {
        total_count: packets_count,
        total_size: packets_size,
        eth_protocols: eth_protocols,
        ip_protocols: ip_protocols,
        ip4_ttl: ip4_ttl,
        tcp_flags: tcp_flags,
        src_ports: src_ports,
        dst_ports: dst_ports,
    }
}

fn print_table<T: Display>(map: &HashMap<T, Counter>, count: &f64, size: &f64, time: u64, sort: &bool, top: &u64) {
    let mut vec: Vec<(&T, &Counter)> = map.iter().collect();
    if *sort {
        vec.sort_unstable_by(|a, b| a.1.count.cmp(&b.1.count));
    } else {
        vec.sort_unstable_by(|a, b| a.1.size.cmp(&b.1.size));
    }

    for n in 0..*top {
        match vec.pop() {
            Some((k, v)) => { // (k, v): (&T, &Counter)
                println!(
                    "{0: <10} | {1: <10.2} | {2: <10.2} | {3: <10.2} | {4: <10.2}",
                    k,
                    v.count as f64 / time as f64,
                    8f64 * v.size as f64 / time as f64 / 1024f64 / 1024f64,
                    100f64 * v.count as f64 / count,
                    100f64 * v.size as f64 / size
                );
            },
            _ => (),
        };
    }
}

pub fn print_human(result: ParseResult, time: &u64, sort: &bool, top: &u64) {
    println!("TOTAL COUNT: {}", result.total_count);
    println!("TOTAL SIZE: {}", result.total_size);
    println!("TOTAL PPS: {:.2}", result.total_count as f64 / *time as f64);
    println!("TOTAL MbPS: {:.2}", 8f64 * result.total_size as f64 / *time as f64 / 1024f64 / 1024f64);

    println!(
        "\n{0: <10} | {1: <10} | {2: <10} | {3: <10} | {4: <10}",
        "L3PROTO", "PPS", "MbPS", "COUNT%", "SIZE%"
    );
    print_table(
        &result.eth_protocols,
        &(result.total_count as f64),
        &(result.total_size as f64),
        *time,
        sort,
        top,
    );

    println!(
        "\n{0: <10} | {1: <10} | {2: <10} | {3: <10} | {4: <10}",
        "L4PROTO", "PPS", "MbPS", "COUNT%", "SIZE%"
    );
    print_table(
        &result.ip_protocols,
        &(result.total_count as f64),
        &(result.total_size as f64),
        *time,
        sort,
        top,
    );

    println!(
        "\n{0: <10} | {1: <10} | {2: <10} | {3: <10} | {4: <10}",
        "TTL IPv4", "PPS", "MbPS", "COUNT%", "SIZE%"
    );
    print_table(
        &result.ip4_ttl,
        &(result.total_count as f64),
        &(result.total_size as f64),
        *time,
        sort,
        top,
    );

    println!(
        "\n{0: <10} | {1: <10} | {2: <10} | {3: <10} | {4: <10}",
        "TCP FLAGS", "PPS", "MbPS", "COUNT%", "SIZE%"
    );
    print_table(
        &result.tcp_flags,
        &(result.total_count as f64),
        &(result.total_size as f64),
        *time,
        sort,
        top,
    );

    println!(
        "\n{0: <10} | {1: <10} | {2: <10} | {3: <10} | {4: <10}",
        "SRC PORT", "PPS", "MbPS", "COUNT%", "SIZE%"
    );
    print_table(
        &result.src_ports,
        &(result.total_count as f64),
        &(result.total_size as f64),
        *time,
        sort,
        top,
    );

    println!(
        "\n{0: <10} | {1: <10} | {2: <10} | {3: <10} | {4: <10}",
        "DST PORT", "PPS", "MbPS", "COUNT%", "SIZE%"
    );
    print_table(
        &result.dst_ports,
        &(result.total_count as f64),
        &(result.total_size as f64),
        *time,
        sort,
        top,
    );
}
