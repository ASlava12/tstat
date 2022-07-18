use pcap::{Device, Capture, Inactive, Active, Packet};
use std::time::{SystemTime, UNIX_EPOCH, Duration};
use std::collections::HashMap;
use pktparse;
use clap::Parser;

use pktparse::{
    ethernet::{EthernetFrame, parse_ethernet_frame, EtherType},
    ip::IPProtocol,
    ipv4::{IPv4Header, parse_ipv4_header},
    ipv6::{IPv6Header, parse_ipv6_header},
    udp::{UdpHeader, parse_udp_header},
    tcp::{TcpHeader, parse_tcp_header},
};


/// A simple program for capturing and analyzing network card packets
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Network interface
    #[clap(short, long, value_parser, default_value = "any")]
    interface: String,

    /// filter
    #[clap(short, long, value_parser, default_value = "")]
    filter: String,

    /// Capture time in seconds
    #[clap(short, long, value_parser, default_value_t = 1)]
    wait: u64,
}


#[derive(Debug)]
struct Counter {
    count: u64,
    size: u64,
}


fn find_device_by_name(find_name: Option<String>) -> Result<pcap::Device, String> {
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


fn get_timestamp() -> Duration {
    let start: SystemTime = SystemTime::now();
    let now: Duration = start.duration_since(UNIX_EPOCH)
                             .unwrap();
    
    now
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
        _ => String::from("Over")
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
        _ => String::from("Over")
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


fn main() {
    let args = Args::parse();

    let dev: Device = find_device_by_name(Some(String::from(args.interface))).unwrap();
    let cap: Capture<Inactive> = Capture::from_device(dev).unwrap();

    let mut cap: Capture<Active> = cap.timeout(1000)
                     .promisc(true)
                     .open()
                     .unwrap();

    if args.filter != "" {
        cap.filter(&args.filter[..], false).unwrap();
    }

    let mut packets_count: u64 = 0;
    let mut eth_protocols: HashMap<String, Counter> = HashMap::new();
    let mut ip_protocols: HashMap<String, Counter> = HashMap::new();
    let mut ip4_ttl: HashMap<u8, u64> = HashMap::new();
    let mut tcp_flags: HashMap<String, u64> = HashMap::new();
    let mut src_ports: HashMap<u16, u64> = HashMap::new();
    let mut dst_ports: HashMap<u16, u64> = HashMap::new();

    let wait_until: Duration = get_timestamp() + Duration::from_secs(args.wait);

    while wait_until > get_timestamp() {
        let packet: Packet = cap.next().unwrap();
        let (data, eth): (&[u8], EthernetFrame) = parse_ethernet_frame(packet.data).unwrap();

        packets_count += 1;
        let size: u64 = data.len() as u64;
        let eth_type: String = get_eth_protocol(&eth.ethertype);

        let eth_proto: &Counter = eth_protocols.get(&eth_type).unwrap_or(&Counter{size: 0, count: 0});
        eth_protocols.insert(eth_type, Counter{size: eth_proto.size + &size, count: eth_proto.count + 1});

        let (proto, data): (IPProtocol, &[u8]) = if eth.ethertype == EtherType::IPv4 {
            let (data, ip4): (&[u8], IPv4Header) = parse_ipv4_header(data).unwrap();

            let ip4_type: String = get_ip_protocol(&ip4.protocol);
            let ip4_proto: &Counter = ip_protocols.get(&ip4_type).unwrap_or(&Counter{size: 0, count: 0});
            ip_protocols.insert(ip4_type, Counter{size: ip4_proto.size + &size, count: ip4_proto.count + 1});

            let ip4_ttl_value: &u64 = ip4_ttl.get(&ip4.ttl).unwrap_or(&0);
            ip4_ttl.insert(ip4.ttl, ip4_ttl_value + 1);

            (ip4.protocol, data)

        } else if eth.ethertype == EtherType::IPv6 {
            let (_, ip6): (&[u8], IPv6Header) = parse_ipv6_header(data).unwrap();

            let ip6_type: String = get_ip_protocol(&ip6.next_header);
            let ip6_proto: &Counter = ip_protocols.get(&ip6_type).unwrap_or(&Counter{size: 0, count: 0});
            ip_protocols.insert(ip6_type, Counter{size: ip6_proto.size + &size, count: ip6_proto.count + 1});

            (ip6.next_header, data)
        } else {
            (IPProtocol::Other(255), &[])
        };

        if proto == IPProtocol::TCP {
            let (data, tcp): (&[u8], TcpHeader) = parse_tcp_header(data).unwrap();

            let flag: String = get_tcp_flag(&tcp);
            
            let tcp_flags_value: &u64 = tcp_flags.get(&flag).unwrap_or(&0);
            tcp_flags.insert(flag, tcp_flags_value + 1);

            let src_port_value: &u64 = src_ports.get(&tcp.source_port).unwrap_or(&0);
            src_ports.insert(tcp.source_port, src_port_value + 1);

            let dst_port_value: &u64 = dst_ports.get(&tcp.dest_port).unwrap_or(&0);
            dst_ports.insert(tcp.dest_port, dst_port_value + 1);
        }

        if proto == IPProtocol::UDP {
            let (data, udp): (&[u8], UdpHeader) = parse_udp_header(data).unwrap();

            let src_port_value: &u64 = src_ports.get(&udp.source_port).unwrap_or(&0);
            src_ports.insert(udp.source_port, src_port_value + 1);

            let dst_port_value: &u64 = dst_ports.get(&udp.dest_port).unwrap_or(&0);
            dst_ports.insert(udp.dest_port, dst_port_value + 1);
            
        }
    }

    println!("Total packets: {:?}", packets_count);
    println!("L3: {:?}", eth_protocols);
    println!("L4: {:?}", ip_protocols);
    println!("IPv4 TTL: {:?}", ip4_ttl);
    println!("TPC FLAGS: {:?}", tcp_flags);
    println!("SRC Port: {:?}", src_ports);
    println!("DST Port: {:?}", dst_ports);

}