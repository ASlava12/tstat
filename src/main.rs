use clap::Parser;
use mac_address::MacAddressIterator;
use pcap::{Active, Capture, Device, Inactive, Packet};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

mod tstat;
use tstat::{find_device_by_name, parse, print_human, ParseResult};

/// A simple program for capturing and analyzing network card packets
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Network interface
    #[clap(short, long, value_parser, default_value = "default")]
    interface: String,

    /// See http://biot.com/capstats/bpf.html for more information about this syntax.
    #[clap(short, long, value_parser, default_value = "")]
    filter: String,

    /// Capture time in seconds
    #[clap(short, long, value_parser, default_value_t = 1)]
    wait: u64,

    /// Sort by count (default by size)
    #[clap(short, long, value_parser, default_value_t = false)]
    sort: bool,

    /// Show top Records in table
    #[clap(short, long, value_parser, default_value_t = 10)]
    top: u64,

    /// Analize packets from direction (all, in, out, undef)
    #[clap(short, long, value_parser, default_value = "all")]
    direction: String,
}

fn get_timestamp() -> Duration {
    let start: SystemTime = SystemTime::now();
    let now: Duration = start.duration_since(UNIX_EPOCH).unwrap();

    now
}

fn main() {
    let args: Args = Args::parse();

    let mac_iter: MacAddressIterator = MacAddressIterator::new().unwrap();
    let mut mac_list: Vec<[u8; 6]> = Vec::new();

    for mac in mac_iter {
        let res: [u8; 6] = mac.bytes();
        mac_list.push(res);
    }

    let dev: Device = if args.interface == "default" {
        Device::lookup().unwrap()
    } else {
        find_device_by_name(Some(String::from(args.interface))).unwrap()
    };

    let cap: Capture<Inactive> = Capture::from_device(dev).unwrap();

    let mut cap: Capture<Active> = cap.timeout(1).promisc(true).open().unwrap();

    if args.filter != "" {
        cap.filter(&args.filter[..], false).unwrap();
    }

    let wait_until: Duration = get_timestamp() + Duration::from_secs(args.wait);
    let mut capture: Vec<Vec<u8>> = Vec::new();

    while wait_until > get_timestamp() {
        let packet: Packet = cap.next().unwrap();
        capture.push(packet.data.to_owned());
    }

    let (input, output, undefined): (ParseResult, ParseResult, ParseResult) =
        parse(capture, mac_list);

    match &args.direction[..] {
        "in" => {
            print_human(input, &args.wait, &args.sort, &args.top);
        }
        "out" => {
            print_human(output, &args.wait, &args.sort, &args.top);
        }
        "undef" => {
            print_human(undefined, &args.wait, &args.sort, &args.top);
        }
        _ => {
            println!("\n\n\nINPUT:");
            print_human(input, &args.wait, &args.sort, &args.top);
            println!("\n\n\nOUTPUT:");
            print_human(output, &args.wait, &args.sort, &args.top);
            println!("\n\n\nUNDEFINED:");
            print_human(undefined, &args.wait, &args.sort, &args.top);
        }
    }
}
