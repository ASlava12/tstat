use clap::Parser;
use pcap::{Active, Capture, Device, Inactive, Packet};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

mod tstat;
use tstat::{find_device_by_name, parse, print_human};

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

fn get_timestamp() -> Duration {
    let start: SystemTime = SystemTime::now();
    let now: Duration = start.duration_since(UNIX_EPOCH).unwrap();

    now
}

fn main() {
    let args: Args = Args::parse();

    let dev: Device = find_device_by_name(Some(String::from(args.interface))).unwrap();
    let cap: Capture<Inactive> = Capture::from_device(dev).unwrap();

    let mut cap: Capture<Active> = cap.timeout(1000).promisc(true).open().unwrap();

    if args.filter != "" {
        cap.filter(&args.filter[..], false).unwrap();
    }

    let wait_until: Duration = get_timestamp() + Duration::from_secs(args.wait);
    let mut capture: Vec<Vec<u8>> = Vec::new();

    while wait_until > get_timestamp() {
        let packet: Packet = cap.next().unwrap();

        capture.push(packet.data.to_owned());
    }

    print_human(parse(capture));
}
