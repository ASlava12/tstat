mod args;
mod device;
mod mac;
mod parser;
mod stats;
mod view;

use anyhow::Context;
use clap::Parser;
use pcap::{Active, Capture};
use std::time::{Duration, Instant};

use crate::args::Args;
use crate::mac::read_local_macs;
use crate::parser::parse_packet;
use crate::stats::ParseResult;
use crate::view::{print_human, print_json};

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // Открываем интерфейс
    let mut cap: Capture<Active> = device::open_capture(&args)
        .with_context(|| "failed to open pcap capture (try sudo?)")?;

    // BPF-фильтр (если задан)
    if !args.filter.is_empty() {
        cap.filter(&args.filter, true).context("failed to set BPF filter")?;
    }

    // MAC для выбранного интерфейса (оставляем Option)
    let macs = read_local_macs(Some(args.interface.as_str()));

    // Счётчики
    let mut input = ParseResult::default();
    let mut output = ParseResult::default();
    let mut undefined = ParseResult::default();

    let wait = Duration::from_secs(args.wait);
    let stop_at = Instant::now() + wait;

    while Instant::now() < stop_at {
        match cap.next_packet() {
            Ok(pkt) => {
                parse_packet(
                    pkt.data,
                    &macs,
                    args.verbose,
                    &mut input,
                    &mut output,
                    &mut undefined,
                );
            }
            Err(pcap::Error::NoMorePackets) | Err(pcap::Error::TimeoutExpired) => { /* continue */ }
            Err(e) => {
                if args.verbose {
                    eprintln!("pcap error: {e}");
                }
            }
        }
    }

    if args.json {
        print_json(&input, &output, &undefined);
    } else {
        match args.direction.as_str() {
            "in" => print_human("INPUT", &input, args.wait, args.sort, args.top),
            "out" => print_human("OUTPUT", &output, args.wait, args.sort, args.top),
            "undef" | "undefined" => {
                print_human("UNDEFINED", &undefined, args.wait, args.sort, args.top)
            }
            _ => {
                print_human("INPUT", &input, args.wait, args.sort, args.top);
                print_human("OUTPUT", &output, args.wait, args.sort, args.top);
                print_human("UNDEFINED", &undefined, args.wait, args.sort, args.top);
            }
        }
    }

    Ok(())
}

