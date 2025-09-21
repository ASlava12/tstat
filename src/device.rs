use anyhow::Context;
use pcap::{Active, Capture, Device};

use crate::args::Args;

/// Открыть `pcap` без перечисления всех интерфейсов:
/// - "default" → системный по умолчанию (через Device::lookup())
/// - иначе → напрямую по имени: Capture::from_device("eth0")
pub fn open_capture(args: &Args) -> anyhow::Result<Capture<Active>> {
    let inactive = if args.interface == "default" {
        let dev = Device::lookup()
            .context("device lookup failed")?
            .context("no default device available")?;
        Capture::from_device(dev)?
    } else {
        Capture::from_device(args.interface.as_str())?
    };

    // Небольшие твики для latency
    let cap = inactive
        .timeout(100)           // 100 мс
        .promisc(true)          // promiscuous
        .immediate_mode(true)   // не буферизовать
        .open()?;               // активировать

    Ok(cap)
}

