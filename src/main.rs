extern crate clap;
extern crate failure;

extern crate pcap;
extern crate smoltcp;

use std::path::Path;

use clap::{App, Arg};
use failure::{err_msg, Error};

use pcap::Capture;

use smoltcp::wire::*;

fn parse_endpoint(endpoint: &str) -> Result<IpEndpoint, Error> {
    let mut iter = endpoint.rsplitn(2, ':');
    let port = iter.next().ok_or(err_msg("missing port"))?.parse::<u16>()?;
    let addr = iter.next()
        .ok_or(err_msg("missing address"))?
        .parse::<IpAddress>()
        .map_err(|_| err_msg("failed to parse ip address"))?;
    Ok(IpEndpoint::new(addr, port))
}

// no tcp reassembly yet
fn dump_file<P: AsRef<Path>>(path: P, endpoint: &str) -> Result<(), Error> {
    let endpoint = parse_endpoint(endpoint)?;
    let mut cap = Capture::from_file(path)?;
    while let Ok(packet) = cap.next() {
        let ether = EthernetFrame::new_checked(packet.data).map_err(err_msg)?;
        if EthernetProtocol::Ipv4 == ether.ethertype() {
            let ipv4 = Ipv4Packet::new_checked(ether.payload()).map_err(err_msg)?;
            if IpAddress::from(ipv4.dst_addr()) == endpoint.addr {
                let tcp = TcpPacket::new_checked(ipv4.payload()).map_err(err_msg)?;
                if tcp.dst_port() == endpoint.port {
                    println!("{}", String::from_utf8_lossy(tcp.payload()));
                }
            }
        }
    }
    Ok(())
}

fn main() {
    let matches = App::new("grpcdump")
        .version("0.1")
        .author("Sebastian Wicki <gandro@gmx.net>")
        .about("Traces and dumps gRPC calls")
        .arg(
            Arg::with_name("INPUT")
                .help("Sets the input pcap trace to use (experimental)")
                .required(true)
                .index(1),
        )
        .arg(
            Arg::with_name("endpoint")
                .short("e")
                .long("endpoint")
                .value_name("ENDPOINT")
                .help("Filter for TCP streams connected to the ENDPOINT")
                .takes_value(true)
                .required(true),
        )
        .get_matches();

    let input = matches.value_of("INPUT").unwrap();
    let endpoint = matches.value_of("endpoint").unwrap();

    if let Err(err) = dump_file(input, &endpoint) {
        eprintln!("error: failed to dump pcap file");
        for cause in err.causes() {
            eprintln!("caused by: {}", cause);
        }
        std::process::exit(1);
    }
}
