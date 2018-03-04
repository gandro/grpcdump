extern crate clap;
extern crate failure;
extern crate h2;
extern crate tokio_io;
extern crate futures;

extern crate env_logger;

extern crate pcap;
extern crate smoltcp;

mod reassembly;

use std::path::Path;

use clap::{App, Arg};
use failure::{err_msg, Error};
use futures::prelude::*;
use tokio_io::io::read_exact;
use h2::Codec;

use pcap::Capture;

use smoltcp::wire::*;

use self::reassembly::TcpStream;

const PREFACE: [u8; 24] = *b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

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

    let mut server = TcpStream::new();
    let mut client = TcpStream::new();

    while let Ok(packet) = cap.next() {
        let ether = EthernetFrame::new_checked(packet.data).map_err(err_msg)?;
        if EthernetProtocol::Ipv4 == ether.ethertype() {
            let ipv4 = Ipv4Packet::new_checked(ether.payload()).map_err(err_msg)?;

            if IpAddress::from(ipv4.dst_addr()) == endpoint.addr {
                let tcp = TcpPacket::new_checked(ipv4.payload()).map_err(err_msg)?;
                if tcp.dst_port() == endpoint.port {
                    client.push(tcp.payload());
                }
            }

            if IpAddress::from(ipv4.src_addr()) == endpoint.addr {
                let tcp = TcpPacket::new_checked(ipv4.payload()).map_err(err_msg)?;
                if tcp.src_port() == endpoint.port {
                    server.push(tcp.payload());
                }
            }
        }
    }

    let buf = [0u8; 24];
    let (client, preface) = read_exact(client, buf).wait()?;
    assert_eq!(preface, PREFACE);

    Codec::from(client)
        .for_each(|frame| {
            println!("Frame: {:?}", frame);
            Ok(())
        })
        .map(|()| println!("Client closed."))
        .wait()?;

    Codec::from(server)
        .for_each(|frame| {
            println!("Frame: {:?}", frame);
            Ok(())
        })
        .map(|()| println!("Server closed."))
        .wait()?;

    Ok(())
}

fn main() {
    env_logger::init();

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

        for line in err.backtrace().to_string().lines() {
            eprintln!("{}", line);
        }

        std::process::exit(1);
    }
}
