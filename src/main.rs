use std::env;
use std::error;
use std::net;
use std::str::FromStr;

use pnet::packet::icmp::echo_request::MutableEchoRequestPacket;
use pnet::packet::icmp::IcmpTypes;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::MutablePacket;
use pnet::transport::{icmp_packet_iter, transport_channel, TransportChannelType::Layer3};
use pnet::util;

type Result<T> = std::result::Result<T, Box<dyn error::Error>>;

static IPV4_HEADER_LEN: usize = 21;
static ICMP_HEADER_LEN: usize = 8;
static ICMP_PAYLOAD_LEN: usize = 32;

fn main() {
    std::process::exit(match run_app() {
        Ok(_) => 0,
        Err(error) => {
            eprintln!("Error: {}", error);
            1
        }
    });
}

fn run_app() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    match args.len() {
        2 => {
            let protocol = Layer3(IpNextHeaderProtocols::Icmp);
            let (mut tx, mut rx) = transport_channel(1024, protocol)
                .map_err(|err| format!("Error opening the channel: {}", err))?;

            let ip_addr = net::Ipv4Addr::from_str(&args[1]).map_err(|_| "Invalid address")?;
            let mut rx = icmp_packet_iter(&mut rx);
            let mut ttl = 4;
            let mut prev_addr = None;
            loop {
                let mut buffer_ip = [0u8; 40];
                let mut buffer_icmp = [0u8; 40];
                let icmp_packet =
                    create_icmp_packet(&mut buffer_ip, &mut buffer_icmp, ip_addr, ttl)?;
                tx.send_to(icmp_packet, net::IpAddr::V4(ip_addr))?;
                if let Ok((_, addr)) = rx.next() {
                    if Some(addr) == prev_addr {
                        return Ok(());
                    }
                    prev_addr = Some(addr);
                    // This is not quite ideal as replies may arrive in different order
                    // than they were sent in
                    println!("TTL: {} - {:?}", ttl, addr);
                }
                ttl += 1;
            }
        }
        _ => Err((format!("Usage: {} ip", args[0])).into()),
    }
}

fn create_icmp_packet<'a>(
    buffer_ip: &'a mut [u8],
    buffer_icmp: &'a mut [u8],
    dest: net::Ipv4Addr,
    ttl: u8,
) -> Result<MutableIpv4Packet<'a>> {
    let mut ipv4_packet = MutableIpv4Packet::new(buffer_ip).unwrap();
    ipv4_packet.set_version(4);
    ipv4_packet.set_header_length(IPV4_HEADER_LEN as u8);
    ipv4_packet.set_total_length((IPV4_HEADER_LEN + ICMP_HEADER_LEN + ICMP_PAYLOAD_LEN) as u16);
    ipv4_packet.set_ttl(ttl);
    ipv4_packet.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
    ipv4_packet.set_destination(dest);

    let mut icmp_packet = MutableEchoRequestPacket::new(buffer_icmp).unwrap();
    icmp_packet.set_icmp_type(IcmpTypes::EchoRequest);
    let checksum = util::checksum(icmp_packet.packet_mut(), 2);
    icmp_packet.set_checksum(checksum);
    ipv4_packet.set_payload(icmp_packet.packet_mut());
    Ok(ipv4_packet)
}
