use crate::ipc;
use crate::ipc::KernelMessageType;
use packet::ip::v4;
use packet::ip::Protocol;
use packet::{Builder, Packet};
use std::net::Ipv4Addr;

pub fn register_ipv4_address(addr: Ipv4Addr) -> Result<(), String> {
    ipc::trivial_kernel_request(KernelMessageType::IP_ADDRESS_REGISTER_V4, &addr.octets())
        .map(|_| ())
}

pub fn register_ipv6_address(addr: Ipv4Addr) -> Result<(), String> {
    ipc::trivial_kernel_request(KernelMessageType::IP_ADDRESS_REGISTER_V6, &addr.octets())
        .map(|_| ())
}

pub fn ip_input(packet: &mut [u8]) {
    if packet.len() == 0 || packet.len() > 1500 {
        return;
    }

    match packet[0] >> 4 {
        4 => ipv4_input(packet),
        6 => ipv6_input(packet),
        _ => {}
    }
}

fn ipv4_input(raw_packet: &mut [u8]) {
    let packet = if let Ok(x) = v4::Packet::new(raw_packet) {
        x
    } else {
        return;
    };

    match packet.protocol() {
        Protocol::Icmp => {
            let payload = packet.payload();
            let icmp = match packet::icmp::Packet::new(payload) {
                Ok(x) => x,
                Err(_) => return,
            };
            if let Ok(x) = icmp.echo() {
                if x.is_request() {
                    let response = v4::Builder::default()
                        .source(packet.destination())
                        .unwrap()
                        .destination(packet.source())
                        .unwrap()
                        .icmp()
                        .unwrap()
                        .echo()
                        .unwrap()
                        .reply()
                        .unwrap()
                        .identifier(x.identifier())
                        .unwrap()
                        .sequence(x.sequence())
                        .unwrap()
                        .payload(x.payload())
                        .unwrap()
                        .build()
                        .unwrap();
                    ipc::send_message(
                        0,
                        0,
                        KernelMessageType::IP_PACKET as u32,
                        response.as_slice(),
                    );
                }
            }
        }
        _ => {}
    }
}

fn ipv6_input(_raw_packet: &mut [u8]) {}
