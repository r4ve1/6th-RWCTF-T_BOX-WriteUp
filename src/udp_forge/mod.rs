use pnet::{
    packet::{
        ip::IpNextHeaderProtocols,
        ipv4::{Ipv4Flags, MutableIpv4Packet},
        udp::MutableUdpPacket,
        Packet,
    },
    transport::{transport_channel, TransportChannelType},
};
use std::net::{IpAddr, SocketAddrV4};
use tracing::{debug, info};

pub struct UdpForger {
    src: SocketAddrV4,
    dst: SocketAddrV4,
}

impl UdpForger {
    pub fn new(src: SocketAddrV4, dst: SocketAddrV4) -> Self {
        Self { src, dst }
    }

    pub fn send(&self, payload: impl AsRef<[u8]>) {
        let source_ip = self.src.ip();
        let source_port = self.src.port();
        let destination_ip = self.dst.ip();
        let destination_port = self.dst.port();

        let payload = payload.as_ref();

        const UDP_HEADER_LEN: usize = 8;
        let mut udp_packet =
            MutableUdpPacket::owned(vec![0u8; UDP_HEADER_LEN + payload.len()]).unwrap();
        udp_packet.set_source(source_port);
        udp_packet.set_destination(destination_port);
        udp_packet.set_length((UDP_HEADER_LEN + payload.len()) as u16);
        udp_packet.set_payload(payload);
        let udp_packet = udp_packet.packet();

        debug!(length = udp_packet.len(), "UDP packet");

        let mut offset = 0;

        const MTU: usize = 500;
        const IPV4_HEADER_LEN: usize = 20;
        const MAX_PAYLOAD_LEN: usize = MTU - IPV4_HEADER_LEN;

        while offset < udp_packet.len() {
            let (this_payload_length, more_fragments) =
                if udp_packet.len() - offset > MAX_PAYLOAD_LEN {
                    (MAX_PAYLOAD_LEN, true)
                } else {
                    (udp_packet.len() - offset, false)
                };
            debug!(this_payload_length, "Sending packet");
            let this_packet_length = IPV4_HEADER_LEN + this_payload_length;
            let mut ipv4_packet = MutableIpv4Packet::owned(vec![0u8; this_packet_length]).unwrap();
            ipv4_packet.set_version(4);
            ipv4_packet.set_header_length(IPV4_HEADER_LEN as u8 / 4);
            ipv4_packet.set_identification(54321);
            ipv4_packet.set_total_length((this_packet_length + IPV4_HEADER_LEN) as u16);
            ipv4_packet.set_next_level_protocol(IpNextHeaderProtocols::Udp);
            ipv4_packet.set_source(source_ip.to_owned());
            ipv4_packet.set_destination(destination_ip.to_owned());
            ipv4_packet.set_fragment_offset((offset >> 3) as u16);
            ipv4_packet.set_ttl(64);
            if more_fragments {
                debug!("Fragmenting packet");
                ipv4_packet.set_flags(Ipv4Flags::MoreFragments);
            } else {
                debug!("Sending last packet");
                ipv4_packet.set_flags(Ipv4Flags::DontFragment);
            }
            ipv4_packet.set_payload(&udp_packet[offset..offset + this_payload_length]);
            offset += this_payload_length;

            info!(ipv4_len = ipv4_packet.packet().len(), "Sending packet");

            let (mut tx, _) = transport_channel(
                0x10000,
                TransportChannelType::Layer3(IpNextHeaderProtocols::Ipv4),
            )
            .expect("Failed to create transport channel");

            let ret = tx
                .send_to(ipv4_packet, IpAddr::V4(destination_ip.to_owned()))
                .unwrap();

            info!(length = ret, "Packet sent");
        }
    }
}
