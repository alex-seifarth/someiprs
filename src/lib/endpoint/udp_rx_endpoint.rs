// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright 2023 Alexander Seifarth
//
// This file is part of `someip-rsmw`.
// `someip-rsmw` is free software: you can redistribute it and/or modify it under the terms
// of the GNU General Public License as published by the Free Software Foundation, either
// version 3 of the License, or (at your option) any later version.
//
// `someip-rsmw` is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
// See the GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along with Foobar.
// If not, see <https://www.gnu.org/licenses/>.
use std::net::SocketAddr;
use std::collections::HashMap;
use bytes::{BytesMut, Bytes};
use crate::endpoint::someip;
use crate::endpoint::types;

pub type TxReceiver = tokio::sync::mpsc::Receiver<(SocketAddr, Bytes)>;
pub type TxSender = tokio::sync::mpsc::Sender<(SocketAddr, Bytes)>;

struct ServiceContext {
    pub service_id: someip::ServiceId,
    pub chnnl: types::MessageSender,
    pub m_segm_size: usize,             // maximum frame size with segmentation (0 = segmentation off)
}

unsafe impl Send for ServiceContext {}
unsafe impl Sync for ServiceContext {}

/// A UDP Receiver Endpoint for SOME/IP messages.
pub struct UdpRxEndpoint {
    mtu_size: usize,
    services: HashMap<someip::ServiceId, ServiceContext>,
    tx_chnnl: TxSender,
}

unsafe impl Send for UdpRxEndpoint {}
unsafe impl Sync for UdpRxEndpoint {}

impl UdpRxEndpoint {
    /// Creates a new [UdpRxEndpoint] with the given MTU size `mtu_size`
    pub fn new(mtu_size: usize, tx_chnnl: TxSender) -> Self {
        UdpRxEndpoint {mtu_size,
            services: HashMap::new(),
            tx_chnnl,
        }
    }

    /// Returns the configured MTU size, which determines the maximum packet size for SOME/IP
    pub fn mtu(&self) -> usize {
        self.mtu_size
    }

    /// Returns the maximum payload size for non-fragmented and fragmented SOME/IP messages.
    pub fn max_payload_size(&self, fragmented: bool) -> usize {
        self.mtu_size - someip::SOMEIP_HEADER_SIZE
            - if fragmented {someip::SOMEIP_TP_HEADER_SIZE} else {0}
    }

    /// Creates a buffer with the MTU size [UdpRxEndpoint::mtu()] wrapped in
    /// [BytesMut] filled with 0.
    /// To use it with UdpSocket, use `as_mut()`
    pub fn create_buffer(&self) -> BytesMut {
        let mut b = BytesMut::with_capacity(self.mtu());
        b.resize(self.mtu(), 0);
        b
    }

    /// Resets the buffer for new data.
    pub fn reset_buffer(&self, buf: &mut BytesMut) {
        buf.clear();
        buf.resize(self.mtu(), 0);
    }

    /// Adds a service to the endpoint.
    /// The method returns an error does nothing when the service is already set up.
    pub fn add_service(&mut self, svc_id: someip::ServiceId,
                       chnnl: types::MessageSender,
                       m_segm_size: usize)
                       -> Result<(), ()>
    {
        if self.services.contains_key(&svc_id) {
            return Err(())
        }
        let sc = ServiceContext { service_id: svc_id.clone(), chnnl, m_segm_size };
        self.services.insert(svc_id, sc);
        Ok(())
    }

    /// Removes a service from the configuration of this endpoint. Does nothing if the service
    /// is not configured.
    pub fn rem_service(&mut self, svc_id: &someip::ServiceId) {
        self.services.remove(svc_id);
    }

    pub async fn process_cmd(&mut self, cmd: types::Command) {
        match cmd {
            types::Command::Received{ transport: _, local, peer, msg} => {
                let svcid = &msg.header.message_id.service();
                if let Some(entry) = self.services.get(svcid) {

                } else {

                }
            },
            types::Command::Transmit{ peer, msg} => {
                // fragmentation
                //self.tx_chnnl.send((peer, msg)).await.expect()
            },
            types::Command::AddService(svcid, chnnl, max_seg_size) => {
                let _ = self.add_service(svcid, chnnl, max_seg_size);
            },
            types::Command::RemService(svcid) => {
                self.rem_service(&svcid);
            },
        }
    }

    pub async fn process_data(&mut self, raddr: &SocketAddr, buf: &mut BytesMut) {
        let cmds = self.decode_udp_frame(raddr, buf);
        for cmd in cmds {
            self.process_cmd(cmd).await;
        }
    }

    fn decode_udp_frame(&mut self, raddr: &SocketAddr, buf: &mut BytesMut) -> Vec<types::Command> {
        vec![]
    }
}
