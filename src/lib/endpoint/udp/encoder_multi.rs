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

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use bytes::BytesMut;
use crate::endpoint::someip;
use crate::endpoint::udp::encoder;
use crate::endpoint::udp::encoder::{Encoder, MIN_RETENTION_TIME};

struct PeerContext {
    encoder: Encoder,
    last_used: Instant,
}

/// Message encoder for multiple peers.
pub struct EncoderMulti {
    /// Time to live for an inactive peer.
    max_inactivity_time: Duration,
    /// Maximum datagram size of this endpoint.
    max_datagram_size: usize,
    /// Encoders per peer.
    peers: HashMap<SocketAddr, PeerContext>,
    /// buffer for completed datagrams
    completed: Vec<(SocketAddr /*peer*/, BytesMut)>,
    /// Next scheduled transmission due to held back messages (retention)
    next_schedule: Option<Instant>,
}

impl EncoderMulti {

    pub fn new_default() -> Self {
        EncoderMulti::new(encoder::DEFAULT_MAX_DATAGRAM_SIZE, Duration::from_secs(100))
    }

    /// Creates a new [EncoderMulti] object.
    pub fn new(max_datagram_size: usize, max_inactivity_time: Duration) -> Self {
        EncoderMulti{
            max_inactivity_time,
            max_datagram_size,
            peers: HashMap::new(),
            completed: Vec::new(),
            next_schedule: None,
        }
    }

    /// Returns the time when the [Encoder] should be run with or without
    /// new messages to transmit to send held back messages.
    pub fn next_schedule(&self) -> Option<Instant> {
        self.next_schedule
    }

    /// Returns the maximum datagram size for this [Encoder]
    pub fn max_datagram_size(&self) -> usize {
        self.max_datagram_size
    }

    /// Cleanup for peers that have not been sent any message to for too long.
    /// This should be called periodically.
    pub fn cleanup(&mut self) {
        let now = Instant::now();
        self.peers.retain(|_, ctxt| {
            assert!(now >= ctxt.last_used);
            now - ctxt.last_used <= self.max_inactivity_time
        } );
    }

    /// Finishes the pending messages, returns `true` when there are completed datagrams.
    pub fn schedule(&mut self) -> bool {
        let now = Instant::now();
        for ec in self.peers.iter_mut() {
            if let Some(ns) = ec.1.encoder.next_schedule().as_ref() {
                let nsd = ns.clone();
                if nsd <= now || nsd - now < MIN_RETENTION_TIME {
                    if ec.1.encoder.schedule() {
                        let c = ec.1.encoder.get_completed();
                        self.completed.extend( c.into_iter().map(|x| (ec.0.clone(), x)) );
                        continue;
                    }
                }
            }
        }
        self.update_next_schedule();
        !self.is_completed_empty()
    }

    /// Processes the a new message `msg` for transmission.
    /// #Args
    /// - `msg`                 The new message. If too big for one datagram it will be segmented.
    /// - `retention_time`      The maximum time the new message can be held back to fill the datagram.
    /// #Returns
    /// The message returns `true` when completed datagrams are availale (see `get_completed()`),
    /// otherwise `false` is returned.
    pub fn prepare_msg(&mut self, peer: &SocketAddr, msg: someip::Message, retention_time: Duration) -> bool {
        let ctxt = if let Some(ctxt) = self.peers.get_mut(&peer) {
            ctxt
        } else {
            self.peers.insert(peer.clone(),
                              PeerContext{last_used: Instant::now(), encoder: Encoder::new(self.max_datagram_size)});
            self.peers.get_mut(&peer).unwrap()
        };

        if ctxt.encoder.prepare_msg(msg, retention_time) {
            self.completed.extend( ctxt.encoder.get_completed().into_iter().map(|x| (peer.clone(), x)) );
        }
        self.update_next_schedule();
        !self.is_completed_empty()
    }

    fn update_next_schedule(&mut self) {
        let mut has_next = false;
        let mut next = Instant::now();

        for (_, ctxt) in &self.peers {
            if let Some(ns) = ctxt.encoder.next_schedule() {
                if !has_next || next > ns {
                    has_next = true;
                    next = ns;
                }
            }
        }
        self.next_schedule = if has_next { Some(next) } else { None }
    }

    /// Returns `true` when there are no completed datagrams.
    pub fn is_completed_empty(&self) -> bool {
        self.completed.is_empty()
    }

    /// Returns the currently completed datagrams.
    pub fn get_completed(&mut self) -> Vec<(SocketAddr, BytesMut)> {
        std::mem::take( &mut self.completed )
    }
}

#[cfg(test)]
mod tests {
    use std::thread::sleep;
    use super::*;

    fn make_msg(len: usize, value: u8) -> someip::Message {
        let hdr = someip::Header{
            message_id: someip::MessageId::from(0x02030405),
            length: 0,
            request_id: someip::RequestId::from(0xc1c28080),
            proto_version: someip::ProtocolVersion::Version1,
            intf_version: someip::InterfaceVersion::from(1),
            msg_type: someip::MessageType::TpRequestNoReturn,
            ret_code: someip::ReturnCode::Ok,
            tp_header: None,
        };
        let mut data = BytesMut::zeroed(len);
        data.fill(value);
        someip::Message{ header: hdr, payload: data.freeze()}
    }

    #[test]
    fn two_peers() {
        let mut encdr = EncoderMulti::new_default();
        let msg1 = make_msg(12, 0x1a);
        let msg2 = make_msg(30, 0x1b);
        let msg3 = make_msg(44, 0x1c);

        let a: SocketAddr = "10.10.2.1:8088".parse().unwrap();
        let b: SocketAddr = "10.10.4.4:3490".parse().unwrap();

        assert!( !encdr.prepare_msg(&a, msg1, Duration::from_secs(2)) );
        assert!( !encdr.prepare_msg(&b, msg2, Duration::from_millis(1)) );
        assert!( encdr.prepare_msg(&a, msg3, Duration::from_millis(0)) );
        let d1 = encdr.get_completed();
        assert_eq!(d1.len(), 1);
        assert_eq!(d1[0].0, a);

        sleep(Duration::from_secs(1));
        assert!(encdr.schedule());
        let d2 = encdr.get_completed();
        assert_eq!(d2.len(), 1);
        assert_eq!(d2[0].0, b);
    }
}