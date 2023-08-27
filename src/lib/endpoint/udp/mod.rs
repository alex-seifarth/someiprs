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

use tokio::net::UdpSocket;
use std::sync::Arc;
use tokio::select;
use tokio_util::sync::CancellationToken;
use crate::endpoint::types::{EndpointReceiver, TransportBinding};
use crate::endpoint::udp::encoder::Encoder;
use crate::endpoint::types::EndpointCmd;

pub mod decoder;
pub mod encoder;
pub mod reassembler;
pub mod encoder_multi;



pub async fn udp_tx_task(socket: Arc<UdpSocket>,
                         max_datagram_size: usize,
                         mut channel: EndpointReceiver,
                         ct: CancellationToken)
{
    let mut encoder = Encoder::new(max_datagram_size);
    loop {
        select! {
            cmd = channel.recv() => {
                match cmd {
                    None => {},
                    Some(cmd) => {
                        match cmd {
                            EndpointCmd::Send {transport: t,local: l,peer: p, msg: m} => {
                                debug_assert!(t == TransportBinding::Udp);
                                debug_assert!(l == socket.local_addr().unwrap());
                           //     encoder.prepare_msg()
                            },
                            _ => {
                                log::error!("Invalid cmd for UDP rx task: {:?}", cmd);
                            },
                        }
                    },
                }
            },
            _ = ct.cancelled() => {},
        }
    }
}

