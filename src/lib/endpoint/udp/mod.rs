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
use std::time::Duration;
use tokio::select;
use tokio::time::MissedTickBehavior;
use tokio_util::sync::CancellationToken;
use crate::endpoint::types::{EndpointReceiver, TransportBinding, EndpointCmd};
use crate::endpoint::udp::encoder_multi::EncoderMulti;

pub mod decoder;
pub mod encoder;
pub mod reassembler;
pub mod encoder_multi;


/// UDP receiver task
///
pub async fn udp_tx_task(socket: Arc<UdpSocket>,
                         max_datagram_size: usize,
                         mut channel: EndpointReceiver,
                         ct: CancellationToken)
{
    let mut encoder = EncoderMulti::new(max_datagram_size, Duration::from_secs(360));
    let mut cleanup_timeout = tokio::time::interval(Duration::from_millis(1000));
    let mut schedule = tokio::time::interval(Duration::from_secs(1000));
    schedule.set_missed_tick_behavior(MissedTickBehavior::Burst);
    let mut scheduled = false;
    loop {
        select! {
            _ = cleanup_timeout.tick() => {
                encoder.cleanup();
                // update of next_schedule shouldn't be necessary because the next_schedule can
                // just be later (or no schedule at all), but this would be captured by the
                // EncoderMulti itself
                //update_schedule(&mut scheduled, &mut schedule, &encoder);
            },
            _ = schedule.tick() => {
                if scheduled {
                    if encoder.schedule() {
                        send_datagrams(&mut encoder, socket.as_ref()).await;
                    }
                    update_schedule(&mut scheduled, &mut schedule, &encoder);
                }
            },
            cmd = channel.recv() => {
                match cmd {
                    None => {},
                    Some(cmd) => {
                        match cmd {
                            EndpointCmd::Send {transport,
                                               local,
                                               peer,
                                               msg,
                                               retention_time} => {
                                debug_assert!(transport == TransportBinding::Udp);
                                debug_assert!(local == socket.local_addr().unwrap());
                                if encoder.prepare_msg(&peer, msg, retention_time) {
                                    send_datagrams(&mut encoder, socket.as_ref()).await;
                                }
                                update_schedule(&mut scheduled, &mut schedule, &encoder);
                            },
                            _ => {
                                log::error!("Invalid cmd for UDP rx task: {:?}", cmd);
                            },
                        }
                    },
                }
            },
            _ = ct.cancelled() => {
                break
            },
        }
    }
}

fn update_schedule(scheduled: &mut bool, schedule: &mut tokio::time::Interval, encoder: &EncoderMulti) {
    if let Some(next_schedule) = encoder.next_schedule() {
        schedule.reset_at( tokio::time::Instant::from_std(next_schedule));
        *scheduled = true;
    } else {
        *scheduled = false;
    }
}

async fn send_datagrams(encoder: &mut EncoderMulti, socket: &UdpSocket) {
    for msg in encoder.get_completed() {
        let len = msg.1.len();
        match socket.send_to(msg.1.as_ref(), msg.0).await {
            Ok(size) => {
                if len != size {
                    log::error!("UDP transmission couldn't send all data to {:?} ({} < {})",
                        msg.0, size, len);
                }
            },
            Err(err) => {
                log::error!("UDP transmission error to {:?}: {:?}", msg.0, err);
            },
        }
    }
}

