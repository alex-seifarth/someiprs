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
pub mod reassembler;
mod encoder;
mod encoder_multi;

/// UDP receiver task
pub async fn udp_rx_task(_socket: Arc<UdpSocket>) {

}

/// UDP sender task
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
                    None => {
                        ct.cancel();
                        break
                    },
                    Some(cmd) => {
                        match cmd {
                            EndpointCmd::Send {transport,
                                               peer,
                                               msg,
                                               retention_time} => {
                                debug_assert!(transport == TransportBinding::Udp);
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

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::sync::Mutex;
    use super::*;
    use bytes::BytesMut;
    use crate::endpoint::someip;

    fn make_msg(len: usize, value: u8) -> someip::Message {
        let hdr = someip::Header{
            message_id: someip::MessageId::from(0x12030405),
            length: 0,
            request_id: someip::RequestId::from(0xc1c28080),
            proto_version: someip::ProtocolVersion::Version1,
            intf_version: someip::InterfaceVersion::from(1),
            msg_type: someip::MessageType::RequestNoReturn,
            ret_code: someip::ReturnCode::Ok,
            tp_header: None,
        };
        let mut data = BytesMut::zeroed(len);
        data.fill(value);
        someip::Message{ header: hdr, payload: data.freeze()}
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 5)]
    async fn sender() {
        let socket = Arc::new(
            UdpSocket::bind("127.0.0.1:34900").await.expect("failed to setup socket"));
        let (chnnl_tx, chnnl_rx) = tokio::sync::mpsc::channel(1024);
        let ct = CancellationToken::new();
        let received2 = Arc::new( Mutex::new( Vec::new() ) );
        let received3 = received2.clone();

        let h1 = tokio::spawn(
            udp_tx_task(socket.clone(), 1420, chnnl_rx, ct.clone()));

        let ct2 = ct.clone();
        let h2 = tokio::spawn(async move {
            let rxsock = UdpSocket::bind("127.0.0.1:35000").await.expect("client socket fail");
            rxsock.connect("127.0.0.1:34900").await.expect("client connect fail");
            let mut buf = vec![0; 1500];
            loop {
                select! {
                    _ = ct2.cancelled() => break,
                    rsz = rxsock.recv(&mut buf) => {
                        match rsz {
                            Ok(sz) => {
                                if sz > 0 {
                                    let mut msg_box = received3.lock().expect("");
                                    msg_box.push( BytesMut::from( &buf[0..sz]) );
                                }
                            },
                            Err(err) => {
                                panic!("IO Error {:?}", err);
                            },
                        }
                    }
                }
            }
        });

        let daddr: SocketAddr = "127.0.0.1:35000".parse().expect("");
        for i in 0..10 {
            let msg = make_msg(1024, 0xa0 + (i as u8));
            chnnl_tx.send( EndpointCmd::Send {
                transport: TransportBinding::Udp,
                msg,
                retention_time: Duration::from_millis(5),
                peer: daddr.clone()
            }).await.expect("Send on channel failed");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        let r = tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                if received2.lock().expect("").len() == 10 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }).await;

        assert!(r.is_ok(), "Wait for received vector failed with timeout");
        assert_eq!(received2.lock().unwrap().len(), 10);
        ct.cancel();
        let _ = h1.await;
        let _ = h2.await;
    }
}

