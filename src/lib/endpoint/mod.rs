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

pub mod someip;
pub mod types;
pub mod udp;

// use std::net::SocketAddr;
// use std::sync::Arc;
// use std::sync::mpsc::Receiver;
// use tokio::net::UdpSocket;
// use tokio_util::sync::CancellationToken;
// use bytes::{BytesMut, Bytes};
// use tokio::task::JoinHandle;
//
// pub mod udp;
//
// pub mod someip;
// pub mod types;
// //mod someip_decoder;
// mod udp_rx_endpoint;
//
// use udp_rx_endpoint::{UdpRxEndpoint, TxSender, TxReceiver};
// use crate::endpoint::types::{Command, MessageReceiver, MessageSender};
//
// const UDP_MAX_PACKET_SIZE: usize = 1500;
//
// async fn udp_rx_task(sckt: Arc<UdpSocket>,
//                      ct: CancellationToken,
//                      tx: MessageSender)
//     -> Result<(), std::io::Error>
// {
//     // start the transmitter buffering task
//     let (ttx, trx) = tokio::sync::mpsc::channel(2048);
//     let tx_task_handle = tokio::spawn(udp_tx_task2(sckt.clone(),
//         ct.clone(), trx));
//
//     let mut udp_endpoint = UdpRxEndpoint::new(UDP_MAX_PACKET_SIZE,ttx);
//     let mut buf = udp_endpoint.create_buffer();
//     loop {
//         tokio::select! {
//             r = sckt.recv_from(buf.as_mut()) => {
//                 match r {
//                     Ok((0, _)) => {
//                         println!("len = 0 in UDP");
//                         // does this happen, when our interface or IP addr. goes away?
//                     },
//                     Ok((len, addr)) => {
//                         let mut bb = BytesMut::from(buf.as_ref()[..(len-1)].as_ref());
//                         udp_endpoint.process_data(&addr, &mut bb).await;
//                     },
//                     Err(ioe) => {
//                         println!("Socket I/O error: {:?}", ioe);
//                         ct.cancel();
//                     }
//                 }
//             },
//             _ = ct.cancelled() => {
//                 break;
//             },
//         }
//     }
//     let _ = tx_task_handle.await;
//     Ok(())
// }
//
// async fn udp_tx_task(sckt: Arc<UdpSocket>,
//                      ct: CancellationToken,
//                      mut rx: MessageReceiver)
//     -> Result<(), std::io::Error>
// {
//     tokio::select! {
//         msg = rx.recv() => {},
//         _ = ct.cancelled() => {},
//     }
//     Ok(())
// }
//
// async fn udp_tx_task2(sckt: Arc<UdpSocket>,
//                       ct: CancellationToken,
//                       mut rx: TxReceiver)
// {
//     loop {
//         tokio::select!{
//             _ = ct.cancelled() => break,
//             m = rx.recv() => {
//                 match m {
//                     None => break,
//                     Some((addr, frame)) => {
//                         let len = sckt.send_to(frame.as_ref(), addr).await
//                             .expect("IP version mismatch of address and socket");
//                         if len != frame.len() {
//                             println!("Couldn't send all data {} : {}", frame.len(), len);
//                         }
//                     }
//                 }
//             },
//         }
//     }
// }
//
// fn start_udp_tx_task(sckt: &Arc<UdpSocket>, ct: &CancellationToken)
//                     -> (JoinHandle<Result<(), std::io::Error>>, MessageSender)
// {
//     let (tx, rx) = tokio::sync::mpsc::channel(1024);
//     let jh = tokio::spawn(udp_tx_task(sckt.clone(), ct.clone(), rx));
//     (jh, tx)
// }
//
// fn start_udp_rx_task(sckt: &Arc<UdpSocket>, ct: &CancellationToken, txtx: &MessageSender)
//                     -> JoinHandle<Result<(), std::io::Error>>
// {
//     tokio::spawn(udp_rx_task(sckt.clone(), ct.clone(), txtx.clone()))
// }
//
// pub async fn start_udp_endpoint(local_addr: SocketAddr, ct: CancellationToken) {
//     match UdpSocket::bind(local_addr.clone()).await {
//         Ok(socket) => {
//             let ct2 = CancellationToken::new();
//             let rsckt = Arc::new(socket);
//             let (jhtx, txtx) = start_udp_tx_task(&rsckt, &ct2);
//             let jhrx = start_udp_rx_task(&rsckt, &ct2, &txtx);
//
//             tokio::select! {
//                 r_rx = jhrx => { println!("Rx task finished with {:?}", r_rx) },
//                 r_tx = jhtx => { println!("Tx task finished with {:?}", r_tx) },
//                 _ = ct.cancelled() => {},
//             }
//             ct2.cancel();
//         }
//         Err(ioe) => { println!("Socket error at bind: {:?}", ioe) }
//     }
// }