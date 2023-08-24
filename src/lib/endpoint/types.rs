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
use tokio::sync::mpsc::{Receiver, Sender};
use crate::endpoint::someip;
use crate::endpoint::someip::Header;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UdpRxError {

}

pub enum Transport {
    UDP, TCP
}

pub enum Command {
    /// SOME/IP messages received by rx endpoints
    Received{ transport: Transport, local: SocketAddr, peer: SocketAddr, msg: someip::Message },
    /// SOME/IP messages that shall be sent by tx endpoints
    Transmit{ peer: SocketAddr, msg: someip::Message },
    ///
    AddService(someip::ServiceId, MessageSender, usize /*max segmentation size*/),

    /// Remove the service from this endpoint.
    RemService(someip::ServiceId),

}

pub type MessageSender = Sender<Command>;
pub type MessageReceiver = Receiver<Command>;

#[derive(Debug, Clone)]
pub enum Error {
    /// Maximum payload size exceeded.
    MaxPayloadSizeExceeded(Header),
    /// The received SOME/IP protocol version is not supported.
    ProtocolVersionUnsupported(Header),
    /// The length field is shorter then the headers
    LengthFieldValueTooSmall(Header),

    /// UDP datagram ends in the middle of a SOME/IP Header.
    UdpIncompleteHeader,
    /// UDP (or unix domain dgrm) datagram too short for expected payload
    UdpPayloadLongerThanHeader(Header),
    /// Segmentation/Reassembly is not allowed/configured for the message.
    UdpSegmentationNotAllowed(Header),
    /// Received an intermediate segment (or first one) where payload size is not a multiple of 16.
    UdpIntermediateSegmentInvalidSize(Header),
    /// While reassmbling a hole in the segment sequence was detected.
    UdpSegmentationHoleDetected(Header),

}

pub type Result<T> = std::result::Result<T, Error>;

