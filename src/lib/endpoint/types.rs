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
use std::time::Duration;
use crate::endpoint::someip;
use crate::endpoint::someip::Header;

/// Error for endpoint message processing.
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
    /// While reassembling a hole in the segment sequence was detected.
    UdpSegmentationHoleDetected(Header),
}

/// Result type for message processing.
pub type Result<T> = std::result::Result<T, Error>;

/// Transport type for received/send SOME/IP messages.
#[derive(Debug, PartialEq, Eq)]
pub enum TransportBinding {
    Udp, Tcp, Multicast
}

/// Protocol to communicate with endpoints.
#[derive(Debug)]
pub enum EndpointCmd {
    /// Sent by Rx part of an endpoint when a SOME/IP message has been received
    Received{transport: TransportBinding, local: SocketAddr, peer: SocketAddr, msg: someip::Message},
    /// Sent to Tp part of an endpoint when a SOME/IP message shall be sent
    Send{transport: TransportBinding,
         local: SocketAddr,
         peer: SocketAddr,
         msg: someip::Message,
         retention_time: Duration},

    EndpointDown{transport: TransportBinding, local: SocketAddr },

    AddService{svc: someip::ServiceId, sender: EndpointSender },

    RemService{svc: someip::ServiceId },
}

pub type EndpointReceiver = tokio::sync::mpsc::Receiver<EndpointCmd>;
pub type EndpointSender = tokio::sync::mpsc::Sender<EndpointCmd>;