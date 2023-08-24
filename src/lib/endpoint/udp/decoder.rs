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
use bytes::{Buf, BytesMut};
use crate::endpoint::someip;
use crate::endpoint::types;
use crate::endpoint::udp::reassembler as rsm;


/// Configuration parameters for a reassembly/fragmentation.
#[derive(Debug, Clone)]
pub struct TpConfig {
    /// initial segmentation task buffer size for payload
    pub initial_payload_buffer_size: usize,
    /// maximum segmentation task buffer size for payload
    pub max_payload_size: usize,
    /// alive counter start value
    pub alive_counter_init: u8,
}


/// Message decoder for SOME/IP messages incoming via UDP.
pub struct Decoder {
    /// Ongoing reassembly tasks.
    reassemblers: HashMap<rsm::ReassemblyKey, rsm::Reassembler>,
    /// Configuration for reassembly tasks.
    configs: HashMap<(someip::MessageId, someip::MessageType, someip::InterfaceVersion), TpConfig>,
}

impl Decoder {
    pub fn new() -> Self {
        Decoder{ reassemblers: HashMap::new(), configs: HashMap::new() }
    }

    /// This method should be called periodically at fixed time interval to cleanup
    /// stale and overdue reassembly tasks.
    /// The method runs through all ongoing reassembly tasks and decrements their alive counter
    /// by one - if the counter is 0 the reassembly is cancelled.
    pub fn cleanup(&mut self) {
        let mut to_delete = vec![];
        for r in &mut self.reassemblers {
            if r.1.tick() {
                to_delete.push(r.0.clone());
            }
        }
        for k in to_delete {
            self.reassemblers.remove(&k);
            log::warn!("Cancelling reassembly for {:?} by timeout", k);
        }
    }

    /// Process a single received UDP datagram from `peer`.
    /// For each completely received message the `callback` is called as well as for each
    /// encountered error.
    pub fn process_datagram<M>(&mut self, peer: SocketAddr, dgrm: BytesMut, mut callback: M)
        where M: FnMut(types::Result< Option<someip::Message> >)
    {
        process_datagram(dgrm, |result| {
            match result {
                Ok(msg) => {
                    callback( self.process_message(peer, msg));
                    // errors reported from process message are higher level errors where
                    // we have already successfully decoded the SOME/IP message - so we can
                    // continue to parse the next one from the datagram
                    true
                },
                Err(e) => {
                    let cont = match &e {
                        // provided that the length field works also in later SOME/IP versions
                        // like in Version 1, we can continue parsing the packet after protocol
                        // version errors
                        types::Error::ProtocolVersionUnsupported(_) => true,
                        _ => false,
                    };
                    callback(Err(e));
                    cont
                },
            }
        })
    }

    /// process a successfully received SOME/IP message from UDP.
    fn process_message(&mut self, peer: SocketAddr, msg: someip::Message)
            -> types::Result< Option<someip::Message> >
    {
        let key = rsm::make_reassembly_key(&peer, &msg.header);
        if !msg.header.is_tp() {
            self.cancel_reassembly(&key);
            return Ok( Some(msg) );
        }
        self.process_segment(msg, key)
    }

    /// process a segmented SOME/IP message from UDP
    fn process_segment(&mut self, mut msg: someip::Message, key: rsm::ReassemblyKey)
            -> types::Result< Option<someip::Message> >
    {
        assert!(msg.header.tp_header.is_some());
        if self.tp_allowed(&msg.header) {
            let is_not_final = msg.header.tp_header.as_ref().unwrap().more;

            if is_not_final && msg.payload.len() % rsm::SOMEIP_TP_OFFSET_SCALE != 0 {
                log::warn!("Received non-final segment for {:?} with payload not a multiple of 16 bytes.",
                    key);
                self.reassemblers.remove(&key);
                return Err(types::Error::UdpIntermediateSegmentInvalidSize(msg.header));
            }

            if let Some(reassembler) = self.reassemblers.get_mut(&key) {
                // subsequent segments
                if let Err(err) = reassembler.process_segment(msg) {
                    log::warn!("Reassembly for {:?} aborted: {:?}", key, err);
                    self.reassemblers.remove(&key);
                    return Err(err);
                }
                if is_not_final {
                   return Ok(None)
                }
                let reassembler = self.reassemblers.remove(&key).expect("");
                return reassembler.finish().map(|msg| Some(msg))
            } else {
                // initial segment
                if is_not_final {
                    let tp_config = self.get_config(&msg.header).expect("");
                    let mut reassembler = rsm::Reassembler::new(
                        tp_config.initial_payload_buffer_size,
                        tp_config.max_payload_size,
                        tp_config.alive_counter_init,
                        &msg.header);
                    if let Err(err) = reassembler.process_segment(msg) {
                        log::warn!("Reassembly for {:?} aborted: {:?}", key, err);
                        return Err(err);
                    }
                    self.reassemblers.insert(key, reassembler);
                    Ok( None )
                } else {
                    log::warn!("Initial segment that is final from {:?}.", key);
                    // deliver it anyway
                    rsm::finish_reassembled_header(&mut msg);
                    Ok( Some(msg) )
                }
            }
        } else {
            Err(types::Error::UdpSegmentationNotAllowed(msg.header))
        }
    }

    /// deletes an ongoing reassembly if there is one and logs a warning
    fn cancel_reassembly(&mut self, key: &rsm::ReassemblyKey) {
        if self.reassemblers.contains_key(key) {
            log::warn!("Cancelling reassembly for {:?} by non segmented message", key);
            self.reassemblers.remove(key);
        }
    }

    /// Returns the TP configuration for the given header.
    fn get_config(&self, header: &someip::Header) -> Option<&TpConfig> {
        self.configs.get(&(header.message_id.clone(), header.msg_type, header.intf_version.clone()) )
    }

    fn tp_allowed(&self, header: &someip::Header) -> bool {
        self.configs.contains_key(&(header.message_id.clone(), header.msg_type, header.intf_version.clone()))
    }
}

/// Decode a UDP datagram into a sequence of SOME/IP messages
/// The method calls for each successfully decoded message or encountered error the `callback`.
/// If the callback returns `false` further parts of the datagram will be discarded - otherwise
/// decoding continues until the datagram buffer is empty.
/// NOTE: Continuing to decode the datagram after an error has been received might lead to unexpected
///       results, because we cannot guarantee that the buffer is at some message boundary.
fn process_datagram<M>(mut dgrm: BytesMut, mut callback: M)
    where M: FnMut(types::Result<someip::Message>) -> bool,
{
    while !dgrm.is_empty() {
        if !callback(process_datagram_one(&mut dgrm)) {
            break;
        }
    }
}

/// Decodes a single SOME/IP message from the datagram buffer.
fn process_datagram_one(dgrm: &mut BytesMut) -> types::Result<someip::Message> {
    if dgrm.len() < someip::SOMEIP_HEADER_SIZE {
        return Err(types::Error::UdpIncompleteHeader);
    }
    let mut header = someip::Header::read_base_from(dgrm);
    if header.msg_type.is_tp() {
        if dgrm.len() < someip::SOMEIP_TP_HEADER_SIZE {
            return Err(types::Error::UdpIncompleteHeader);
        }
        header.read_tp(dgrm);
    }

    // basic header conformance checks
    if header.length < header.min_length_value() {
        // this check should be done first to avoid underflow panic in expected_payload_len()
        // afterwards
        return Err(types::Error::LengthFieldValueTooSmall(header));
    }
    if header.expected_payload_len() > someip::DEFAULT_MAX_FRAME_SIZE {
        return Err(types::Error::MaxPayloadSizeExceeded(header));
    }
    if header.proto_version != someip::ProtocolVersion::Version1 {
        return Err(types::Error::ProtocolVersionUnsupported(header));
    }
    let pl_length = header.expected_payload_len();
    if pl_length > dgrm.len() {
        return Err(types::Error::UdpPayloadLongerThanHeader(header));
    }
    Ok(someip::Message { header, payload: dgrm.copy_to_bytes(pl_length) })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_datagram_err1() {
        let b = BytesMut::from([
            0x01u8, 0x02, 0x03, 0x04,       // message id: 0x01020304
            0x00  , 0x00, 0x00, 0x18,       // length: 24 bytes
            0x32  , 0x33, 0x34, 0x35,       // request id: 0x32333435
            0x01  , 0x12, 0x01, 0x00,       // proto: 1, intf: 18, msg_type: RequestNoReturn, return: Ok
            0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8,
            0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8,
            0x01u8, 0x02, 0x03, 0x05,       // message id: 0x01020305
            0x00  , 0x00, 0x00, 0x18,       // length: 24 bytes
            0x32  , 0x33, 0x34, 0x35,       // request id: 0x32333435
            0x02  , 0x12, 0x01, 0x00,       // proto: 2, intf: 18, msg_type: RequestNoReturn, return: Ok
            0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8,
            0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8,
            0x01u8, 0x02, 0x03, 0x06,       // message id: 0x01020304
            0x00  , 0x00, 0x00, 0x18,       // length: 24 bytes
            0x32  , 0x33, 0x34, 0x35,       // request id: 0x32333435
            0x01  , 0x12, 0x01, 0x00,       // proto: 1, intf: 18, msg_type: RequestNoReturn, return: Ok
            0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8,
            0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8,
        ].as_ref());

        let mut v = Vec::new();
        let mut error = None;

        process_datagram(b, |r| -> bool {
            match r {
                Ok(msg) => v.push(msg),
                Err(e) => { error = Some(e); return false }
            }
            true}
        );
        assert!(if let Some(types::Error::ProtocolVersionUnsupported(_)) = error {true} else {false});
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].header.message_id, someip::MessageId::from(0x01020304));
    }

    #[test]
    fn decode_datagram() {
        let b = BytesMut::from([
            0x01u8, 0x02, 0x03, 0x04,       // message id: 0x01020304
            0x00  , 0x00, 0x00, 0x18,       // length: 24 bytes
            0x32  , 0x33, 0x34, 0x35,       // request id: 0x32333435
            0x01  , 0x12, 0x01, 0x00,       // proto: 1, intf: 18, msg_type: RequestNoReturn, return: Ok
            0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8,
            0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8,
            0x01u8, 0x02, 0x03, 0x05,       // message id: 0x01020305
            0x00  , 0x00, 0x00, 0x18,       // length: 24 bytes
            0x32  , 0x33, 0x34, 0x35,       // request id: 0x32333435
            0x01  , 0x12, 0x01, 0x00,       // proto: 1, intf: 18, msg_type: RequestNoReturn, return: Ok
            0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8,
            0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8,
            0x01u8, 0x02, 0x03, 0x06,       // message id: 0x01020304
            0x00  , 0x00, 0x00, 0x18,       // length: 24 bytes
            0x32  , 0x33, 0x34, 0x35,       // request id: 0x32333435
            0x01  , 0x12, 0x01, 0x00,       // proto: 1, intf: 18, msg_type: RequestNoReturn, return: Ok
            0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8,
            0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8,
        ].as_ref());

        let mut v = Vec::new();
        let mut error = None;

        process_datagram(b, |r| -> bool {
            match r {
                Ok(msg) => v.push(msg),
                Err(e) => { error = Some(e); return false }
            }
            true}
        );
        assert!(error.is_none());
        assert_eq!(v.len(), 3);
        assert_eq!(v[0].header.message_id, someip::MessageId::from(0x01020304));
        assert_eq!(v[1].header.message_id, someip::MessageId::from(0x01020305));
        assert_eq!(v[2].header.message_id, someip::MessageId::from(0x01020306));
    }

    /// unsuccessful transmission: payload not complete
    #[test]
    fn decode_single_payload_incomplete() {
        let mut b = BytesMut::from([
            0x01u8, 0x02, 0x03, 0x04,       // message id: 0x01020304
            0x00  , 0x00, 0x00, 0x33,       // length: 51 bytes
            0x32  , 0x33, 0x34, 0x35,       // request id: 0x32333435
            0xf1  , 0x12, 0x01, 0x00,       // proto: 0xf1, intf: 18, msg_type: RequestNoReturn, return: Ok
            0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8,
            0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8,
            0x99, 0xa8, 0xfe, 0xde
        ].as_ref());
        assert!(process_datagram_one(&mut b).is_err());
    }

    /// unsuccessful transmission: protocol version
    #[test]
    fn decode_single_invalid_protocol_version() {
        let mut b = BytesMut::from([
            0x01u8, 0x02, 0x03, 0x04,       // message id: 0x01020304
            0x00  , 0x00, 0x00, 0x18,       // length: 24 bytes
            0x32  , 0x33, 0x34, 0x35,       // request id: 0x32333435
            0xf1  , 0x12, 0x01, 0x00,       // proto: 0xf1, intf: 18, msg_type: RequestNoReturn, return: Ok
            0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8,
            0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8,
            0x99, 0xa8, 0xfe, 0xde
        ].as_ref());
        assert!(process_datagram_one(&mut b).is_err());
    }

    /// unsuccessful transmission of a to big length field
    #[test]
    fn decode_single_header_length_too_big() {
        let mut b = BytesMut::from([
            0x01u8, 0x02, 0x03, 0x04,       // message id: 0x01020304
            0xff, 0x00, 0x00, 0x01,       // length: 0xff000001 bytes
            0x32, 0x33, 0x34, 0x35,       // request id: 0x32333435
            0x01, 0x12, 0x01, 0x00,       // proto: 1, intf: 18, msg_type: RequestNoReturn, return: Ok
            0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8,
            0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8,
            0x99, 0xa8, 0xfe, 0xde
        ].as_ref());
        assert!(process_datagram_one(&mut b).is_err());
    }

    /// unsuccessful transmission of a non-sense length field
    #[test]
    fn decode_single_header_length_nonsense() {
        let mut b = BytesMut::from([
            0x01u8, 0x02, 0x03, 0x04,       // message id: 0x01020304
            0x00, 0x00, 0x00, 0x01,       // length: 1 bytes
            0x32, 0x33, 0x34, 0x35,       // request id: 0x32333435
            0x01, 0x12, 0x01, 0x00,       // proto: 1, intf: 18, msg_type: RequestNoReturn, return: Ok
            0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8,
            0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8,
            0x99, 0xa8, 0xfe, 0xde
        ].as_ref());
        assert!(process_datagram_one(&mut b).is_err());
    }

    /// unsuccessful transmission of a partial header non-segmented
    #[test]
    fn decode_single_header_partial_nontp() {
        let mut b = BytesMut::from([
                       0x01u8, 0x02, 0x03, 0x04,       // message id: 0x01020304
                       0x00  , 0x00, 0x00, 0x18,       // length: 24 bytes
                       0x32  , 0x33, 0x34, 0x35,       // request id: 0x32333435
        ].as_ref());
        assert!(process_datagram_one(&mut b).is_err());
    }

    /// unsuccessful transmission of a partial header segmented
    #[test]
    fn decode_single_header_partial_tp() {
        let mut b = BytesMut::from([
            0x01u8, 0x02, 0x03, 0x04,       // message id: 0x01020304
            0x00  , 0x00, 0x00, 0x18,       // length: 24 bytes
            0x32  , 0x33, 0x34, 0x35,       // request id: 0x32333435
            0x01  , 0x12, 0x20, 0x00,       // proto: 1, intf: 18, msg_type: TpRequest, return: Ok
        ].as_ref());
        assert!(process_datagram_one(&mut b).is_err());
    }

    /// successful transmission of a non-segmented SOME/IP message
    #[test]
    fn decode_single_nontp() {
        let mut b = BytesMut::from([
            0x01u8, 0x02, 0x03, 0x04,       // message id: 0x01020304
            0x00  , 0x00, 0x00, 0x18,       // length: 24 bytes
            0x32  , 0x33, 0x34, 0x35,       // request id: 0x32333435
            0x01  , 0x12, 0x01, 0x00,       // proto: 1, intf: 18, msg_type: RequestNoReturn, return: Ok
            0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8,
            0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8,
            0x99, 0xa8, 0xfe, 0xde
        ].as_ref());
        let r = process_datagram_one(&mut b);
        assert!(r.is_ok());
        assert_eq!(b, [0x99, 0xa8, 0xfe, 0xde].as_ref());

        let msg = r.unwrap();
        assert_eq!(msg.header.message_id, someip::MessageId::from(0x01020304));
        assert_eq!(msg.header.length, 24);
        assert_eq!(msg.header.request_id, someip::RequestId::from(0x32333435));
        assert_eq!(msg.header.proto_version, someip::ProtocolVersion::Version1);
        assert_eq!(msg.header.msg_type, someip::MessageType::RequestNoReturn);
        assert_eq!(msg.header.intf_version, someip::InterfaceVersion::from(18));
        assert_eq!(msg.header.ret_code, someip::ReturnCode::Ok);
        assert_eq!(msg.header.tp_header, None);
        assert_eq!(msg.payload, [0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8,
            0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8,].as_ref());
    }

    /// successful transmission of a segmented SOME/IP message.
    #[test]
    fn decode_single_tp() {
        let mut b = BytesMut::from([
            0x01u8, 0x02, 0x03, 0x04,       // message id: 0x01020304
            0x00  , 0x00, 0x00, 0x1d,       // length: 29 bytes
            0x32  , 0x33, 0x34, 0x35,       // request id: 0x32333435
            0x01  , 0x12, 0x20, 0x00,       // proto: 1, intf: 18, msg_type: RequestNoReturn, return: Ok
            0x00,   0x00, 0x02, 0x01,       // tp header: offset = 0x20, more = true
            0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8,
            0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0x99,
            0xa8, 0xfe, 0xde
        ].as_ref());
        let r = process_datagram_one(&mut b);
        assert!(r.is_ok());
        assert_eq!(b, [0xa8, 0xfe, 0xde].as_ref());

        let msg = r.unwrap();
        assert_eq!(msg.header.message_id, someip::MessageId::from(0x01020304));
        assert_eq!(msg.header.length, 29);
        assert_eq!(msg.header.request_id, someip::RequestId::from(0x32333435));
        assert_eq!(msg.header.proto_version, someip::ProtocolVersion::Version1);
        assert_eq!(msg.header.intf_version, someip::InterfaceVersion::from(18));
        assert_eq!(msg.header.msg_type, someip::MessageType::TpRequest);
        assert_eq!(msg.header.ret_code, someip::ReturnCode::Ok);
        assert_eq!(msg.payload, [0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8,
            0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0x99].as_ref());
    }
}
