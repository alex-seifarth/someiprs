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

use bytes::{Buf, BytesMut};
use crate::endpoint::someip;
use crate::endpoint::types;

/// Message decoder for SOME/IP messages incoming via UDP.
///
pub struct Decoder {}


impl Decoder {

}

/// Decode a UDP datagram into a sequence of SOME/IP messages
/// The method calls for each successfully decoded message or encountered error the `callback`.
/// If the callback returns `false` further parts of the datagram will be discarded - otherwise
/// decoding continues until the datagram buffer is empty.
/// NOTE: Continuing to decode the datagram after an error has been received might lead to unexpected
///       results, because we cannot guarantee that the buffer is at some message boundary.
pub fn process_datagram<M>(mut dgrm: BytesMut, mut callback: M)
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
