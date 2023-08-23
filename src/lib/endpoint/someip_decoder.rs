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
use crate::endpoint::someip;
use crate::util::coder::Decoder;
use bytes::{Buf, Bytes, BytesMut};

/// Decoder for SOME/IP messages
/// This decoder takes an input buffer and reads the SOME/IP standard
/// header with optional TP header and then the payload and returns it.
pub struct SomeipDecoder {
    max_frame_size: usize,
    current_header: Option<someip::Header>,
    wait_for_tp: bool,
}

impl SomeipDecoder {

    /// Creates a new [SomeipDecoder] object with standard values.
    pub fn new() -> Self {
        SomeipDecoder{
            max_frame_size: someip::DEFAULT_MAX_FRAME_SIZE,
            current_header: None,
            wait_for_tp: false
        }
    }
}

impl Decoder for SomeipDecoder {
    type Message = (someip::Header, Bytes);
    type Error = someip::SomeipWireError;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Message>, Self::Error> {
        // if no header in store -> try to decode base header
        if self.current_header.is_none() {
            if buf.len() < someip::SOMEIP_HEADER_SIZE {
                return Ok(None)
            }
            let header = someip::Header::read_base_from(buf);
            if header.length < someip::SOMEIP_HEADER_LEN_PART {
                return Err(someip::SomeipWireError::LengthFieldErrorToShort)
            }
            if (header.length - someip::SOMEIP_HEADER_LEN_PART) > self.max_frame_size {
                return Err(someip::SomeipWireError::ExceedingMaxFrameSize)
            }
            if header.proto_version != someip::ProtocolVersion::Version1 {
                return Err(someip::SomeipWireError::UnsupportedProtocolVersion)
            }
            self.wait_for_tp = header.requires_tp();
            self.current_header = Some(header);
        }

        debug_assert!(self.current_header.is_some());
        // header is there - if TP header expected and not yet received
        // -> try to decode TP header
        if self.wait_for_tp {
            if buf.len() < someip::SOMEIP_TP_HEADER_SIZE {
                return Ok(None)
            }
            self.current_header.as_mut().unwrap().read_tp(buf);
            self.wait_for_tp = false;
        }

        debug_assert!(self.current_header.is_some());
        // we have header and optionally TP header
        // -> try to get payload from buffer
        let header = self.current_header.as_ref().unwrap();
        let payload_len = header.expected_payload_len();
        if buf.len() < payload_len {
            buf.reserve(payload_len - buf.len());
            return Ok(None)
        }
        return Ok( Some( (self.current_header.take().unwrap(), buf.copy_to_bytes(payload_len)) ) )
    }

    fn reset(&mut self) {
        self.current_header = None;
        self.wait_for_tp = false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::endpoint::someip::{MessageId, RequestId, ProtocolVersion, InterfaceVersion,
        MessageType, ReturnCode, SomeipWireError, TpHeader};

    #[test]
    fn decode_someip_header1() {
        let mut decoder = SomeipDecoder::new();
        let b = [
            0x01u8, 0x02, 0x03, 0x04,       // message id: 0x01020304
            0x00  , 0x00, 0x00, 0x18,       // length: 24 bytes
            0x32  , 0x33, 0x34, 0x35,       // request id: 0x32333435
            0x01  , 0x12, 0x01, 0x00,       // proto: 1, intf: 18, msg_type: RequestNoReturn, return: Ok
            0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8,
            0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8,
            0x99
        ].as_ref();
        let mut ba: BytesMut = BytesMut::from(b);

        let res = decoder.decode(&mut ba);
        assert!(res.is_ok());
        assert!(res.as_ref().unwrap().is_some());
        let msg = res.unwrap().unwrap();

        assert_eq!(msg.0.message_id, MessageId::from(0x01020304));
        assert_eq!(msg.0.length, 24);
        assert_eq!(msg.0.request_id, RequestId::from(0x32333435));
        assert_eq!(msg.0.proto_version, ProtocolVersion::Version1);
        assert_eq!(msg.0.intf_version, InterfaceVersion::from(18));
        assert_eq!(msg.0.msg_type, MessageType::RequestNoReturn);
        assert_eq!(msg.0.ret_code, ReturnCode::Ok);
        assert!(msg.0.tp_header.is_none());
        assert_eq!(msg.1, [0xa1u8, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8,
            0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8,].as_ref());
    }

    #[test]
    fn decode_someip_header2() {
        let mut decoder = SomeipDecoder::new();
        let mut b1 = BytesMut::from([
            0x01u8, 0x02, 0x03, 0x04,       // message id: 0x01020304
            0x00, 0x00, 0x00, 0x18,       // length: 24 bytes
        ].as_ref());

        let r1 = decoder.decode(&mut b1);
        assert!(r1.is_ok() && r1.unwrap().is_none());

        b1.extend_from_slice([
            0x32u8, 0x33, 0x34, 0x35,       // request id: 0x32333435
            0x01, 0x12, 0x01, 0x00,       // proto: 1, intf: 18, msg_type: RequestNoReturn, return: Ok
            0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8,
            0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8,
            0x99
        ].as_ref());

        let r2 = decoder.decode(&mut b1);
        assert!(r2.is_ok() && r2.as_ref().unwrap().is_some());

        let msg = r2.unwrap().unwrap();

        assert_eq!(msg.0.message_id, MessageId::from(0x01020304));
        assert_eq!(msg.0.length, 24);
        assert_eq!(msg.0.request_id, RequestId::from(0x32333435));
        assert_eq!(msg.0.proto_version, ProtocolVersion::Version1);
        assert_eq!(msg.0.intf_version, InterfaceVersion::from(18));
        assert_eq!(msg.0.msg_type, MessageType::RequestNoReturn);
        assert_eq!(msg.0.ret_code, ReturnCode::Ok);
        assert_eq!(msg.1, [0xa1u8, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8,
            0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8,].as_ref());

        let r3 = decoder.decode(&mut b1);
        assert!(r3.is_ok() && r3.unwrap().is_none());
    }

    #[test]
    fn decode_someip_header3() {
        let mut decoder = SomeipDecoder::new();
        let b = [
            0x01u8, 0x02, 0x03, 0x04,       // message id: 0x01020304
            0x00, 0x00, 0x00, 0x18,       // length: 24 bytes
            0x32, 0x33, 0x34, 0x35,       // request id: 0x32333435
            0x04, 0x12, 0x01, 0x00,       // proto: 1, intf: 18, msg_type: RequestNoReturn, return: Ok
            0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8,
            0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8,
            0x99
        ].as_ref();
        let mut ba: BytesMut = BytesMut::from(b);

        let res = decoder.decode(&mut ba);
        assert!(res.is_err());
        match res.err().unwrap() {
            SomeipWireError::UnsupportedProtocolVersion => {}
            _ => { assert!(false, "expected UnsupportedProtocolVersion error")}
        }
    }

    #[test]
    fn decode_someip_header4() {
        let mut decoder = SomeipDecoder::new();
        let b = [
            0x01u8, 0x02, 0x03, 0x04,       // message id: 0x01020304
            0x00, 0x00, 0x00, 0x01,       // length: 1 bytes
            0x32, 0x33, 0x34, 0x35,       // request id: 0x32333435
            0x01, 0x12, 0x01, 0x00,       // proto: 1, intf: 18, msg_type: RequestNoReturn, return: Ok
            0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8,
            0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8,
            0x99
        ].as_ref();
        let mut ba: BytesMut = BytesMut::from(b);

        let res = decoder.decode(&mut ba);
        assert!(res.is_err());
        match res.err().unwrap() {
            SomeipWireError::LengthFieldErrorToShort => {}
            _ => { assert!(false, "expected LengthFieldErrorToShort error")}
        }
    }

    #[test]
    fn decode_someip_header5() {
        let mut decoder = SomeipDecoder::new();
        let b = [
            0x01u8, 0x02, 0x03, 0x04,       // message id: 0x01020304
            0x20, 0x00, 0x00, 0x24,       // length: 1 bytes
            0x32, 0x33, 0x34, 0x35,       // request id: 0x32333435
            0x01, 0x12, 0x01, 0x00,       // proto: 1, intf: 18, msg_type: RequestNoReturn, return: Ok
            0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8,
            0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8,
            0x99
        ].as_ref();
        let mut ba: BytesMut = BytesMut::from(b);

        let res = decoder.decode(&mut ba);
        assert!(res.is_err());
        match res.err().unwrap() {
            SomeipWireError::ExceedingMaxFrameSize => {}
            _ => { assert!(false, "expected ExceedingMaxFrameSize error")}
        }
    }

    #[test]
    fn decode_someip_header6() {
        let mut decoder = SomeipDecoder::new();
        let mut b1 = BytesMut::from([
            0x01u8, 0x02, 0x03, 0x04,       // message id: 0x01020304
            0x00, 0x00, 0x00, 0x18,       // length: 24 bytes
            0x32u8, 0x33, 0x34, 0x35,       // request id: 0x32333435
            0x01, 0x12, 0x01, 0x00,       // proto: 1, intf: 18, msg_type: RequestNoReturn, return: Ok
            0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8,

        ].as_ref());

        let r1 = decoder.decode(&mut b1);
        assert!(r1.is_ok() && r1.unwrap().is_none());

        b1.extend_from_slice([
            0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8,
            0x99
        ].as_ref());

        let r2 = decoder.decode(&mut b1);
        assert!(r2.is_ok() && r2.as_ref().unwrap().is_some());

        let msg = r2.unwrap().unwrap();

        assert_eq!(msg.0.message_id, MessageId::from(0x01020304));
        assert_eq!(msg.0.length, 24);
        assert_eq!(msg.0.request_id, RequestId::from(0x32333435));
        assert_eq!(msg.0.proto_version, ProtocolVersion::Version1);
        assert_eq!(msg.0.intf_version, InterfaceVersion::from(18));
        assert_eq!(msg.0.msg_type, MessageType::RequestNoReturn);
        assert_eq!(msg.0.ret_code, ReturnCode::Ok);
        assert_eq!(msg.1, [0xa1u8, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8,
            0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8,].as_ref());

        let r3 = decoder.decode(&mut b1);
        assert!(r3.is_ok() && r3.unwrap().is_none());
    }

    #[test]
    fn decode_someip_header_tp1() {
        let mut decoder = SomeipDecoder::new();
        let mut b1 = BytesMut::from([
            0x01u8, 0x02, 0x03, 0x04,       // message id: 0x01020304
            0x00, 0x00, 0x00, 0x14,       // length: 20 bytes
            0x32u8, 0x33, 0x34, 0x35,       // request id: 0x32333435
            0x01, 0x12, 0x21, 0x00,       // proto: 1, intf: 18, msg_type: TpRequestNoReturn, return: Ok
            0x00, 0x00, 0x01, 0x41,        // TP header
            0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8,
        ].as_ref());

        let r2 = decoder.decode(&mut b1);
        assert!(r2.is_ok() && r2.as_ref().unwrap().is_some());

        let msg = r2.unwrap().unwrap();
        assert_eq!(msg.0.msg_type, MessageType::TpRequestNoReturn);
        assert_eq!(msg.0.tp_header, Some(TpHeader{offset: 0x14 , more: true}));
        assert_eq!(msg.1, [0xa1u8, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8].as_ref());

        let r3 = decoder.decode(&mut b1);
        assert!(r3.is_ok() && r3.unwrap().is_none());
    }

    #[test]
    fn decode_someip_header_tp2() {
        let mut decoder = SomeipDecoder::new();
        let mut b1 = BytesMut::from([
            0x01u8, 0x02, 0x03, 0x04,       // message id: 0x01020304
            0x00, 0x00, 0x00, 0x14,       // length: 20 bytes
            0x32u8, 0x33, 0x34, 0x35,       // request id: 0x32333435
            0x01, 0x12, 0x21, 0x00,       // proto: 1, intf: 18, msg_type: TpRequestNoReturn, return: Ok
            0x00, 0x00].as_ref());

        let r1 = decoder.decode(&mut b1);
        assert!(r1.is_ok() && r1.unwrap().is_none());

        b1.extend_from_slice([0x01, 0x41,        // TP header pt 1
            0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8,
        ].as_ref());

        let r2 = decoder.decode(&mut b1);
        assert!(r2.is_ok() && r2.as_ref().unwrap().is_some());

        let msg = r2.unwrap().unwrap();
        assert_eq!(msg.0.msg_type, MessageType::TpRequestNoReturn);
        assert_eq!(msg.0.tp_header, Some(TpHeader{offset: 0x14 , more: true}));
        assert_eq!(msg.1, [0xa1u8, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8].as_ref());

        let r3 = decoder.decode(&mut b1);
        assert!(r3.is_ok() && r3.unwrap().is_none());
    }

    #[test]
    fn decode_someip_header_tp3() {
        let mut decoder = SomeipDecoder::new();
        let mut b1 = BytesMut::from([
            0x01u8, 0x02, 0x03, 0x04,       // message id: 0x01020304
            0x00, 0x00, 0x00, 0x14,       // length: 20 bytes
            0x32u8, 0x33, 0x34, 0x35,       // request id: 0x32333435
            0x01, 0x12, 0x21, 0x00,       // proto: 1, intf: 18, msg_type: TpRequestNoReturn, return: Ok
            0x00, 0x00].as_ref());

        let r1 = decoder.decode(&mut b1);
        assert!(r1.is_ok() && r1.unwrap().is_none());

        b1.extend_from_slice([0x01, 0x41,        // TP header pt 1
            0xa1, 0xa2, 0xa3].as_ref());

        let r1a = decoder.decode(&mut b1);
        assert!(r1a.is_ok() && r1a.unwrap().is_none());

        b1.extend_from_slice([0xa4, 0xa5, 0xa6, 0xa7, 0xa8,
        ].as_ref());

        let r2 = decoder.decode(&mut b1);
        assert!(r2.is_ok() && r2.as_ref().unwrap().is_some());

        let msg = r2.unwrap().unwrap();
        assert_eq!(msg.0.msg_type, MessageType::TpRequestNoReturn);
        assert_eq!(msg.0.tp_header, Some(TpHeader{offset: 0x14 , more: true}));
        assert_eq!(msg.1, [0xa1u8, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8].as_ref());

        let r3 = decoder.decode(&mut b1);
        assert!(r3.is_ok() && r3.unwrap().is_none());
    }
}