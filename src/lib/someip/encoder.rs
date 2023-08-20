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
use crate::someip::types::*;
use crate::util::coder::Encoder;
use bytes::{BytesMut, Bytes};
use std::marker::PhantomData;

/// Encoder for SOME/IP messages
pub struct SomeipEncoder<'a> {
    max_frame_size: usize,
    _p : PhantomData<&'a ()>
}

impl<'a> SomeipEncoder<'a> {
    pub fn new() -> Self {
        SomeipEncoder{ max_frame_size: DEFAULT_MAX_FRAME_SIZE, _p: PhantomData::default() }
    }
}

impl<'a> Encoder for SomeipEncoder<'a> {
    type Message = (&'a SomeipMessageHeader, &'a Bytes);
    type Error = SomeipWireError;

    fn encode(&mut self, msg: &Self::Message, buf: &mut BytesMut) -> Result<(), SomeipWireError> {
        let len = msg.0.header_size() + msg.1.len();
        if len > self.max_frame_size {
            return Err(SomeipWireError::ExceedingMaxFrameSize)
        }
        buf.reserve(len);
        msg.0.write_to(buf, msg.1.len());
        buf.extend_from_slice(msg.1.as_ref());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_someip1() {
        let payload = Bytes::from([0xa0u8, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5].as_ref());
        let msg = SomeipMessageHeader {
            message_id: MessageId::from(0x00221100),
            length: 0, //irrelevant for encoding
            request_id: RequestId::from(0x8899b1b2),
            proto_version: ProtocolVersion::Version1,
            intf_version: InterfaceVersion::from(2),
            msg_type: MessageType::Request,
            ret_code: ReturnCode::Ok,
            tp_header: None
        };
        let mut buf = BytesMut::with_capacity(1024);
        let mut encoder = SomeipEncoder::new();

        let res = encoder.encode(&(&msg, &payload), &mut buf);
        assert!(res.is_ok());

        assert_eq!(buf.as_ref(), &[0x00u8, 0x22, 0x11, 0x00,
                                    0x00,  0x00, 0x00, 0x0e,
                                    0x88, 0x99, 0xb1, 0xb2,
                                    0x01, 0x02, 0x00, 0x00,
                                    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5]);

    }


}

