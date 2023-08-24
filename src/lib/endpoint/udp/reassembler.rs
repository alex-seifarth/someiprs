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
use std::os::unix::raw::mode_t;
use bytes::{Bytes};
use crate::endpoint::someip;
use crate::endpoint::types;

/// Scale factor for the TP header's offset value
pub const SOMEIP_TP_OFFSET_SCALE: usize = 16;

/// Removes the segmentation artifacts from the header, corrects the length field
/// and sets the return code.
pub fn finish_reassembled_header(msg: &mut someip::Message) {
    msg.header.tp_header = None;
    msg.header.msg_type = msg.header.msg_type.strip_tp();
    msg.header.length = msg.header.calc_length(msg.payload.len());
}

/// A [ReassemblyKey] uniquely identifies a single reassembly task of segmented SOME/IP messages.
pub type ReassemblyKey = (SocketAddr,
                          someip::MessageId,
                          someip::InterfaceVersion,
                          someip::RequestId,
                          someip::MessageType,
                          someip::ProtocolVersion);

/// Creates a reassembly key from the peer's socket address and the message header.
pub fn make_reassembly_key(peer: &SocketAddr, header: &someip::Header) -> ReassemblyKey {
    (peer.clone(), header.message_id.clone(), header.intf_version.clone(), header.request_id.clone(),
     header.msg_type.clone(), header.proto_version.clone())
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum ReassemblyMode {
    Up,
    Down,
    Unknown
}

/// Reassembler for segmented SOME/IP messages.
pub struct Reassembler {
    /// Time to live
    ttl: u8,
    /// Reset value for ttl
    init_ttl: u8,
    /// maximum payload size for this message
    max_payload_size: usize,
    /// initial header -> used to build the header of the reassembled message
    header: someip::Header,
    /// payload buffer
    payload: Vec<u8>,
    /// direction of reassembly
    mode: ReassemblyMode,
    /// next expected offset (in bytes)
    ///     for mode == Up this points to the last byte after of the last received segment
    ///     for mode == Down this points to the first byte of the last received segment
    next_offset: usize,
}

impl Reassembler {

    /// Creates a new empty reassembler with buffer for the payload.
    /// #Args
    /// - `init_buffer_size`    The initial payload buffer size.
    /// - `max_payload_size`    The maximum allowed payload size.
    /// - `init_ttl`            The start time to live value. See [tick()]
    pub fn new(init_buffer_size: usize,
               max_payload_size: usize,
               init_ttl: u8,
               header: &someip::Header) -> Self
    {
        Reassembler{
            ttl: init_ttl,
            init_ttl,
            max_payload_size,
            header: header.clone(),
            payload: Vec::with_capacity(init_buffer_size),
            mode: ReassemblyMode::Unknown,
            next_offset: 0
        }
    }

    /// Process a new incoming segment for the reassembly.
    pub fn process_segment(&mut self, msg: someip::Message) -> types::Result<()> {
        assert!(msg.header.tp_header.is_some());
        let tph = msg.header.tp_header.as_ref().unwrap();

        if self.mode == ReassemblyMode::Unknown {
            self.set_mode(tph, msg.payload.len());
        }

        let start = tph.offset as usize * SOMEIP_TP_OFFSET_SCALE;
        let end = start + msg.payload.len();
        // CHECK: max allowed payload size exceeded
        if end > self.max_payload_size {
            return Err(types::Error::MaxPayloadSizeExceeded(msg.header));
        }

        assert_ne!(self.mode, ReassemblyMode::Unknown);
        // CHECK: no missing segments while reassembling (reordering not supported)
        if (self.mode == ReassemblyMode::Up && start > self.next_offset) ||
            (self.mode == ReassemblyMode::Down && end < self.next_offset)
        {
            return Err(types::Error::UdpSegmentationHoleDetected(msg.header));
        }

        // extend payload buffer if necessary to hold the new segment and then copy and update next_offset
        if end > self.payload.len() {
            self.payload.resize(end, 0);
        }
        self.payload.as_mut_slice()[start..end].copy_from_slice(msg.payload.as_ref());
        if self.mode == ReassemblyMode::Up {
            self.next_offset = end;
        } else {
            self.next_offset = start;
        }

        // reset timeout = ttl
        self.ttl = self.init_ttl;

        // store the last return code -> the latest one is then used to finish the reassembly
        self.header.ret_code = msg.header.ret_code;
        Ok(())
    }

    /// Finishes the reassembly of the segments received so far and returns
    /// a SOME/IP message of the whole packet without reassembly related artifacts:
    /// - message type is non-TP,
    /// - no TP header,
    /// - length field for the whole payload,
    /// - return code of the last received segment.
    pub fn finish(self) -> types::Result<someip::Message> {
        let mut msg = someip::Message{
            header: self.header,
            payload: Bytes::from(self.payload)
        };
        finish_reassembled_header(&mut msg);
        Ok(msg)
    }

    /// Decrements the time to live `ttl` field and returns `false` if the `ttl` is not already `0`
    /// otherwise returns `terue`.
    pub fn tick(&mut self) -> bool {
        if self.ttl == 0 {
            return true
        }
        self.ttl -= 1;
        false
    }

    /// Sets up/down reassembly mode and inits the next_offset value.
    /// This should be called on the first received segment only.
    fn set_mode(&mut self, tph: &someip::TpHeader, payload_len: usize) {
        if tph.offset > 0 {
            self.mode = ReassemblyMode::Down;
            self.next_offset = payload_len + (tph.offset as usize * SOMEIP_TP_OFFSET_SCALE);
        } else {
            self.mode = ReassemblyMode::Up;
            self.next_offset = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use bytes::BytesMut;
    use super::*;

    fn make_default_header() -> someip::Header {
        someip::Header{
            message_id: someip::MessageId::from(0x01020304),
            length: 0,
            request_id: someip::RequestId::from(0xc1c28080),
            proto_version: someip::ProtocolVersion::Version1,
            intf_version: someip::InterfaceVersion::from(1),
            msg_type: someip::MessageType::TpRequestNoReturn,
            ret_code: someip::ReturnCode::Ok,
            tp_header: Some( someip::TpHeader{ offset: 0, more: false} ),
        }
    }

    fn make_message(len: usize, offset: u32, more: bool, value: u8) -> someip::Message {
        let mut hdr = make_default_header();
        hdr.tp_header.as_mut().unwrap().more = more;
        hdr.tp_header.as_mut().unwrap().offset = offset;
        hdr.length  = hdr.calc_length(len);
        let mut data = BytesMut::zeroed(len);
        data.fill(value);
        someip::Message{ header: hdr, payload: data.freeze()}
    }

    #[test]
    fn reassemble_tick_resurrected() {
        let msg1 = make_message(64,0, true, 0xa1);
        let msg2 = make_message(32, 4, true, 0xb0);
        let msg3 = make_message(128, 6, true, 0xcf);

        let mut ra = Reassembler::new(1024, 4096, 5, &msg1.header);
        assert!( ra.process_segment(msg1).is_ok() );
        assert!( ra.process_segment(msg2).is_ok() );

        assert!(!ra.tick());
        assert!(!ra.tick());
        assert!(!ra.tick());
        assert!(!ra.tick());
        assert!(!ra.tick());
        assert!( ra.process_segment(msg3).is_ok() );
        assert!(!ra.tick());
        assert!(ra.finish().is_ok());
    }

    #[test]
    fn reassemble_tick_death() {
        let msg1 = make_message(64,0, true, 0xa1);
        let msg2 = make_message(32, 4, true, 0xb0);
        let msg3 = make_message(128, 7, true, 0xcf);

        let mut ra = Reassembler::new(1024, 4096, 5, &msg1.header);
        assert!( ra.process_segment(msg1).is_ok() );
        assert!( ra.process_segment(msg2).is_ok() );

        assert!(!ra.tick());
        assert!(!ra.tick());
        assert!(!ra.tick());
        assert!(!ra.tick());
        assert!(!ra.tick());
        assert!(ra.tick());
        assert!(ra.tick());
    }

    #[test]
    fn reassemble_hole_detected() {
        let msg1 = make_message(64,0, true, 0xa1);
        let msg2 = make_message(32, 4, true, 0xb0);
        let msg3 = make_message(128, 7, true, 0xcf);

        let mut ra = Reassembler::new(1024, 4096, 5, &msg1.header);
        assert!( ra.process_segment(msg1).is_ok() );
        assert!( ra.process_segment(msg2).is_ok() );

        if let Err(types::Error::UdpSegmentationHoleDetected(header)) = ra.process_segment(msg3) {
            assert_eq!(header.message_id, someip::MessageId::from(0x01020304));
            assert_eq!(header.request_id, someip::RequestId::from(0xc1c28080));
            assert_eq!(header.proto_version, someip::ProtocolVersion::Version1);
            assert_eq!(header.intf_version, someip::InterfaceVersion::from(1));
            assert_eq!(header.msg_type, someip::MessageType::TpRequestNoReturn);
        }
        else {
            panic!("no error returned from message 3.")
        }
    }

    #[test]
    fn reassemble_exceeding_max_size() {
        let msg1 = make_message(64,0, true, 0xa1);
        let msg2 = make_message(32, 4, true, 0xb0);
        let msg3 = make_message(128, 6, false, 0xcf);

        let mut ra = Reassembler::new(128, 190, 5, &msg1.header);
        assert!( ra.process_segment(msg1).is_ok() );
        assert!( ra.process_segment(msg2).is_ok() );

        if let Err(types::Error::MaxPayloadSizeExceeded(header)) = ra.process_segment(msg3) {
            assert_eq!(header.message_id, someip::MessageId::from(0x01020304));
            assert_eq!(header.request_id, someip::RequestId::from(0xc1c28080));
            assert_eq!(header.proto_version, someip::ProtocolVersion::Version1);
            assert_eq!(header.intf_version, someip::InterfaceVersion::from(1));
            assert_eq!(header.msg_type, someip::MessageType::TpRequestNoReturn);
        }
        else {
            panic!("no error returned from message 3.")
        }
    }

    #[test]
    fn reassemble_3segments_down_ok() {
        let msg3 = make_message(64,0, false, 0xa1);
        let msg2 = make_message(32, 4, true, 0xb0);
        let msg1 = make_message(128, 6, true, 0xcf);

        let mut ra = Reassembler::new(1024, 4096, 5, &msg1.header);
        assert!( ra.process_segment(msg1).is_ok() );
        assert!( ra.process_segment(msg2).is_ok() );
        assert!( ra.process_segment(msg3).is_ok() );

        let result = ra.finish();
        assert!(result.is_ok());
        let msg = result.unwrap();
        assert_eq!(msg.header.message_id, someip::MessageId::from(0x01020304));
        assert_eq!(msg.header.length, 64usize + 32usize + 128usize + someip::SOMEIP_HEADER_LEN_PART);
        assert_eq!(msg.header.request_id, someip::RequestId::from(0xc1c28080));
        assert_eq!(msg.header.proto_version, someip::ProtocolVersion::Version1);
        assert_eq!(msg.header.intf_version, someip::InterfaceVersion::from(1));
        assert_eq!(msg.header.msg_type, someip::MessageType::RequestNoReturn);
        assert_eq!(msg.header.ret_code, someip::ReturnCode::Ok);
        assert!(msg.header.tp_header.is_none());
        assert_eq!(msg.payload.len(), 224);
        assert_eq!(msg.payload.as_ref()[0], 0xa1);
        assert_eq!(msg.payload.as_ref()[64], 0xb0);
        assert_eq!(msg.payload.as_ref()[96], 0xcf);
    }

    #[test]
    fn reassemble_3segments_up_ok() {
        let msg1 = make_message(64,0, true, 0xa1);
        let msg2 = make_message(32, 4, true, 0xb0);
        let msg3 = make_message(128, 6, false, 0xcf);

        let mut ra = Reassembler::new(1024, 4096, 5, &msg1.header);
        assert!( ra.process_segment(msg1).is_ok() );
        assert!( ra.process_segment(msg2).is_ok() );
        assert!( ra.process_segment(msg3).is_ok() );

        let result = ra.finish();
        assert!(result.is_ok());
        let msg = result.unwrap();
        assert_eq!(msg.header.message_id, someip::MessageId::from(0x01020304));
        assert_eq!(msg.header.length, 64usize + 32usize + 128usize + someip::SOMEIP_HEADER_LEN_PART);
        assert_eq!(msg.header.request_id, someip::RequestId::from(0xc1c28080));
        assert_eq!(msg.header.proto_version, someip::ProtocolVersion::Version1);
        assert_eq!(msg.header.intf_version, someip::InterfaceVersion::from(1));
        assert_eq!(msg.header.msg_type, someip::MessageType::RequestNoReturn);
        assert_eq!(msg.header.ret_code, someip::ReturnCode::Ok);
        assert!(msg.header.tp_header.is_none());
        assert_eq!(msg.payload.len(), 224);
        assert_eq!(msg.payload.as_ref()[0], 0xa1);
        assert_eq!(msg.payload.as_ref()[64], 0xb0);
        assert_eq!(msg.payload.as_ref()[96], 0xcf);
    }
}