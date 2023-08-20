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
use crate::util::interval;
use bytes::{Bytes};

/// Errors from segmentation processing
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum SegmentationError {
    ExceedingMaxSize,
    SegmentSizeError{offset: u32, len: usize},
    MissingSegment,
    MultipleFinalSegments,
}

/// Default capacity allocated for the buffer to store the segmented message payloads.
pub const DEFAULT_INITIAL_BUFFER_CAPACITY: usize = 16 * 1024;

/// Default maximum value for the whole message payload length.
pub const DEFAULT_MAX_SEGMENTATION_PAYLOAD_SIZE: usize = 64*1024;

/// Scale for the offset value. PRS_SOMEIP_00725, PRS_SOMEIP_00729
const SEGMENT_OFFSET_SCALE: usize = 16;

/// Buffer and context data for SOME/IP TP segmented message reassembly.
pub struct DesegmentationTask {
    key: SegmentationKey,
    header: SomeipMessageHeader,
    segments: Vec<(usize, usize)>, // segment intervals (start, end)
    payload: Vec<u8>,
    max_payload_size: usize,
    final_received: bool,
}

impl DesegmentationTask {

    /// Creates a new segmentation task with the default maximum payload size.
    pub fn new(header: SomeipMessageHeader) -> Self {
        DesegmentationTask::new_with_max_size(header,
                              DEFAULT_MAX_SEGMENTATION_PAYLOAD_SIZE,
                              DEFAULT_INITIAL_BUFFER_CAPACITY)
    }

    /// Creates a new segmentation task.
    pub fn new_with_max_size(header: SomeipMessageHeader,
                             max_payload_size: usize,
                             init_payload_buffer: usize) -> Self {
        let mut sheader = header.clone();
        sheader.msg_type = sheader.msg_type.strip_tp();
        sheader.tp_header = None;

        DesegmentationTask {
            key: make_key(&header),
            header: sheader,
            segments: Vec::with_capacity(8),
            payload: Vec::with_capacity(init_payload_buffer),
            max_payload_size,
            final_received: false,
        }
    }

    /// Returns the segmentation task key.
    pub fn key(&self) -> &SegmentationKey {
        &self.key
    }

    /// Add a new segmented message to the task.
    /// This will store the message's payload in the [DesegmentationTask]
    /// Error checks:
    /// - non-final segment length is not a multiple of 16 (PRS_SOMEIP_00754),
    /// - multiple final segments received,
    /// - maximum buffer capacity exceeded,
    pub fn add_segment(&mut self, offset: u32, data: Bytes, fin: bool) -> Result<(), SegmentationError> {
        if fin {
            if self.final_received {
                return Err( SegmentationError::MultipleFinalSegments)
            }
            self.final_received = true;
        } else {
            if data.len() % SEGMENT_OFFSET_SCALE != 0 {
                return Err( SegmentationError::SegmentSizeError {offset, len: data.len()} )
            }
        }

        // check current buffer size and copy data
        let start_of_data = (offset as usize) * SEGMENT_OFFSET_SCALE;
        let end_of_data = start_of_data + data.len();
        if end_of_data > self.max_payload_size {
            return Err( SegmentationError::ExceedingMaxSize )
        }
        if self.payload.len() < end_of_data {
            self.payload.resize(end_of_data, 0);
        }
        self.payload.as_mut_slice()[start_of_data..end_of_data].copy_from_slice(data.as_ref());

        // bookkeeping for the segment ranges
        self.segments = interval::merge_new(&self.segments, (start_of_data, end_of_data-1));
        Ok(())
    }

    /// Finish the task and return the resulting assembled message or an error.
    pub fn finish(mut self, ret_code: ReturnCode) -> Result<(SomeipMessageHeader, Bytes), SegmentationError> {
        if self.segments.len() != 1 {
            return Err( SegmentationError::MissingSegment )
        }
        let s = self.segments.first().unwrap();
        if s.0 != 0 {
            return Err( SegmentationError::MissingSegment )
        }
        // truncate payload to the really transmitted payload size
        debug_assert!(self.payload.len() > s.1);  // NOTE s.1 is the last index!!
        self.payload.resize(s.1 + 1, 0);
        self.header.ret_code = ret_code;
        self.header.length = self.payload.len() + SOMEIP_HEADER_LEN_PART;
        Ok( (self.header, Bytes::from(self.payload)) )
    }
}

#[cfg(test)]
mod tests {
    use bytes::BytesMut;
    use super::*;

    fn header() -> SomeipMessageHeader {
        SomeipMessageHeader {
            message_id: MessageId::from(0x12345678),
            length: 228,    // not relevant here
            request_id: RequestId::from(0xabcdef99),
            proto_version: ProtocolVersion::Version1,
            intf_version: InterfaceVersion::from(7),
            msg_type: MessageType::TpResponse,
            ret_code: ReturnCode::E2eNoNewData,
            tp_header: Some( SomeipTpHeader {offset: 0, more: false} ),
        }
    }

    #[test]
    fn assembly_success_2segments() {
        let mut st = DesegmentationTask::new(header());
        assert_eq!(st.key(), &(MessageId::from(0x12345678), ClientId::from(0xabcd),
           MessageType::Response, ProtocolVersion::Version1, InterfaceVersion::from(7)));

        let d1 = Bytes::from(b"this is a text m".as_ref());
        let d2 = Bytes::from(b"essage.".as_ref());

        let r = st.add_segment(0, d1, false);
        assert_eq!(r, Ok(()));
        let r = st.add_segment(1, d2, true);
        assert_eq!(r, Ok(()));

        let r = st.finish(ReturnCode::Ok);
        assert!(r.is_ok());
        let (header, data) = r.unwrap();
        assert_eq!(header.message_id, MessageId::from(0x12345678));
        assert_eq!(header.length, data.len() + SOMEIP_HEADER_LEN_PART);
        assert_eq!(header.request_id, RequestId::from(0xabcdef99));
        assert_eq!(header.proto_version, ProtocolVersion::Version1);
        assert_eq!(header.intf_version, InterfaceVersion::from(7));
        assert_eq!(header.msg_type, MessageType::Response);
        assert_eq!(header.ret_code, ReturnCode::Ok);
        assert!(header.tp_header.is_none());
        assert_eq!(data, b"this is a text message.".as_ref());
    }

    #[test]
    fn assembly_success_4segments_disordered() {
        let mut st = DesegmentationTask::new(header());
        assert_eq!(st.key(), &(MessageId::from(0x12345678), ClientId::from(0xabcd),
                               MessageType::Response, ProtocolVersion::Version1, InterfaceVersion::from(7)));

        let d1 = Bytes::from(b"This is a text m".as_ref());
        let d2 = Bytes::from(b"essage. A non-sense story about ".as_ref());
        let d3 = Bytes::from(b"a desparate engineer fighting ag".as_ref());
        let d4 = Bytes::from(b"ainst modern programmers.".as_ref());

        assert_eq!(st.add_segment(1, d2, false), Ok(()));
        assert_eq!(st.add_segment(0, d1, false), Ok(()));
        assert_eq!(st.add_segment(3, d3, false), Ok(()));
        assert_eq!(st.add_segment(5, d4, true), Ok(()));

        let r = st.finish(ReturnCode::Ok);
        assert!(r.is_ok());
        let (_, data) = r.unwrap();
        assert_eq!(data, b"This is a text message. A non-sense story about a desparate engineer fighting against modern programmers.".as_ref());
    }

    #[test]
    fn assembly_fail_size16() {
        let mut st = DesegmentationTask::new(header());

        let d1 = Bytes::from(b"this is a text m".as_ref());
        let d2 = Bytes::from(b"essage.".as_ref());

        let r = st.add_segment(0, d1, false);
        assert_eq!(r, Ok(()));
        let r = st.add_segment(1, d2, false);
        assert_eq!(r, Err(SegmentationError::SegmentSizeError{ len: 7, offset: 1 }));
    }

    #[test]
    fn assembly_fail_too_big() {
        let mut st = DesegmentationTask::new(header());

        let d1 = Bytes::from(b"this is a text m".as_ref());
        let d2 = Bytes::from(b"essage. Some non".as_ref());
        let d3 = BytesMut::zeroed(DEFAULT_MAX_SEGMENTATION_PAYLOAD_SIZE + 32).freeze();

        let r = st.add_segment(0, d1, false);
        assert_eq!(r, Ok(()));
        let r = st.add_segment(1, d2, false);
        assert_eq!(r, Ok(()));
        let r = st.add_segment(2, d3, false);
        assert_eq!(r, Err(SegmentationError::ExceedingMaxSize));
    }
}
