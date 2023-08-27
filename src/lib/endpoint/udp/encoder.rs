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

use std::cmp::min;
use std::time::{Duration, Instant};
use bytes::BytesMut;
use crate::endpoint::someip;
use crate::endpoint::someip::TpHeader;

/// Maximum payload size for a UDP datagram filled with SOME/IP messages
/// PRS_SOMEIP_00730 (note the constant includes the maximum header size)
pub const DEFAULT_MAX_DATAGRAM_SIZE: usize = 1420;

/// Relative threshold from maximum datagram size, when datagram is filled enough.
const DATAGRAM_TX_THRESHOLD: f32 = 0.8; // in %

/// If the due time (retention) of a message is less than this away from `now` -> send the
/// pending train and do not wait anymore.
pub const MIN_RETENTION_TIME: Duration = Duration::from_micros(200);

/// Encoder for SOME/IP messages into UDP datagrams
/// - all messages must fit into the maximum allowed frame size (1420 bytes)
/// - retention: messages can be held back when only small frame would be sent to bundle with further messages.
pub struct Encoder {
    /// Maximum datagram size for this [Encoder] instance.
    max_datagram_size: usize,
    /// Next scheduled transmission due to held back messages (retention)
    next_schedule: Option<Instant>,
    /// Threshold fill level when datagram is considered to be full enough.
    datagram_fill_threshold: usize,
    /// waiting messages (retention; datagram not filled enough)
    waiting: Vec<someip::Message>,
    /// size of waiting messages (in the datagram)
    waiting_size: usize,
    /// buffer for completed datagrams
    completed: Vec<BytesMut>,
    /// maximum segment payload length
    seg_pl_len: usize,
    /// how many offset (TP segment) fit into seg_pl_len
    offset_factor: u32,
}

impl Encoder {

    /// Creates a new [Encoder] object with default configuration.
    pub fn new_default() -> Self {
        Encoder::new(DEFAULT_MAX_DATAGRAM_SIZE)
    }

    /// Creates new [Encoder].
    /// #Args
    /// - `max_datagram_size`         Maximum datagram size.
    pub fn new(max_datagram_size: usize) -> Self
    {
        let seg_pl_len = calc_pl_seg_len(max_datagram_size);
        Encoder{ max_datagram_size,
            next_schedule: None,
            waiting: Vec::new(),
            waiting_size: 0usize,
            completed: Vec::new(),
            datagram_fill_threshold: ((max_datagram_size as f32) * DATAGRAM_TX_THRESHOLD) as usize,
            seg_pl_len,
            offset_factor: calc_offset_scale(seg_pl_len)
        }
    }

    /// Returns the time when the [Encoder] should be run with or without
    /// new messages to transmit to send held back messages.
    pub fn next_schedule(&self) -> Option<Instant> {
        self.next_schedule
    }

    /// Returns the maximum datagram size for this [Encoder]
    pub fn max_datagram_size(&self) -> usize {
        self.max_datagram_size
    }

    /// Finishes the pending messages, returns `true` when there are completed datagrams.
    pub fn schedule(&mut self) -> bool {
        self.finish_waiting();
        !self.is_completed_empty()
    }

    /// Processes the a new message `msg` for transmission.
    /// #Args
    /// - `msg`                 The new message. If too big for one datagram it will be segmented.
    /// - `retention_time`      The maximum time the new message can be held back to fill the datagram.
    /// #Returns
    /// The message returns `true` when completed datagrams are availale (see `get_completed()`),
    /// otherwise `false` is returned.
    pub fn prepare_msg(&mut self, msg: someip::Message, retention_time: Duration) -> bool {
        if someip::final_msg_size(&msg) > self.max_datagram_size {
            let segs = segment_msg(msg, self.seg_pl_len, self.offset_factor);
            for segm in segs {
                self.prepare_msg_int(segm, retention_time.clone());
            }
            !self.is_completed_empty()
        } else {
            self.prepare_msg_int(msg, retention_time)
        }
    }

    /// Processes a new message for transmission and returns `true` when at least one completed
    /// datagram is waiting.
    fn prepare_msg_int(&mut self, mut msg: someip::Message, retention_time: Duration) -> bool {
        let due = Instant::now() + retention_time;
        let len = someip::final_msg_size(&msg);
        if len > self.max_datagram_size {
            log::error!("Encoder received message that exceeds maximum datagram size.");
            return !self.is_completed_empty();
        }
        someip::fix_length(&mut msg);

        // check in whether we have still place in the actually pending train
        if self.waiting_size + len >= self.max_datagram_size {
            // no place left in the pending train -> finish it
            self.finish_waiting();
        }
        self.waiting.push(msg);
        self.waiting_size += len;
        match self.next_schedule.as_ref() {
            None => self.next_schedule = Some(due),
            Some(d) => {
                if *d > due {
                    self.next_schedule = Some(due)
                }
            }
        }

        // check whether the datagram is already filled over the threshold or next schedule
        // (old and new) are not too far away
        assert!(self.next_schedule.is_some());
        let next_due = self.next_schedule.as_ref().unwrap().clone();
        let now = Instant::now();
        let due_now = (next_due < now) || (next_due - now < MIN_RETENTION_TIME);
        if due_now || self.waiting_size >= self.datagram_fill_threshold {
            self.finish_waiting();
        }
        return !self.is_completed_empty()
    }

    /// Takes all the waiting messages (e.g. the pending train) and assembles them into a
    /// buffer that should be sent then as datagram.
    /// The resulting buffer is stored in the object's [completed] field - the client must
    /// retrieve it itself.
    fn finish_waiting(&mut self) {
        if self.waiting_size > 0 {
            let mut dgrm = BytesMut::with_capacity(self.waiting_size);
            for msg in self.waiting.drain(..) {
                msg.header.write_to(&mut dgrm);
                dgrm.extend_from_slice(msg.payload.as_ref());
            }
            self.completed.push(dgrm);
            self.waiting_size = 0;
            self.next_schedule = None;
        }
        assert!(self.waiting.is_empty());
    }

    /// Returns `true` when there are no completed datagrams.
    pub fn is_completed_empty(&self) -> bool {
        self.completed.is_empty()
    }

    /// Returns the currently completed datagrams.
    pub fn get_completed(&mut self) -> Vec<BytesMut> {
        std::mem::take( &mut self.completed )
    }
}

/// Segments a single SOME/IP message into multiple segments fitting into the maximum datagram
/// size.
fn segment_msg(mut msg: someip::Message, seg_pl_len: usize, offset_factor: u32)
    -> Vec<someip::Message>
{
    debug_assert!(seg_pl_len > 0 && seg_pl_len % someip::SOMEIP_TP_OFFSET_SCALE == 0);
    debug_assert!(offset_factor as usize * someip::SOMEIP_TP_OFFSET_SCALE == seg_pl_len);

    let mut v = Vec::new();
    msg.header.msg_type = msg.header.msg_type.convert_to_tp();

    let seg_count = ((msg.payload.len() + seg_pl_len - 1) / seg_pl_len) as u32;
    assert!(seg_count > 1);

    for i in 0..seg_count {
        let pl = msg.payload.split_to(min(seg_pl_len, msg.payload.len()));
        let mut hdr = msg.header.clone();
        hdr.length = pl.len() + someip::SOMEIP_HEADER_LEN_PART + someip::SOMEIP_TP_HEADER_SIZE;
        hdr.tp_header = Some( TpHeader{ offset: i * offset_factor, more: i != seg_count-1});
        v.push(someip::Message{header: hdr, payload: pl })
    }
    v
}

/// Calculates the max payload size for segments depending on the maximum datagram size.
fn calc_pl_seg_len(max_datagram_size: usize) -> usize {
    ((max_datagram_size - someip::SOMEIP_HEADER_SIZE - someip::SOMEIP_TP_HEADER_SIZE)
        / someip::SOMEIP_TP_OFFSET_SCALE)
        * someip::SOMEIP_TP_OFFSET_SCALE
}

/// Calculates the scale factor for the offset field in the TP header.
fn calc_offset_scale(seg_pl_len: usize) -> u32 {
    (seg_pl_len / someip::SOMEIP_TP_OFFSET_SCALE) as u32
}

#[cfg(test)]
mod tests {
    use std::thread::sleep;
    use super::*;

    fn make_msg(len: usize, value: u8) -> someip::Message {
        let hdr = someip::Header{
            message_id: someip::MessageId::from(0x01020304),
            length: 0,
            request_id: someip::RequestId::from(0xc1c28080),
            proto_version: someip::ProtocolVersion::Version1,
            intf_version: someip::InterfaceVersion::from(1),
            msg_type: someip::MessageType::TpRequestNoReturn,
            ret_code: someip::ReturnCode::Ok,
            tp_header: None,
        };
        let mut data = BytesMut::zeroed(len);
        data.fill(value);
        someip::Message{ header: hdr, payload: data.freeze()}
    }

    #[test]
    fn segmented_delayed() {
        let mut encdr = Encoder::new_default();
        let msg1 = make_msg(123, 0x01);
        let msg2 = make_msg(5600, 0x01);
        let msg3 = make_msg(8, 0x01);

        assert!(!encdr.prepare_msg(msg1, Duration::from_secs(1)));
        assert!(encdr.prepare_msg(msg2, Duration::from_secs(1)));
        assert_eq!(encdr.get_completed().len(), 5);
        assert!(encdr.prepare_msg(msg3, Duration::from_millis(0)));
        assert_eq!(encdr.get_completed().len(), 1);
    }

    #[test]
    fn tst_segment_msg() {
        let mut msg = make_msg(5600, 0x01);
        msg.header.msg_type = someip::MessageType::Response;

        let segs = segment_msg(msg, 1376, 86);
        assert_eq!(segs.len(), 5);
        assert_eq!(segs[0].payload.len(), 1376);
        assert_eq!(segs[0].header.msg_type, someip::MessageType::TpResponse);
        assert_eq!(segs[0].header.tp_header.as_ref().unwrap().offset, 0);
        assert!(segs[0].header.tp_header.as_ref().unwrap().more);
        assert_eq!(segs[1].payload.len(), 1376);
        assert_eq!(segs[1].header.msg_type, someip::MessageType::TpResponse);
        assert_eq!(segs[1].header.tp_header.as_ref().unwrap().offset, 86);
        assert!(segs[1].header.tp_header.as_ref().unwrap().more);
        assert_eq!(segs[2].payload.len(), 1376);
        assert_eq!(segs[2].header.tp_header.as_ref().unwrap().offset, 172);
        assert!(segs[2].header.tp_header.as_ref().unwrap().more);
        assert_eq!(segs[4].payload.len(), 96);
        assert_eq!(segs[4].header.msg_type, someip::MessageType::TpResponse);
        assert_eq!(segs[4].header.tp_header.as_ref().unwrap().offset, 344);
        assert!(!segs[4].header.tp_header.as_ref().unwrap().more);
    }

    #[test]
    fn single_retention_0() {
        let mut encdr = Encoder::new_default();
        let msg = make_msg(512, 0x1a);
        assert!( encdr.prepare_msg(msg, Duration::from_micros(0)) );

        let d = encdr.get_completed();
        assert_eq!(d.len(), 1);
        let msg = d[0].as_ref();
        assert_eq!(msg.len(), 528);
        assert_eq!(msg[0..4], [0x01, 0x02, 0x03, 0x04]);
        assert_eq!(msg[4..8], [0x00, 0x00, 0x02, 0x08]);
        assert_eq!(msg[8..12], [0xc1, 0xc2, 0x80, 0x80]);
        assert_eq!(msg[12..16], [0x01, 0x01, 0x21, 0x00]);
        assert_eq!(msg[16..20], [0x1a, 0x1a, 0x1a, 0x1a]); // first 4 bytes of payload
    }

    #[test]
    fn single_retention_1_long() {
        let mut encdr = Encoder::new_default();
        let msg = make_msg(1280, 0x1a);
        assert!( encdr.prepare_msg(msg, Duration::from_millis(1000)) );

        let d = encdr.get_completed();
        assert_eq!(d.len(), 1);
        let msg = d[0].as_ref();
        assert_eq!(msg.len(), 1296);
        assert_eq!(msg[0..4], [0x01, 0x02, 0x03, 0x04]);
        assert_eq!(msg[4..8], [0x00, 0x00, 0x05, 0x08]);
        assert_eq!(msg[8..12], [0xc1, 0xc2, 0x80, 0x80]);
        assert_eq!(msg[12..16], [0x01, 0x01, 0x21, 0x00]);
        assert_eq!(msg[16..20], [0x1a, 0x1a, 0x1a, 0x1a]); // first 4 bytes of payload
    }

    #[test]
    fn multi_finish_by_retention_0() {
        let mut encdr = Encoder::new_default();
        let msg1 = make_msg(12, 0x1a);
        let msg2 = make_msg(30, 0x1b);
        let msg3 = make_msg(44, 0x1c);

        assert!( !encdr.prepare_msg(msg1, Duration::from_secs(1500)) );
        assert!( !encdr.prepare_msg(msg2, Duration::from_millis(1500)) );
        assert!( encdr.prepare_msg(msg3, Duration::from_millis(0)) );
    }

    #[test]
    fn multi_finish_by_retention_1() {
        let mut encdr = Encoder::new_default();
        let msg1 = make_msg(12, 0x1a);
        let msg2 = make_msg(30, 0x1b);
        let msg3 = make_msg(44, 0x1c);

        assert!( !encdr.prepare_msg(msg1, Duration::from_secs(1500)) );
        assert!( !encdr.prepare_msg(msg2, Duration::from_secs(1) ));
        assert!( !encdr.prepare_msg(msg3, Duration::from_secs(1500)) );
        assert!(encdr.next_schedule().is_some());
        sleep(Duration::from_secs(1));
        assert!(encdr.schedule());
        assert_eq!(encdr.get_completed().len(), 1);
    }

    #[test]
    fn multi_finish_by_size() {
        let mut encdr = Encoder::new_default();
        let msg1 = make_msg(12, 0x1a);
        let msg2 = make_msg(30, 0x1b);
        let msg3 = make_msg(1250, 0x1c);

        assert!( !encdr.prepare_msg(msg1, Duration::from_secs(1500)) );
        assert!( !encdr.prepare_msg(msg2, Duration::from_secs(1500)) );
        assert!( encdr.prepare_msg(msg3, Duration::from_secs(1500)) );
    }

    #[test]
    fn test_seg_pl_len() {
        assert_eq!(calc_pl_seg_len(1400), 1376);
    }

    #[test]
    fn test_offset_scale() {
        assert_eq!(calc_offset_scale(1376), 86);
    }
}
