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

use std::collections::{HashMap};
use bytes::{Bytes, BytesMut};
use crate::someip::decoder::SomeipDecoder;
use crate::someip::types::*;
use crate::util::coder::Decoder;
use crate::someip::desegmentation_task::*;

pub enum DecodedMessage {
    Message(SomeipMessageHeader, Bytes),
    TpAssemblyAbortedByNonSegmentedMessage(SegmentationKey),
    TpSegmentationError(SegmentationError, SegmentationKey),
    TpSegmentationNotAllowed(SegmentationKey),
}

impl From<(SomeipMessageHeader, Bytes)> for DecodedMessage {
    fn from(value: (SomeipMessageHeader, Bytes)) -> Self {
        DecodedMessage::Message(value.0, value.1)
    }
}

impl From<(SegmentationError, SegmentationKey)> for DecodedMessage {
    fn from(value: (SegmentationError, SegmentationKey)) -> Self {
        DecodedMessage::TpSegmentationError(value.0, value.1)
    }
}

/// Configuration parameters for a segmentation task.
pub struct SegmentationConfig {
    /// initial segmentation task buffer size for paylaod
    pub initial_paylaod_buffer_size: usize,
    /// maximum segmentation task buffer size for payload
    pub max_paylaod_size: usize,
    /// alive counter start value
    pub alive_counter_init: u32,
}

/// Data structure for storing segmentation task data.
struct SegmentationData {
    /// The de-segmentation task data (e.g. buffer for payload, segment bookkeeping)
    task: DesegmentationTask,
    /// Alive counter for assembly of whole packet.
    alive_counter: u32,
}

const ALIVE_COUNTER_INITIAL_VALUE: u32 = 5;

/// Decoder for SOME/IP message that may or may not be segmented by the SOME/IP-TP layer.
///
pub struct SomeipTpDecoder {
    /// Decoder for the standard SOME/IP messages.
    decoder: SomeipDecoder,
    /// Storage for TP message segments ordered by service/method/message. PRS_SOMEIP_00738
    segments: HashMap<SegmentationKey, SegmentationData>,
    /// Cache to store incoming message when a segmentation failure must be reported first.
    cached: Option<(SomeipMessageHeader, Bytes)>,
    /// configuration parameters for segmentation
    seg_configs: HashMap<(MessageId, MessageType, InterfaceVersion), SegmentationConfig>,
}

impl SomeipTpDecoder {
    /// Creates a new [SomeipTpDecoder] object with standard values.
    pub fn new() -> Self {
        SomeipTpDecoder {
            decoder: SomeipDecoder::new(),
            segments: HashMap::new(),
            cached: None,
            seg_configs: HashMap::new(),
        }
    }

    /// Retrieves the segmentation configuration for the key.
    fn get_seg_config(&self, key: &SegmentationKey) -> Option<&SegmentationConfig> {
        self.seg_configs.get(&(key.0, key.2, key.4))
    }

    /// Adds or overwrites the segmentation configuration for the triple
    /// ([MessageId], [MessageType], [InterfaceVersion]).
    pub fn add_seg_config(&mut self,
                          msg_id: MessageId,
                          msg_type: MessageType,
                          intf_version: InterfaceVersion,
                          config: SegmentationConfig)
    {
        self.seg_configs.insert((msg_id, msg_type, intf_version), config);
    }

    // Process an incoming message.
    fn process_msg(&mut self, msg: (SomeipMessageHeader, Bytes))
                   -> Result<Option<DecodedMessage>, SomeipWireError>
    {
        if !msg.0.is_tp() {
            self.process_non_segmented_msg(msg.0, msg.1)
        } else {
            self.process_segmented_msg(msg.0, msg.1)
        }
    }

    fn process_non_segmented_msg(&mut self, header: SomeipMessageHeader, payload: Bytes)
                                 -> Result<Option<DecodedMessage>, SomeipWireError>
    {
        let key = make_key(&header);
        if self.segments.contains_key(&key) {
            // we got a non-segmented message for an ongoing segmented message
            // -> cache actual message and report error for the aborted old one
            self.cached = Some((header, payload));
            self.segments.remove(&key).unwrap();
            return Ok(Some(DecodedMessage::TpAssemblyAbortedByNonSegmentedMessage(key)));
        }
        return Ok(Some(DecodedMessage::Message(header, payload)));
    }

    fn process_segmented_msg(&mut self, header: SomeipMessageHeader, payload: Bytes)
                             -> Result<Option<DecodedMessage>, SomeipWireError>
    {
        assert!(header.tp_header.is_some());
        let tph = header.tp_header.as_ref().unwrap().clone();
        let key = make_key(&header);
        let ret_code = header.ret_code;

        // check whether segmentation is allowed for this key
        let seg_config = if let Some(cfg) = self.get_seg_config(&key) {
            cfg
        } else {
            return Ok(Some(DecodedMessage::TpSegmentationNotAllowed(key)));
        };

        if !self.segments.contains_key(&key) {
            self.segments.insert(key.clone(), SegmentationData {
                alive_counter: seg_config.alive_counter_init,
                task: DesegmentationTask::new_with_max_size(header,
                                                            seg_config.max_paylaod_size,
                                                            seg_config.initial_paylaod_buffer_size),
            });
        }
        let st = self.segments.get_mut(&key).unwrap();

        if let Err(e) = st.task.add_segment(tph.offset, payload, !tph.more) {
            self.segments.remove(&key);
            return Ok(Some(DecodedMessage::from((e, key))));
        }

        if !tph.more {
            // final segment --> finish segmentation
            let st = self.segments.remove(&key).unwrap().task;
            return match st.finish(ret_code) {
                Ok((hdr, pl)) =>
                    Ok(Some(DecodedMessage::Message(hdr, pl))),
                Err(e) =>
                    Ok(Some(DecodedMessage::from((e, key))))
            };
        }
        Ok(None)
    }

    /// Cleanup runs through the segmentation tasks, decreases their alive counter and
    /// cancels the reassembly when the alive counter is 0.
    pub fn cleanup(&mut self) -> Vec<SegmentationKey> {
        // TODO: performance check/measurement required, possibly dividing the de-segmentation tasks
        //       into chunks depending on their number might be necessary
        //       BUT only if the cleanup really takes too long.
        let mut to_remove = Vec::new();
        for st in self.segments.iter_mut() {
            st.1.alive_counter -= 1;
            if st.1.alive_counter == 0 {
                to_remove.push(st.0.clone())
            }
        }
        for k in to_remove.iter() {
            self.segments.remove(k);
        }
        to_remove
    }
}

impl Decoder for SomeipTpDecoder {
    type Message = DecodedMessage;
    type Error = <SomeipDecoder as Decoder>::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Message>, Self::Error> {
        if let Some(msg) = self.cached.take() {
            self.process_msg(msg)
        } else if let Some(msg) = self.decoder.decode(buf)? {
            self.process_msg(msg)
        } else {
            Ok(None)
        }
    }

    fn reset(&mut self) {
        self.decoder.reset();
        self.segments.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_seg_config() -> SegmentationConfig {
        SegmentationConfig {
            alive_counter_init: ALIVE_COUNTER_INITIAL_VALUE,
            initial_paylaod_buffer_size: DEFAULT_INITIAL_BUFFER_CAPACITY,
            max_paylaod_size: DEFAULT_MAX_FRAME_SIZE,
        }
    }

    fn default_decoder() -> SomeipTpDecoder {
        let mut dcdr = SomeipTpDecoder::new();
        dcdr.add_seg_config(MessageId::from(0x01020304), MessageType::RequestNoReturn, InterfaceVersion::from(0x12),
                            default_seg_config());
        dcdr
    }

    #[test]
    fn desegmentation_segm_asc_1() {
        let mut b1 = BytesMut::from([
            0x01u8, 0x02, 0x03, 0x04, 0x00, 0x00, 0x00, 0x1c,
            0x32, 0x33, 0x34, 0x35, 0x01, 0x12, 0x21, 0x00,
            0x00, 0x00, 0x00, 0x01,     // more = true, offset = 0
            0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8,
            0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8].as_ref());
        let mut b2 = BytesMut::from([0x01u8, 0x02, 0x03, 0x04, 0x00, 0x00, 0x00, 0x1a,
            0x32, 0x33, 0x34, 0x35, 0x01, 0x12, 0x21, 0x00,
            0x00, 0x00, 0x00, 0x10,     // more = false, offset = 1 (=16 bytes)
            0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8,
            0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0x99].as_ref());
        let mut dcdr = default_decoder();

        let r = dcdr.decode(&mut b1);
        assert!(r.is_ok() && r.as_ref().unwrap().is_none());

        let r = dcdr.decode(&mut b2);
        assert!(r.is_ok() && r.as_ref().unwrap().is_some());

        if let DecodedMessage::Message(hdr, pl) = r.unwrap().unwrap() {
            assert_eq!(pl, [
                0xa1u8, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8,
                0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6
            ].as_ref());
            assert_eq!(hdr.msg_type, MessageType::RequestNoReturn);
            assert!(hdr.tp_header.is_none());
            assert_eq!(hdr.message_id, MessageId::from(0x01020304));
        } else {
            assert!(false, "Expected DecodedMessage::Message");
        }
    }

    #[test]
    fn desegmentation_no_segm() {
        let mut b = BytesMut::from([0x01u8, 0x02, 0x03, 0x04, 0x00, 0x00, 0x00, 0x18,
            0x32, 0x33, 0x34, 0x35, 0x01, 0x12, 0x01, 0x00,
            0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8,
            0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0x99].as_ref());
        let mut dcdr = default_decoder();
        let r = dcdr.decode(&mut b);
        assert!(r.is_ok() && r.as_ref().unwrap().is_some());
    }

    #[test]
    fn desegmentation_degen() {
        let mut b = BytesMut::from([0x01u8, 0x02, 0x03, 0x04, 0x00, 0x00, 0x00, 0x1a,
            0x32, 0x33, 0x34, 0x35, 0x01, 0x12, 0x21, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8,
            0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0x97, 0x98, 0x99].as_ref());
        let mut dcdr = default_decoder();
        let r = dcdr.decode(&mut b);
        if let Ok(Some(DecodedMessage::Message(hdr, pl))) = r {
            assert_eq!(hdr.tp_header, None);
            assert_eq!(hdr.msg_type, MessageType::RequestNoReturn);
            assert_eq!(pl.len(), 14);
        } else {
            assert!(false, "Result is not a valid message");
        }
    }
}