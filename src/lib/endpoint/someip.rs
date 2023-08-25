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

use bytes::{Buf, BufMut, BytesMut, Bytes};

macro_rules! id_wrapper {
     ($(#[$attr:meta])* => $id:ident, $tp:ty) => {
         $(#[$attr])*
         #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
         pub struct $id { pub id: $tp}

         impl From<$tp> for $id {
            fn from(value: $tp) -> Self {
                $id{ id: value }
            }
        }
     }
}

id_wrapper!{
        /// PRS_SOMEIP_00034    SOME/IP Message Identifier
        => MessageId, u32}

id_wrapper!{
        /// PRS_SOMEIP_00245    SOME/IP Service Identifier
        /// higher 16 bits [MessageId]
        => ServiceId, u16}

/// Addresses any/all services.
pub const SERVICE_ID_ANY : ServiceId = ServiceId{ id: 0xffff };

id_wrapper!{
        /// PRS_SOMEIP_00245    SOME/IP Method Identifier
        /// lower 16 bits of [MessageId]
        => MethodId, u16}

/// Addresses any/all methods.
pub const METHOD_ID_ANY : MethodId = MethodId{ id: 0xffff };

impl MessageId {
    /// Returns the [ServiceId] as higher 16 bits of the [MessageId].
    pub fn service(&self) -> ServiceId {
        ServiceId::from((self.id >> 16) as u16)
    }

    /// Returns the [MethodId] as lower 16 bits of the [MessageId].
    pub fn method(&self) -> MethodId {
        MethodId::from((self.id & 0xffff) as u16)
    }

    /// Constructs a [MessageId] from [ServiceId] and [MethodId]
    pub fn from_components(svc: ServiceId, mthd: MethodId) -> Self {
        MessageId{ id: ((svc.id as u32) << 16 | (mthd.id as u32)) }
    }
}

id_wrapper!{
        /// PRS_SOMEIP_00043    SOME/IP Request Identifier
        => RequestId, u32}

id_wrapper!{
        /// PRS_SOMEIP_00046    SOME/IP Client Identifier
        /// higher 16 bits of the [RequestId]
        =>ClientId, u16}

id_wrapper!{
        /// PRS_SOMEIP_00046    SOME/IP Sesssion Identifier
        /// lower 16 bits of the [RequestId]
        => SessionId, u16}

/// [SessionId] used for 'no session' - e.g. for events/notifications.
pub const SESSION_ID_NO_SESSION : SessionId = SessionId{ id: 0 };

impl RequestId {
    /// Returns the [ClientId] of the [RequestId].
    pub fn client(&self) -> ClientId {
        ClientId::from((self.id >> 16) as u16)
    }

    /// Returns the [SessionId] of the [RequestId].
    pub fn session(&self) -> SessionId {
        SessionId::from((self.id & 0xffff) as u16)
    }

    /// Constructs a [RequestId] from [ClientId] and [SessionId]
    pub fn from_components(client: ClientId, session: SessionId) -> Self {
        RequestId{ id: ((client.id as u32) << 16 | (session.id as u32)) }
    }
}

impl SessionId {
    /// Returns `true` when `self` is a newer session id than `other`.
    pub fn newer_than(&self, other: &SessionId) -> bool {
        0x8000u16 & (self.id.wrapping_sub(other.id)) == 0
    }
}

/// PRS_SOMEIP_00052        SOME/IP Protocol Version
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum ProtocolVersion {
    Version1,
    Unknown(u8)
}

impl ProtocolVersion {
    pub fn value(&self) -> u8 {
        match self {
            ProtocolVersion::Version1 => 0x01,
            ProtocolVersion::Unknown(v) => *v,
        }
    }
}

impl From<u8> for ProtocolVersion {
    fn from(value: u8) -> Self {
        match value {
            0x01 => ProtocolVersion::Version1,
            _ => ProtocolVersion::Unknown(value)
        }
    }
}

id_wrapper!{
        /// PRS_SOMEIP_00053    SOME/IP Interface Version
        => InterfaceVersion, u8 }

/// PRS_SOMEIP_00055        SOME/IP Message Type
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum MessageType {
    Request                 = 0x00,
    RequestNoReturn         = 0x01,
    Notification            = 0x02,
    TpRequest               = 0x20,
    TpRequestNoReturn       = 0x21,
    TpNotification          = 0x22,
    Response                = 0x80,
    Error                   = 0x81,
    TpResponse              = 0xa0,
    TpError                 = 0xa1,
    Unknown(u8)
}

impl MessageType {
    pub fn value(&self) -> u8 {
        match self {
            MessageType::Request            => 0x00,
            MessageType::RequestNoReturn    => 0x01,
            MessageType::Notification       => 0x02,
            MessageType::TpRequest          => 0x20,
            MessageType::TpRequestNoReturn  => 0x21,
            MessageType::TpNotification     => 0x22,
            MessageType::Response           => 0x80,
            MessageType::Error              => 0x81,
            MessageType::TpResponse         => 0xa0,
            MessageType::TpError            => 0xa1,
            MessageType::Unknown(v)   => *v
        }
    }

    pub fn strip_tp(&self) -> MessageType {
        match self {
            MessageType::TpRequest => MessageType::Request,
            MessageType::TpRequestNoReturn => MessageType::RequestNoReturn,
            MessageType::TpNotification => MessageType::Notification,
            MessageType::TpResponse => MessageType::Response,
            MessageType::TpError => MessageType::Error,
            _ => self.clone()
        }
    }

    /// Returns `true` when the message type requires an TP header, e.g. it
    /// is a SOME/IP TP segment.
    pub fn is_tp(&self) -> bool {
        match self {
            MessageType::TpRequest |
            MessageType::TpRequestNoReturn |
            MessageType::TpNotification |
            MessageType::TpResponse |
            MessageType::TpError => true,
            _ => false,
        }
    }
}

impl From<u8> for MessageType {
    fn from(value: u8) -> Self {
        match value {
            0x00 => MessageType::Request,
            0x01 => MessageType::RequestNoReturn,
            0x02 => MessageType::Notification,
            0x20 => MessageType::TpRequest,
            0x21 => MessageType::TpRequestNoReturn,
            0x22 => MessageType::TpNotification,
            0x80 => MessageType::Response,
            0x81 => MessageType::Error,
            0xa0 => MessageType::TpResponse,
            0xa1 => MessageType::TpError,
            _ => MessageType::Unknown(value),
        }
    }
}

/// PRS_SOMEIP_00058        SOME/IP Return Code
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ReturnCode {
    Ok                      = 0x00,
    NotOk                   = 0x01,
    UnknownService          = 0x02,
    UnknownMethod           = 0x03,
    NotReady                = 0x04,
    NotReachable            = 0x05,
    Timeout                 = 0x06,
    WrongProtocolVersion    = 0x07,
    WrongInterfaceVersion   = 0x08,
    MalformedMessage        = 0x09,
    WrongMessageType        = 0x0a,
    E2eRepeated             = 0x0b,
    E2eWrongSequence        = 0x0c,
    E2eUnspecified          = 0x0d,
    E2eNotAvailable         = 0x0e,
    E2eNoNewData            = 0x0f,
    ReservedInternal(u8),               // reserved for further SOME/IP usage 0x10 .. =0x1f
    ServiceSpecific(u8),                // service specific errors 0x20..=0x5f
    Reserved(u8),                       // not specified return code region >= 0x60
}

impl ReturnCode {
    pub fn value(&self) -> u8 {
        match self {
            ReturnCode::Ok                      => 0x00,
            ReturnCode::NotOk                   => 0x01,
            ReturnCode::UnknownService          => 0x02,
            ReturnCode::UnknownMethod           => 0x03,
            ReturnCode::NotReady                => 0x04,
            ReturnCode::NotReachable            => 0x05,
            ReturnCode::Timeout                 => 0x06,
            ReturnCode::WrongProtocolVersion    => 0x07,
            ReturnCode::WrongInterfaceVersion   => 0x08,
            ReturnCode::MalformedMessage        => 0x09,
            ReturnCode::WrongMessageType        => 0x0a,
            ReturnCode::E2eRepeated             => 0x0b,
            ReturnCode::E2eWrongSequence        => 0x0c,
            ReturnCode::E2eUnspecified          => 0x0d,
            ReturnCode::E2eNotAvailable         => 0x0e,
            ReturnCode::E2eNoNewData            => 0x0f,
            ReturnCode::ReservedInternal(v) => *v,
            ReturnCode::ServiceSpecific(v) => *v,
            ReturnCode::Reserved(v)        => *v,
        }
    }
}

impl From<u8> for ReturnCode {
    fn from(value: u8) -> Self {
        match value {
            0x00 => ReturnCode::Ok,
            0x01 => ReturnCode::NotOk,
            0x02 => ReturnCode::UnknownService,
            0x03 => ReturnCode::UnknownMethod,
            0x04 => ReturnCode::NotReady,
            0x05 => ReturnCode::NotReachable,
            0x06 => ReturnCode::Timeout,
            0x07 => ReturnCode::WrongProtocolVersion,
            0x08 => ReturnCode::WrongInterfaceVersion,
            0x09 => ReturnCode::MalformedMessage,
            0x0a => ReturnCode::WrongMessageType,
            0x0b => ReturnCode::E2eRepeated,
            0x0c => ReturnCode::E2eWrongSequence,
            0x0d => ReturnCode::E2eUnspecified,
            0x0e => ReturnCode::E2eNotAvailable,
            0x0f => ReturnCode::E2eNoNewData,
            0x10..=0x20 => ReturnCode::ReservedInternal(value),
            0x21..=0x5f => ReturnCode::ServiceSpecific(value),
            _ => ReturnCode::Reserved(value),
        }
    }
}

/// SOME/IP message from/to wire.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Header {
    pub message_id: MessageId,
    pub length: usize,
    pub request_id: RequestId,
    pub proto_version: ProtocolVersion,
    pub intf_version: InterfaceVersion,
    pub msg_type: MessageType,
    pub ret_code: ReturnCode,
    pub tp_header: Option<TpHeader>,
}

impl Header {

    /// Returns the size (in bytes) the header requires on the wire.
    pub fn header_size(&self) -> usize {
        if self.is_tp() {
            SOMEIP_HEADER_SIZE
        } else {
            SOMEIP_HEADER_SIZE + SOMEIP_TP_HEADER_SIZE
        }
    }

    /// Returns whether the header is for a segmented message.
    pub fn is_tp(&self) -> bool {
        self.tp_header.is_some()
    }

    /// Calculates the required length field value for the given payload size.
    pub fn calc_length(&self, payload_len: usize) -> usize {
        SOMEIP_HEADER_LEN_PART + payload_len
            + if self.is_tp() {SOMEIP_TP_HEADER_SIZE} else {0}
    }

    /// Returns the expected payload size of the SOME/IP header(s).
    pub fn expected_payload_len(&self) -> usize {
        self.length - SOMEIP_HEADER_LEN_PART - if self.is_tp() {SOMEIP_TP_HEADER_SIZE} else {0}
    }

    /// Minimum length field value.
    pub fn min_length_value(&self) -> usize {
        if self.is_tp() {
            SOMEIP_HEADER_LEN_PART + SOMEIP_TP_HEADER_SIZE
        } else {
            SOMEIP_HEADER_LEN_PART
        }
    }

/// Returns whether message type requires TP header.
    pub fn requires_tp(&self) -> bool {
        match self.msg_type {
            MessageType::TpError |
            MessageType::TpNotification |
            MessageType::TpResponse |
            MessageType::TpRequest |
            MessageType::TpRequestNoReturn => true,
            _ => false
        }
    }

    /// Write the header into the buffer `buf`
    /// NOTE 1: The method does not do any buffer capacity reservation before.
    /// NOTE 2: This method panics if the required length field value exceeds 2^32-1
    pub fn write_to(&self, buf: &mut BytesMut) {
        buf.put_u32(self.message_id.id);
        buf.put_u32(self.length as u32);
        buf.put_u32(self.request_id.id);
        buf.put_u8(self.proto_version.value());
        buf.put_u8(self.intf_version.id);
        buf.put_u8(self.msg_type.value());
        buf.put_u8(self.ret_code.value());
        if let Some(tp) = self.tp_header.as_ref() {
            buf.put_u32( (tp.offset << 4) | (if tp.more {1} else {0}) )
        }
    }

    /// Reads the standard message SOME/IP header from `buf`.
    /// It does not attempt to read the TP header.
    /// NOTE: This methods panics if not enough data is in `buf` for the base header.
    pub fn read_base_from(buf: &mut BytesMut) -> Header {
        assert!(buf.len() >= SOMEIP_HEADER_SIZE);
        Header {
            message_id: MessageId::from(buf.get_u32()),
            length: buf.get_u32() as usize,
            request_id: RequestId::from(buf.get_u32()),
            proto_version: ProtocolVersion::from(buf.get_u8()),
            intf_version: InterfaceVersion::from(buf.get_u8()),
            msg_type: MessageType::from(buf.get_u8()),
            ret_code: ReturnCode::from(buf.get_u8()),
            tp_header: None
        }
    }

    /// Reads the TP header from `buf` and adds it to the header `self`.
    /// NOTE: This method panics if not enough data is available in `buf`
    pub fn read_tp(&mut self, buf: &mut BytesMut) {
        assert!(buf.len() >= SOMEIP_TP_HEADER_SIZE);
        let tpr = buf.get_u32();
        self.tp_header = Some( TpHeader { offset: (tpr >> 4), more: (tpr & 0x1) != 0 })
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct TpHeader {
    /// Segment payload offset into whole package (in SOMEIP_TP_OFFSET_SCALE bytes units).
    pub offset: u32,
    /// More segments to come or not.
    pub more: bool
}

/// Scale factor for [TpHeader::offset] value.
pub const SOMEIP_TP_OFFSET_SCALE: usize = 16;

/// Default maximum supported SOME/IP message size.
pub const DEFAULT_MAX_FRAME_SIZE: usize = 4 * 1024 * 1024; // 4 MByte

/// SOME/IP header size without TP header
pub const SOMEIP_HEADER_SIZE: usize = 16;

/// SOME/IP size of header after length field without TP header
pub const SOMEIP_HEADER_LEN_PART: usize = 8;

/// SOME/IP TP (Transport Protocol) header size
pub const SOMEIP_TP_HEADER_SIZE: usize = 4;

/// Default UDP MTU size
pub const DEFAULT_UDP_MTU_SIZE: usize = 1450;

/// Errors for serialization of SOME/IP messages.
#[derive(Debug)]
pub enum SomeipWireError {
    /// Low level I/O error.
    IoError(std::io::Error),
    /// Incoming or to be formatted outgoing frame will exceed the maximum allowed message size.
    ExceedingMaxFrameSize,
    /// Protocol version (incoming message) is not supported by actual implementation.
    UnsupportedProtocolVersion,
    /// Length field (incoming message) is too short.
    LengthFieldErrorToShort,
}

impl From<std::io::Error> for SomeipWireError {
    fn from(value: std::io::Error) -> Self {
        SomeipWireError::IoError(value)
    }
}

/// Key to identify a segmentation task for a single UDP 'connection'. PRS_SOMEIP_00740
pub type SegmentationKey = (MessageId, ClientId, MessageType, ProtocolVersion, InterfaceVersion);

/// Creates a [SegmentationKey] for the header.
pub fn make_key(header: &Header) -> SegmentationKey {
    (header.message_id, header.request_id.client(), header.msg_type.strip_tp(),
     header.proto_version, header.intf_version)
}

/// SOME/IP message
#[derive(Debug)]
pub struct Message {
    pub header: Header,
    pub payload: Bytes,
}

/// Returns the final size in bytes that the message will allocate in the frame.
pub fn final_msg_size(msg: &Message) -> usize {
    if msg.header.is_tp() {
        SOMEIP_HEADER_SIZE + SOMEIP_TP_HEADER_SIZE + msg.payload.len()
    } else {
        SOMEIP_HEADER_SIZE + msg.payload.len()
    }
}

/// Sets the length value in the message header
pub fn fix_length(msg: &mut Message) {
    msg.header.length = msg.payload.len() + SOMEIP_HEADER_LEN_PART +
        if msg.header.is_tp() {SOMEIP_TP_HEADER_SIZE} else {0usize};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    pub fn message_coding() {

    }

    #[test]
    pub fn message_id_decomp() {
        let msg_id = MessageId::from(0x12345678u32);
        assert_eq!(msg_id.method(), MethodId::from(0x5678u16));
        assert_eq!(msg_id.service(), ServiceId::from(0x1234u16));
    }

    #[test]
    pub fn message_id_comp() {
        let msg_id = MessageId::from_components(
            ServiceId::from(0x9876u16),
            MethodId::from(0x4321u16)
        );
        assert_eq!(msg_id, MessageId::from(0x98764321));
    }

    #[test]
    pub fn request_id_decomp() {
        let req_id = RequestId::from(0x12345678u32);
        assert_eq!(req_id.client(), ClientId::from(0x1234u16));
        assert_eq!(req_id.session(), SessionId::from(0x5678u16));
    }

    #[test]
    pub fn request_id_comp() {
        let req_id = RequestId::from_components(
            ClientId::from(0x9876u16),
            SessionId::from(0x4321u16)
        );
        assert_eq!(req_id, RequestId::from(0x98764321));
    }
}
