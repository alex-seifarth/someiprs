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
use bytes::{BytesMut};

/// The trait [Decoder] represents an entity that processes byte streams and creates a sequence of
/// messages from it or returns an error.
///
/// The decoder object gets fed a buffer ([BytesMut]) and has to decode its content to
/// decode one [Decoder::Message] object from it in the [Decoder::decode] method.
/// The method returns:
/// - `Ok(None)`:   If more data is needed to decode a message completely the driver of the
///                 decoder object will have to add data to the buffer `buf` and call `decode` with
///                 it again.
/// - `Ok(msg)`:    If a single [Decoder::Message] has been decoded (and removed from the buffer) it
///                 returned by the `decode` method.
/// - `Err(e)`:     Returned by `decode` when a fatal error occurs that makes immediate further
///                 decoding of the input useless.
///
pub trait Decoder {
    type Message;
    type Error;

    /// Decode data from `buf` and return the decoded frame.
    /// returns
    /// - Ok(None):         Not enough data in `buf` to decode a complete frame.
    /// - Ok(Some(msg)):    Single decoded frame. (NOTE: buf may contain contain more data --> call decode again)
    /// - Err(e):           Fatal error that makes further decoding impossible.
    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Message>, Self::Error>;

    /// Reset the [Decoder] object to initial state.
    /// This can be called after decoding failures.
    fn reset(&mut self);
}

/// The trait [Encoder] represents an entity that can serialize objects of type [Encoder::Message]
/// into a buffer ([BytesMut]).
pub trait Encoder {
    type Message;
    type Error;

    fn encode(&mut self, msg: &Self::Message, buf: &mut BytesMut) -> Result<(), Self::Error>;
}