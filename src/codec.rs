// maelstrom
// Copyright (C) 2020 Raphael Robert
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see http://www.gnu.org/licenses/.

use crate::errors::ConfigError;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use std::collections::HashMap;
use std::convert::*;

#[derive(Debug)]
pub enum CodecError {
    EncodingError,
    DecodingError,
}

impl From<ConfigError> for CodecError {
    // TODO: tbd in #83
    fn from(_e: ConfigError) -> CodecError {
        CodecError::DecodingError
    }
}

pub enum VecSize {
    VecU8,
    VecU16,
    VecU32,
    VecU64,
}

pub struct Cursor {
    buffer: Vec<u8>,
    position: usize,
}

impl<'a> Cursor {
    pub fn new(bytes: &[u8]) -> Cursor {
        Cursor {
            buffer: bytes.to_vec(),
            position: 0,
        }
    }

    pub fn consume(&mut self, length: usize) -> Result<&[u8], CodecError> {
        let unread_bytes = self.buffer.len() - self.position;
        if unread_bytes < length {
            return Err(CodecError::DecodingError);
        }

        let position = self.position;
        self.position += length;
        Ok(&self.buffer[position..position + length])
    }

    pub fn sub_cursor(&mut self, length: usize) -> Result<Cursor, CodecError> {
        self.consume(length).map(|buffer| Cursor::new(buffer))
    }

    pub fn is_empty(&self) -> bool {
        self.position >= self.buffer.len()
    }

    pub fn has_more(&self) -> bool {
        !self.is_empty()
    }
}

pub trait Codec: Sized {
    fn encode(&self, _buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        unimplemented!();
    }

    fn decode(_cursor: &mut Cursor) -> Result<Self, CodecError> {
        unimplemented!();
    }

    fn encode_detached(&self) -> Result<Vec<u8>, CodecError> {
        let mut buffer = vec![];
        self.encode(&mut buffer)?;
        Ok(buffer)
    }
}

impl Codec for u8 {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        buffer.push(*self);
        Ok(())
    }

    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let byte_option = cursor.consume(1);
        match byte_option {
            Ok(bytes) => Ok(bytes[0]),
            Err(e) => Err(e),
        }
    }
}

impl Codec for u16 {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        buffer.write_u16::<BigEndian>(*self).unwrap();
        Ok(())
    }

    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let bytes_option = cursor.consume(2);
        match bytes_option {
            Ok(mut bytes) => Ok(bytes.read_u16::<BigEndian>().unwrap()),
            Err(e) => Err(e),
        }
    }
}

impl Codec for u32 {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        buffer.write_u32::<BigEndian>(*self).unwrap();
        Ok(())
    }

    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let bytes_option = cursor.consume(4);
        match bytes_option {
            Ok(mut bytes) => Ok(bytes.read_u32::<BigEndian>().unwrap()),
            Err(e) => Err(e),
        }
    }
}

impl Codec for u64 {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        buffer.write_u64::<BigEndian>(*self).unwrap();
        Ok(())
    }

    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let bytes_option = cursor.consume(8);
        match bytes_option {
            Ok(mut bytes) => Ok(bytes.read_u64::<BigEndian>().unwrap()),
            Err(e) => Err(e),
        }
    }
}

impl<T: Codec> Codec for Option<T> {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        match self {
            None => buffer.push(0),
            Some(value) => {
                buffer.push(1);
                value.encode(buffer)?;
            }
        }
        Ok(())
    }

    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let tag = u8::decode(cursor)?;
        match tag {
            0 => Ok(None),
            1 => match T::decode(cursor) {
                Ok(value) => Ok(Some(value)),
                Err(e) => Err(e),
            },
            _ => Err(CodecError::DecodingError),
        }
    }
}

impl<T1: Codec, T2: Codec> Codec for (T1, T2) {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        self.0.encode(buffer)?;
        self.1.encode(buffer)?;
        Ok(())
    }

    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        Ok((T1::decode(cursor)?, T2::decode(cursor)?))
    }
}

impl<K: Codec + Eq + ::std::hash::Hash, V: Codec, S: ::std::hash::BuildHasher + Default> Codec
    for HashMap<K, V, S>
{
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        let size = self.len() as u32;
        size.encode(buffer)?;
        for (key, val) in self.iter() {
            key.encode(buffer)?;
            val.encode(buffer)?;
        }
        Ok(())
    }

    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let size = u32::decode(cursor)? as usize;
        let mut hm = HashMap::with_capacity_and_hasher(size, Default::default());
        for _ in 0..size {
            let k = K::decode(cursor)?;
            let v = V::decode(cursor)?;
            hm.insert(k, v);
        }
        Ok(hm)
    }
}

pub fn encode_vec<T: Codec>(
    vec_size: VecSize,
    bytes: &mut Vec<u8>,
    slice: &[T],
) -> Result<(), CodecError> {
    let slice_len = slice.len();
    let mut buffer = Vec::new();

    match vec_size {
        VecSize::VecU8 => {
            if slice_len > (u8::max_value() as usize) {
                return Err(CodecError::EncodingError);
            }
        }
        VecSize::VecU16 => {
            if slice_len > (u16::max_value() as usize) {
                return Err(CodecError::EncodingError);
            }
        }
        VecSize::VecU32 => {
            if slice_len > (u32::max_value() as usize) {
                return Err(CodecError::EncodingError);
            }
        }
        VecSize::VecU64 => {}
    }
    for e in slice.iter() {
        e.encode(&mut buffer)?;
    }
    match vec_size {
        VecSize::VecU8 => {
            (buffer.len() as u8).encode(bytes)?;
        }
        VecSize::VecU16 => {
            (buffer.len() as u16).encode(bytes)?;
        }
        VecSize::VecU32 => {
            (buffer.len() as u32).encode(bytes)?;
        }
        VecSize::VecU64 => {
            (buffer.len() as u64).encode(bytes)?;
        }
    }
    bytes.extend(buffer);
    Ok(())
}

pub fn decode_vec<T: Codec>(vec_size: VecSize, cursor: &mut Cursor) -> Result<Vec<T>, CodecError> {
    let mut result: Vec<T> = Vec::new();
    let len;
    match vec_size {
        VecSize::VecU8 => {
            len = usize::from(u8::decode(cursor)?);
        }
        VecSize::VecU16 => {
            len = usize::from(u16::decode(cursor)?);
        }
        VecSize::VecU32 => {
            len = u32::decode(cursor)? as usize;
        }
        VecSize::VecU64 => {
            len = u64::decode(cursor)? as usize;
        }
    }
    let mut sub_cursor = cursor.sub_cursor(len)?;
    while sub_cursor.has_more() {
        result.push(T::decode(&mut sub_cursor)?);
    }
    Ok(result)
}

#[test]
fn test_cursor() {
    let v = vec![1, 2, 3];
    let cursor = &mut Cursor::new(&v);
    assert_eq!(cursor.consume(2).unwrap().to_vec(), vec![1, 2]);
    assert_eq!(cursor.consume(1).unwrap().to_vec(), vec![3]);
    assert!(cursor.consume(1).is_err());
}

#[test]
fn test_primitives() {
    let mut buffer = vec![];
    1u8.encode(&mut buffer).unwrap();
    assert_eq!(buffer, vec![1u8]);

    let mut buffer = vec![];
    1u16.encode(&mut buffer).unwrap();
    assert_eq!(buffer, vec![0u8, 1u8]);

    let mut buffer = vec![];
    1u32.encode(&mut buffer).unwrap();
    assert_eq!(buffer, vec![0u8, 0u8, 0u8, 1u8]);

    let mut buffer = vec![];
    1u64.encode(&mut buffer).unwrap();
    assert_eq!(buffer, vec![0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 1u8]);
}

#[test]
fn test_encode_vec() {
    let v: Vec<u8> = vec![1, 2, 3];
    let mut vec_u8 = vec![];
    let mut vec_u16 = vec![];
    let mut vec_u32 = vec![];
    let mut vec_u64 = vec![];
    encode_vec(VecSize::VecU8, &mut vec_u8, &v).unwrap();
    encode_vec(VecSize::VecU16, &mut vec_u16, &v).unwrap();
    encode_vec(VecSize::VecU32, &mut vec_u32, &v).unwrap();
    encode_vec(VecSize::VecU64, &mut vec_u64, &v).unwrap();
    assert_eq!(vec_u8, vec![3u8, 1u8, 2u8, 3u8]);
    assert_eq!(vec_u16, vec![0u8, 3u8, 1u8, 2u8, 3u8]);
    assert_eq!(vec_u32, vec![0u8, 0u8, 0u8, 3u8, 1u8, 2u8, 3u8]);
    assert_eq!(
        vec_u64,
        vec![0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 3u8, 1u8, 2u8, 3u8]
    );
    assert_eq!(
        decode_vec::<u8>(VecSize::VecU8, &mut Cursor::new(&vec_u8)).unwrap(),
        v
    );
    assert_eq!(
        decode_vec::<u8>(VecSize::VecU16, &mut Cursor::new(&vec_u16)).unwrap(),
        v
    );
    assert_eq!(
        decode_vec::<u8>(VecSize::VecU32, &mut Cursor::new(&vec_u32)).unwrap(),
        v
    );
    assert_eq!(
        decode_vec::<u8>(VecSize::VecU64, &mut Cursor::new(&vec_u64)).unwrap(),
        v
    );
}
