mod errors;

pub use errors::*;

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use std::collections::HashMap;
use std::convert::*;

#[derive(Debug)]
pub enum VecSize {
    VecU8,
    VecU16,
    VecU32,
    VecU64,
}

impl VecSize {
    #[inline(always)]
    pub(crate) const fn len_len(self) -> usize {
        match self {
            VecSize::VecU8 => 1,
            VecSize::VecU16 => 2,
            VecSize::VecU32 => 4,
            VecSize::VecU64 => 8,
        }
    }
}

#[derive(Debug)]
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

    /// Get a slice of the underlying raw buffer.
    pub(crate) fn raw(&self) -> &[u8] {
        &self.buffer[self.position..]
    }
}

pub trait TlsSize {
    fn serialized_len(&self) -> usize;
}

struct TlsSerializer {
    buf: Vec<u8>,
}

impl TlsSerializer {
    pub(crate) fn new(len: usize) -> Self {
        Self {
            buf: Vec::with_capacity(len),
        }
    }

    pub(crate) fn write(&mut self, bytes: &[u8]) -> Result<(), CodecError> {
        if bytes.len() > (self.buf.capacity() - self.buf.len()) {
            return Err(CodecError::EncodingError);
        }
        self.buf.extend_from_slice(bytes);
        Ok(())
    }

    pub(crate) fn write_byte(&mut self, byte: u8) -> Result<(), CodecError> {
        if self.buf.capacity() <= self.buf.len() {
            return Err(CodecError::EncodingError);
        }
        self.buf.push(byte);
        Ok(())
    }

    pub(crate) fn finish(self) -> Result<Vec<u8>, CodecError> {
        if self.buf.len() != self.buf.capacity() {
            return Err(CodecError::EncodingError);
        }
        Ok(self.buf)
    }
}

#[cfg(test)]
mod tests;

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

    fn decode_detached(bytes: &[u8]) -> Result<Self, CodecError> {
        let cursor = &mut Cursor::new(bytes);
        Self::decode(cursor)
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

impl TlsSize for u8 {
    #[inline]
    fn serialized_len(&self) -> usize {
        1
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

impl Codec for String {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        let string_bytes = self.as_bytes();
        let string_bytes_len = match u16::try_from(string_bytes.len()) {
            Ok(v) => v,
            Err(_) => return Err(CodecError::EncodingError),
        };
        string_bytes_len.encode(buffer)?;
        buffer.extend_from_slice(&string_bytes);
        Ok(())
    }

    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let string_length = u16::decode(cursor)?;
        match std::str::from_utf8(cursor.consume(string_length.into())?) {
            Ok(s) => Ok(s.to_string()),
            Err(_) => Err(CodecError::DecodingError),
        }
    }
}

impl<T> Codec for Vec<T>
where
    T: Codec,
{
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        if self.len() >= (u32::MAX as usize) {
            return Err(CodecError::EncodingError);
        }
        encode_vec(VecSize::VecU32, buffer, self)
    }

    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        decode_vec(VecSize::VecU32, cursor)
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

impl<T: Codec> Codec for &T {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        (*self).encode(buffer)?;
        Ok(())
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
    // let len = slice.iter().fold(0, |acc, x| acc + x.serialized_len());
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
    // debug_assert!(len == buffer.len());
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
    log::trace!(
        "Decoding vector with size {:?}: {:X?}",
        vec_size,
        cursor.raw()
    );
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
