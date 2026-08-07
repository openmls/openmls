//! Minimal DER (ASN.1) codec for the ECDSA-Sig-Value structure.
//!
//! MLS (RFC 9420 §5.1.2) requires ECDSA signatures to be DER-encoded, i.e.
//!
//! ```asn1
//! ECDSA-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }
//! ```
//!
//! while `libcrux-ecdsa` works with the raw `(r, s)` scalars. These helpers
//! convert between the two representations. Only the small encodings produced
//! by P-256 (each integer is at most 33 content bytes, the sequence at most ~70
//! bytes) are relevant, so short-form and single-byte long-form lengths are all
//! that is supported. This module deals purely with encoding.

const INTEGER_TAG: u8 = 0x02;
const SEQUENCE_TAG: u8 = 0x30;

const HIGH_BIT: u8 = 0x80;

/// DER-encode a big-endian unsigned integer as an ASN.1 `INTEGER`.
fn encode_integer(value: &[u8]) -> Vec<u8> {
    // Strip leading zero bytes, but keep at least one byte.
    let mut start = 0;
    while start + 1 < value.len() && value[start] == 0 {
        start += 1;
    }
    let mut content = value[start..].to_vec();

    // ASN.1 integers are signed. If the high bit is set, prepend a zero byte so
    // the value is interpreted as positive.
    if content.first().is_some_and(|b| b & HIGH_BIT != 0) {
        content.insert(0, 0x00);
    }

    let mut out = Vec::with_capacity(2 + content.len());
    out.push(INTEGER_TAG); // INTEGER tag
    out.push(content.len() as u8); // content length always < 128 for P-256
    out.extend_from_slice(&content);
    out
}

/// Encode a raw `(r, s)` P-256 signature (each 32 bytes) as a DER
/// `ECDSA-Sig-Value`.
pub(crate) fn raw_to_der(r: &[u8; 32], s: &[u8; 32]) -> Vec<u8> {
    let r_enc = encode_integer(r);
    let s_enc = encode_integer(s);
    let body_len = r_enc.len() + s_enc.len();

    let mut out = Vec::with_capacity(2 + body_len);
    out.push(SEQUENCE_TAG); // SEQUENCE tag
    out.push(body_len as u8); // body length always < 128 for P-256
    out.extend_from_slice(&r_enc);
    out.extend_from_slice(&s_enc);
    out
}

/// Read a DER length (short form or single-byte long form) starting at `*pos`,
/// advancing `*pos` past the length octets.
fn read_len(bytes: &[u8], pos: &mut usize) -> Option<usize> {
    let first = *bytes.get(*pos)?;
    *pos += 1;
    if first < 0x80 {
        Some(first as usize)
    } else if first == 0x81 {
        let len = *bytes.get(*pos)? as usize;
        *pos += 1;
        Some(len)
    } else {
        // Larger lengths cannot occur for P-256 signatures.
        None
    }
}

/// Read a DER `INTEGER` starting at `*pos` and return it left-padded to 32
/// bytes, advancing `*pos` past the integer.
fn read_integer_32(bytes: &[u8], pos: &mut usize) -> Option<[u8; 32]> {
    if *bytes.get(*pos)? != 0x02 {
        return None;
    }
    *pos += 1;
    let len = read_len(bytes, pos)?;
    let content = bytes.get(*pos..*pos + len)?;
    *pos += len;

    // Strip leading zero bytes (sign byte / minimal-encoding padding).
    let trimmed = {
        let mut start = 0;
        while start < content.len() && content[start] == 0 {
            start += 1;
        }
        &content[start..]
    };
    if trimmed.len() > 32 {
        return None;
    }

    let mut out = [0u8; 32];
    out[32 - trimmed.len()..].copy_from_slice(trimmed);
    Some(out)
}

/// Decode a DER `ECDSA-Sig-Value` into raw `(r, s)` scalars, each 32 bytes.
///
/// Returns `None` if the input is not a well-formed P-256 signature.
pub(crate) fn der_to_raw(der: &[u8]) -> Option<([u8; 32], [u8; 32])> {
    let mut pos = 0;
    if *der.get(pos)? != 0x30 {
        return None;
    }
    pos += 1;
    let seq_len = read_len(der, &mut pos)?;
    if pos + seq_len != der.len() {
        return None;
    }
    let r = read_integer_32(der, &mut pos)?;
    let s = read_integer_32(der, &mut pos)?;
    if pos != der.len() {
        return None;
    }
    Some((r, s))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_high_bit() {
        let r = [0x80u8; 32]; // high bit set → needs sign padding
        let s = [0x01u8; 32];
        let der = raw_to_der(&r, &s);
        let (r2, s2) = der_to_raw(&der).unwrap();
        assert_eq!(r, r2);
        assert_eq!(s, s2);
    }

    #[test]
    fn roundtrip_leading_zeros() {
        let mut r = [0u8; 32];
        r[31] = 0x2a; // small value with many leading zeros
        let s = [0xffu8; 32];
        let der = raw_to_der(&r, &s);
        let (r2, s2) = der_to_raw(&der).unwrap();
        assert_eq!(r, r2);
        assert_eq!(s, s2);
    }

    #[test]
    fn rejects_garbage() {
        assert!(der_to_raw(&[0x00, 0x01, 0x02]).is_none());
        assert!(der_to_raw(&[]).is_none());
    }
}
