//! # GREASE Values for MLS
//!
//! This module defines the GREASE (Generate Random Extensions And Sustain
//! Extensibility) values as specified in [RFC 9420 Section 13.5](https://www.rfc-editor.org/rfc/rfc9420.html#section-13.5).
//!
//! GREASE values are used to ensure that implementations properly handle
//! unknown values and maintain extensibility.

/// All valid GREASE values as defined in RFC 9420.
/// These follow the pattern 0x_A_A where _ is 0-E.
pub const GREASE_VALUES: [u16; 15] = [
    0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A, 0x8A8A, 0x9A9A, 0xAAAA, 0xBABA,
    0xCACA, 0xDADA, 0xEAEA,
];

/// Checks if a given u16 value is a valid GREASE value.
///
/// GREASE values follow the pattern where both bytes are of the form 0x_A,
/// where the high nibble can be 0-E (0x0A0A through 0xEAEA).
#[inline]
pub const fn is_grease_value(value: u16) -> bool {
    matches!(
        value,
        0x0A0A
            | 0x1A1A
            | 0x2A2A
            | 0x3A3A
            | 0x4A4A
            | 0x5A5A
            | 0x6A6A
            | 0x7A7A
            | 0x8A8A
            | 0x9A9A
            | 0xAAAA
            | 0xBABA
            | 0xCACA
            | 0xDADA
            | 0xEAEA
    )
}
