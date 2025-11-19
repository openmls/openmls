//! # GREASE Support for MLS
//!
//! This module implements GREASE (Generate Random Extensions And Sustain
//! Extensibility) as defined in [RFC 9420 Section 13.5](https://www.rfc-editor.org/rfc/rfc9420.html#section-13.5).
//!
//! GREASE values are used to ensure that implementations properly handle
//! unknown values and maintain extensibility. The GREASE values follow a
//! specific pattern where both bytes are of the form `0x_A` (e.g., 0x0A0A,
//! 0x1A1A, 0x2A2A, etc.).
//!
//! ## Purpose
//!
//! GREASE helps prevent extensibility failures by:
//! - Ensuring implementations don't reject unknown values
//! - Testing that parsers properly handle unexpected values
//! - Maintaining forward compatibility
//!
//! ## Usage in MLS
//!
//! GREASE values are automatically added to capability lists in KeyPackages and
//! LeafNodes. During validation, GREASE values are automatically filtered out
//! and ignored, ensuring they don't interfere with capability checking or other
//! validation logic.

use openmls_traits::random::OpenMlsRand;

// Re-export GREASE constants and functions from traits crate
pub use openmls_traits::grease::{is_grease_value, GREASE_VALUES};

/// Returns a random GREASE value from the set of valid GREASE values.
///
/// This function uses the provided random number generator to select one of the
/// 15 valid GREASE values defined in RFC 9420.
///
/// # Arguments
///
/// * `rand` - A random number generator implementing [`OpenMlsRand`]
///
/// # Returns
///
/// A randomly selected GREASE value
///
/// # Examples
///
/// ```
/// use openmls::grease::random_grease_value;
/// use openmls_rust_crypto::RustCrypto;
///
/// let crypto = RustCrypto::default();
/// let grease = random_grease_value(&crypto);
/// assert!(openmls::grease::is_grease_value(grease));
/// ```
pub fn random_grease_value(rand: &impl OpenMlsRand) -> u16 {
    // Generate a random index into the GREASE_VALUES array
    let random_bytes: [u8; 1] = rand
        .random_array()
        .expect("Failed to generate random bytes");
    let index = (random_bytes[0] % GREASE_VALUES.len() as u8) as usize;
    GREASE_VALUES[index]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_grease_values_are_valid() {
        // All defined GREASE values should be recognized as GREASE
        for &value in &GREASE_VALUES {
            assert!(
                is_grease_value(value),
                "GREASE value 0x{:04X} not recognized",
                value
            );
        }
    }

    #[test]
    fn test_non_grease_values() {
        // Test various non-GREASE values
        let non_grease = [
            0x0000, 0x0001, 0x0002, 0x00FF, 0x0100, 0x0A00, 0x00A0, 0x1111, 0x2222, 0xFFFF, 0x0B0B,
            0x1B1B, // Wrong pattern (0xB instead of 0xA)
        ];

        for &value in &non_grease {
            assert!(
                !is_grease_value(value),
                "Non-GREASE value 0x{:04X} incorrectly identified as GREASE",
                value
            );
        }
    }

    #[test]
    fn test_all_grease_values_unique() {
        // Ensure all GREASE values are unique
        let mut sorted = GREASE_VALUES;
        sorted.sort_unstable();
        for i in 1..sorted.len() {
            assert_ne!(
                sorted[i - 1],
                sorted[i],
                "Duplicate GREASE value found: 0x{:04X}",
                sorted[i]
            );
        }
    }

    #[test]
    fn test_grease_values_count() {
        // RFC 9420 defines exactly 15 GREASE values
        assert_eq!(GREASE_VALUES.len(), 15);
    }

    #[test]
    fn test_random_grease_value() {
        let crypto = openmls_rust_crypto::RustCrypto::default();

        // Generate multiple random GREASE values and verify they're all valid
        for _ in 0..100 {
            let value = random_grease_value(&crypto);
            assert!(
                is_grease_value(value),
                "random_grease_value returned non-GREASE value: 0x{:04X}",
                value
            );
        }
    }
}
