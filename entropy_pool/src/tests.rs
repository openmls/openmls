use evercrypt::prelude::tag_size;

use crate::{EntropyPoolError, SUPPORTED_HKDF_MODES};

use super::EntropyPool;

#[test]
fn test_pool_initialization() {
    for mode in SUPPORTED_HKDF_MODES {
        // Two pools should be initialized with different value.
        let pool1 = EntropyPool::new(mode);
        let pool2 = EntropyPool::new(mode);

        assert_ne!(pool1.value, pool2.value)
    }
}

#[test]
fn test_randomness_extraction() {
    // A pool should extract different randomness each time. (This is just a
    // simple sanity-check, not a guarantee for random output.)
    for mode in SUPPORTED_HKDF_MODES {
        let mut pool = EntropyPool::new(mode);

        let original_pool = pool.clone();

        let mut pool_copy = pool.clone();

        let randomness = pool.extract(10).expect("error extracting randomness");
        let randomness_copy = pool_copy.extract(10).expect("error extracting randomness");

        // The resulting randomness should be different.
        assert_ne!(randomness, randomness_copy);

        // The pool state after the extraction should be different.
        assert_ne!(pool.value, pool_copy.value);

        // The pool state should not be the same as before the extraction.
        assert_ne!(pool.value, original_pool.value);
        assert_ne!(pool_copy.value, original_pool.value);
    }
}

#[test]
fn test_randomness_injection() {
    // Injecting randomness into a pool should change its value, again just a
    // sanity check, not proof that the entropy has increased.
    for mode in SUPPORTED_HKDF_MODES {
        let mut pool = EntropyPool::new(mode);

        let pool_copy = pool.clone();

        pool.inject(b"test");

        assert_ne!(pool.value, pool_copy.value);
    }
}

#[test]
fn test_max_length() {
    // Trying to extract randomness of too big of a length should yield an
    // error.
    for mode in SUPPORTED_HKDF_MODES {
        let mut pool = EntropyPool::new(mode);

        let length = tag_size(pool.hkdf_mode().into()) * 255 + 1;

        let length_error = pool
            .extract(length as u16)
            .expect_err("no error when extracting randomness with too big length value");

        assert_eq!(EntropyPoolError::LengthError, length_error);
    }
}
