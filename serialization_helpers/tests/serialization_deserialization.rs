#[derive(
    PartialEq,
    Eq,
    Clone,
    Debug,
    openmls_serialization_helpers::Serialize,
    openmls_serialization_helpers::Deserialize,
)]
enum TestEnum {
    #[storage_tag = 0]
    Unit,
    #[storage_tag = 3]
    Unit2,
    #[storage_tag = 2000]
    Value(u64),
    #[storage_tag = 2]
    Data([u8; 3]),
    #[storage_tag = 500]
    Data2(u64, [u8; 3]),
    #[storage_tag = 4]
    Unit3,
}

struct TestCase {
    data: TestEnum,
    expected_tag: u16,
}

#[test]
/// Test non-self-describing serialization/deserialization with `postcard`
fn test_serialization_deserialization_postcard() {
    for TestCase {
        data,
        expected_tag: expected_discriminant,
    } in TEST_CASES
    {
        // serialize the variant
        let serialized = &postcard::to_allocvec(&data).expect("serialization failed");

        // check the serialized discriminant
        // NOTE: `postcard` uses a variable-length encoding for integers,
        // so the discriminant is serialized as a plain `u32`
        // and then compared to the first bytes of the serialized variant
        let serialized_discriminant =
            &postcard::to_allocvec(&(*expected_discriminant as u32)).unwrap();
        assert!(serialized.starts_with(serialized_discriminant));

        // deserialize the variant
        let deserialized: TestEnum =
            postcard::from_bytes(serialized).expect("deserialization failed");

        // check that the deserialized data matches the
        // original data
        assert_eq!(data, &deserialized);
    }
}

/// An identical version of [`TestEnum`] for comparison
#[derive(serde::Serialize)]
enum TestEnumCompare {
    Unit,
    Unit2,
    Value(u64),
    Data([u8; 3]),
    Data2(u64, [u8; 3]),
    Unit3,
}

impl From<&TestEnum> for TestEnumCompare {
    fn from(orig: &TestEnum) -> Self {
        match orig {
            TestEnum::Unit => Self::Unit,
            TestEnum::Unit2 => Self::Unit2,
            TestEnum::Value(value) => Self::Value(*value),
            TestEnum::Data(data) => Self::Data(*data),
            TestEnum::Data2(value, data) => Self::Data2(*value, *data),
            TestEnum::Unit3 => Self::Unit3,
        }
    }
}

#[test]
/// Test self-describing serialization/deserialization with `serde_json`
fn test_serialization_deserialization_serde_json() {
    for TestCase { data, .. } in TEST_CASES {
        // serialize the variant
        let serialized = serde_json::to_string(&data).expect("serialization failed");

        // serialize the version with a derived `serde::Serialize`
        let serialized_compare = serde_json::to_string(&TestEnumCompare::from(data)).unwrap();
        // check that the serialization is identical
        assert_eq!(serialized, serialized_compare);

        // deserialize the variant
        let deserialized: TestEnum =
            serde_json::from_str(&serialized).expect("deserialization failed");

        // check that the deserialized data matches the
        // original data
        assert_eq!(data, &deserialized);
    }
}

const TEST_CASES: &[TestCase] = &[
    TestCase {
        data: TestEnum::Unit,
        expected_tag: 0,
    },
    TestCase {
        data: TestEnum::Unit2,
        expected_tag: 3,
    },
    TestCase {
        data: TestEnum::Data([1, 2, 3]),
        expected_tag: 2,
    },
    TestCase {
        data: TestEnum::Data2(0, [1, 2, 3]),
        expected_tag: 500,
    },
    TestCase {
        data: TestEnum::Value(0),
        expected_tag: 2000,
    },
    TestCase {
        data: TestEnum::Value(60),
        expected_tag: 2000,
    },
    TestCase {
        data: TestEnum::Unit3,
        expected_tag: 4,
    },
];
