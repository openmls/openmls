// Testing some codec functions

use openmls::prelude::*;

#[test]
fn string_codec() {
    let s = "Codec Test String".to_string();
    let encoded_s = s.encode_detached().unwrap();
    let decoded_s = String::decode(&mut Cursor::new(&encoded_s)).unwrap();
    assert_eq!(s, decoded_s);
}

#[test]
fn vec_codec() {
    fn test<T: Codec + std::fmt::Debug + PartialEq>(vec: Vec<T>) {
        let encoded_vec = vec.encode_detached().unwrap();
        let decoded_vec = Vec::<T>::decode(&mut Cursor::new(&encoded_vec)).unwrap();
        assert_eq!(vec, decoded_vec);
    }

    test(vec![0u8, 1, 2, 3, 4]);
    test(vec![vec![0u8, 1, 2, 3, 4], vec![0u8, 1, 2, 3, 4]]);
}
