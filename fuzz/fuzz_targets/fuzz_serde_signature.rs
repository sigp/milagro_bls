#![no_main]
use libfuzzer_sys::fuzz_target;
use milagro_bls::Signature;

fuzz_target!(|data: &[u8]| {
    if let Ok(point) = Signature::from_bytes(data) {
        let data_round_trip = point.as_bytes();
        assert_eq!(data.to_vec(), data_round_trip);
    }
});
