#![no_main]
use libfuzzer_sys::fuzz_target;
use milagro_bls::{compress_g2, decompress_g2};

fuzz_target!(|data: &[u8]| {
    if let Ok(point) = decompress_g2(data) {
        let compressed_data = compress_g2(&point);
        assert_eq!(data.to_vec(), compressed_data);
    }
});
