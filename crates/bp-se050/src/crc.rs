//! CRC-16/X.25 (ISO 13239, the T=1 over I2C epilogue): reflected
//! polynomial 0x1021, initial value and final XOR 0xFFFF, sent low byte
//! first.

pub fn crc16(data: &[u8]) -> u16 {
    let mut c: u16 = 0xFFFF;
    for &b in data {
        c ^= b as u16;
        for _ in 0..8 {
            c = if c & 1 != 0 { (c >> 1) ^ 0x8408 } else { c >> 1 };
        }
    }
    !c
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_value_and_reference() {
        // the catalogue check value of CRC-16/X-25
        assert_eq!(crc16(b"123456789"), 0x906E);
        let mut x = 7u32;
        for len in 0..300 {
            let d: std::vec::Vec<u8> = (0..len)
                .map(|_| {
                    x = x.wrapping_mul(1_103_515_245).wrapping_add(12345);
                    (x >> 16) as u8
                })
                .collect();
            assert_eq!(crc16(&d), se05x::t1::Crc::calculate(&d), "{len}");
        }
    }
}
