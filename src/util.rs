const XOR_TABLE: &[u8] = b"-ODIFIED&W0ROPERTY3HEET7ITH/+4HE3HEET)$3?,$!0?!5?02/0%24)%3.5,,\x10&7?70?/\"*%#43";

#[inline]
fn translate_byte(i: usize, c: u8) -> u8 {
    match (c % 255) ^ XOR_TABLE[i % XOR_TABLE.len()] {
        0 => 255,
        v => v,
    }
}

fn translate<P: AsRef<[u8]>>(data: P) -> Vec<u8> {
    data.as_ref()
        .iter()
        .enumerate()
        .rev()
        .map(|(i, c)| translate_byte(i, *c))
        .collect::<Vec<u8>>()
}

pub fn snx_encrypt<P: AsRef<[u8]>>(data: P) -> String {
    hex::encode(translate(data))
}
