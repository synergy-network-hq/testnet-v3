pub const CHECKSUM_SYMBOLS: usize = 6;
const CHECKSUM_CONSTANT: u32 = 0x2bc8_30a3;
const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

pub fn convert_to_words(bytes: &[u8]) -> Vec<u8> {
    let mut accumulator = 0_u32;
    let mut bits = 0_u8;
    let mut words = Vec::with_capacity((bytes.len() * 8).div_ceil(5));
    for byte in bytes {
        accumulator = (accumulator << 8) | u32::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            words.push(((accumulator >> bits) & 31) as u8);
        }
    }
    if bits > 0 {
        words.push(((accumulator << (5 - bits)) & 31) as u8);
    }
    words
}

pub fn encode(hrp: &str, payload: &[u8]) -> Result<String, String> {
    if hrp.is_empty()
        || !hrp.bytes().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        || payload.is_empty()
        || payload.iter().any(|word| *word > 31)
    {
        return Err("invalid Bech32m address input".into());
    }
    let mut values = hrp_expand(hrp);
    values.extend_from_slice(payload);
    values.extend_from_slice(&[0; CHECKSUM_SYMBOLS]);
    let checksum = polymod(&values) ^ CHECKSUM_CONSTANT;
    let mut encoded = String::with_capacity(hrp.len() + 1 + payload.len() + CHECKSUM_SYMBOLS);
    encoded.push_str(hrp);
    encoded.push('1');
    for word in payload {
        encoded.push(CHARSET[*word as usize] as char);
    }
    for shift in (0..CHECKSUM_SYMBOLS).rev() {
        encoded.push(CHARSET[((checksum >> (shift * 5)) & 31) as usize] as char);
    }
    Ok(encoded)
}

pub fn validate(value: &str) -> Result<(), String> {
    let separator = value
        .rfind('1')
        .filter(|separator| *separator > 0 && value.len().saturating_sub(*separator) > CHECKSUM_SYMBOLS)
        .ok_or("invalid Bech32m separator")?;
    let hrp = &value[..separator];
    let mut values = hrp_expand(hrp);
    for byte in value[separator + 1..].bytes() {
        let word = CHARSET
            .iter()
            .position(|candidate| *candidate == byte)
            .ok_or("invalid Bech32m data symbol")?;
        values.push(word as u8);
    }
    if polymod(&values) != CHECKSUM_CONSTANT {
        return Err("invalid Bech32m checksum".into());
    }
    Ok(())
}

fn hrp_expand(hrp: &str) -> Vec<u8> {
    let mut expanded = Vec::with_capacity(hrp.len() * 2 + 1);
    expanded.extend(hrp.bytes().map(|byte| byte >> 5));
    expanded.push(0);
    expanded.extend(hrp.bytes().map(|byte| byte & 31));
    expanded
}

fn polymod(values: &[u8]) -> u32 {
    const GENERATORS: [u32; 5] = [
        0x3b6a_57b2,
        0x2650_8e6d,
        0x1ea1_19fa,
        0x3d42_33dd,
        0x2a14_62b3,
    ];
    let mut checksum = 1_u32;
    for value in values {
        let top = checksum >> 25;
        checksum = ((checksum & 0x01ff_ffff) << 5) ^ u32::from(*value);
        for (index, generator) in GENERATORS.iter().enumerate() {
            if ((top >> index) & 1) != 0 {
                checksum ^= generator;
            }
        }
    }
    checksum
}
