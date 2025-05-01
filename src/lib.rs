#[cfg(feature = "full")]
pub use full::*;
#[cfg(feature = "full")]
mod full {
    use std::io::{Write, Read};
    use super::*;

    pub struct FeistelEncoder<'a, W> {
        writer: &'a mut W,
    }

    impl<'a, W: Write> FeistelEncoder<'a, W> {
        pub fn new(writer: &'a mut W) -> Self {
            Self {
                writer,
            }
        }

        pub fn encode(&mut self, data: &[u8], keys: &[&[u8]]) {
            let mut tmp_1 = vec![0; data.len()];
            let mut tmp_2 = vec![0; data.len()];

            feistel(data, tmp_1.as_mut_slice(), keys[0]);
            feistel(tmp_1.as_slice(), tmp_2.as_mut_slice(), keys[1]);

            let hlf = data.len() / 2;

            // write second half of tmp_2
            // write first half of tmp_2
            let _ = self.writer.write(&tmp_2[hlf..]);
            let _ = self.writer.write(&tmp_2[..hlf]);
        }
    }

    pub struct FeistelDecoder<R> {
        reader: R,
    }

    impl<R: Read> FeistelDecoder<R> {
        pub fn new(reader: R) -> Self {
            Self {
                reader,
            }
        }

        pub fn decode(&mut self, out: &mut [u8], keys: &[&[u8]]) {
            let mut data = Vec::<u8>::with_capacity(out.len());
            match self.reader.read_to_end(&mut data) {
                Ok(_) => {},
                Err(err) => {
                    println!("Error reading from stream {:?}", err);
                    return;
                },
            }

            let mut tmp = vec![0; data.len()];

            feistel(&data, out, keys[1]);
            feistel(out, tmp.as_mut_slice(), keys[0]);

            let hlf = data.len() / 2;

            (&mut out[..hlf]).clone_from_slice(&tmp[hlf..]);
            (&mut out[hlf..]).clone_from_slice(&tmp[..hlf]);
        }
    }
}

pub fn feistel(data: &[u8], out: &mut [u8], key: &[u8]) {
    if data.len() != out.len() {
        panic!("data and output must be of the same length");
    }
    if data.len() % 2 != 0 {
        panic!("data length must be even :(");
    }

    out.copy_from_slice(data);

    let hlf = data.len() / 2;

    #[inline]
    fn xor_slice(out: &mut [u8], slc: &[u8]) {
        for i in 0..out.len() {
            out[i] ^= slc[i % slc.len()];
        }
    }

    // xor rhs in place with key (fn)
    xor_slice(&mut out[hlf..], key);
    // xor lhs and scrambled rhs into rhs
    xor_slice(&mut out[hlf..], &data[..hlf]);
    // copy data.rhs into out.lhs
    (&mut out[..hlf]).clone_from_slice(&data[hlf..]);
}


pub fn feistel_encrypt(data: &[u8], out: &mut [u8], keys: &[&[u8]]) {
    let mut tmp = vec![0; data.len()];

    feistel(data, out, keys[0]);
    feistel(out, tmp.as_mut_slice(), keys[1]);

    let hlf = data.len() / 2;

    (&mut out[..hlf]).clone_from_slice(&tmp[hlf..]);
    (&mut out[hlf..]).clone_from_slice(&tmp[..hlf]);
}

pub fn feistel_decrypt(data: &[u8], out: &mut [u8], keys: &[&[u8]]) {
    let mut tmp = vec![0; data.len()];

    feistel(data, out, keys[1]);
    feistel(out, tmp.as_mut_slice(), keys[0]);

    let hlf = data.len() / 2;

    (&mut out[..hlf]).clone_from_slice(&tmp[hlf..]);
    (&mut out[hlf..]).clone_from_slice(&tmp[..hlf]);
}

#[cfg(test)]
mod tests {
    use super::*;
    const KEYS: [&'static str; 2] = [
        "cnsifr", "sanumc"
    ];

    #[test]
    fn test_feistel_works() {
        let mut data: [u8; 12] = [115, 104, 97, 110, 101, 119, 97, 115, 104, 101, 114, 101];
        let mut out: [u8; 12] = [0; 12];

        let keys = [
            KEYS[0].as_bytes(), KEYS[1].as_bytes()
        ];
        feistel_encrypt(&data, &mut out, &keys);
        data.clone_from_slice(&out);

        feistel_decrypt(&data, &mut out, &keys);
        assert_eq!("shanewashere".to_string(), String::from_utf8(out.to_vec()).unwrap());
    }

    #[test]
    fn test_feistel_encoder() {
        let mut data: [u8; 12] = [115, 104, 97, 110, 101, 119, 97, 115, 104, 101, 114, 101];
        let mut out: [u8; 12] = [0; 12];

        let mut cursor = std::io::Cursor::new(out.as_mut_slice());
        let mut encoder = FeistelEncoder::new(&mut cursor);

        let keys = [
            KEYS[0].as_bytes(), KEYS[1].as_bytes()
        ];

        encoder.encode(&data, &keys);

        data.clone_from_slice(&out);

        feistel_decrypt(&data, &mut out, &keys);
        assert_eq!("shanewashere".to_string(), String::from_utf8(out.to_vec()).unwrap());
    }

    #[test]
    fn test_feistel_decoder() {
        let mut data: [u8; 12] = [115, 104, 97, 110, 101, 119, 97, 115, 104, 101, 114, 101];
        let mut out: [u8; 12] = [0; 12];

        let mut write_cursor = std::io::Cursor::new(out.as_mut_slice());
        let mut encoder = FeistelEncoder::new(&mut write_cursor);

        let keys = [
            KEYS[0].as_bytes(), KEYS[1].as_bytes()
        ];

        encoder.encode(&data, &keys);

        data.clone_from_slice(&out);

        let mut read_cursor = std::io::Cursor::new(data.as_slice());
        let mut decoder = FeistelDecoder::new(&mut read_cursor);
        decoder.decode(&mut out, &keys);
        assert_eq!("shanewashere".to_string(), String::from_utf8(out.to_vec()).unwrap());
    }
}
