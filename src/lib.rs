const KEYS: [&'static str; 2] = [
    "cnsifr", "sanumc"
];

pub fn feistel(data: &[u8], out: &mut [u8], key: usize) {
    if data.len() != out.len() {
        panic!("data and output must be of the same length");
    }
    if data.len() % 2 != 0 {
        panic!("data length must be even :(");
    }

    out.copy_from_slice(data);

    let hlf = data.len() / 2;

    fn xor_slice(out: &mut [u8], slc: &[u8]) {
        for i in 0..out.len() {
            out[i] ^= slc[i % out.len()];
        }
    }

    // xor rhs in place with key (fn)
    xor_slice(&mut out[hlf..], KEYS[key].as_bytes());
    // xor lhs and scrambled rhs into rhs
    xor_slice(&mut out[hlf..], &data[..hlf]);
    // copy data.rhs into out.lhs
    (&mut out[..hlf]).clone_from_slice(&data[hlf..]);
}

pub fn feistel_encrypt(data: &[u8], out: &mut [u8]) {
    let mut tmp = vec![0; data.len()];

    feistel(data, tmp.as_mut_slice(), 0);
    feistel(tmp.as_slice(), out, 1);

    let hlf = data.len() / 2;

    (&mut tmp[..hlf]).clone_from_slice(&out[hlf..]);
    (&mut tmp[hlf..]).clone_from_slice(&out[..hlf]);
    out.copy_from_slice(&tmp[..]);
}

pub fn feistel_decrypt(data: &[u8], out: &mut [u8]) {
    let mut tmp = vec![0; data.len()];

    feistel(data, tmp.as_mut_slice(), 1);
    feistel(tmp.as_slice(), out, 0);

    let hlf = data.len() / 2;

    (&mut tmp[..hlf]).clone_from_slice(&out[hlf..]);
    (&mut tmp[hlf..]).clone_from_slice(&out[..hlf]);
    out.copy_from_slice(&tmp[..]);
}

#[test]
fn test_feistel_works() {
    let mut data: [u8; 12] = [115, 104, 97, 110, 101, 119, 97, 115, 104, 101, 114, 101];
    let mut out: [u8; 12] = [0; 12];

    feistel_encrypt(&data, &mut out);
    data.clone_from_slice(&out);

    feistel_decrypt(&data, &mut out);
    assert_eq!("shanewashere".to_string(), String::from_utf8(out.to_vec()).unwrap());
}
