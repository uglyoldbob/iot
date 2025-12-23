//! A collection of random utility functions and structures

/// Decode a hex string to a vec of bytes
pub fn decode_hex(s: &str) -> Result<Vec<u8>, std::num::ParseIntError> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect()
}

/// Encode a vec of bytes to a hex string with no separators
pub fn encode_hex(d: &[u8]) -> String {
    let mut start_index = 0;
    let mut i = 0;
    let start_index = loop {
        if i < d.len() {
            if d[i] != 0 {
                break i;
            }
            i += 1;
        } else {
            break i;
        }
    };
    let serhex: Vec<String> = d
        .iter()
        .skip(start_index)
        .map(|e| format!("{:02x}", e))
        .collect();
    serhex.join("")
}

/// Generate a password of the specified length
pub fn generate_password(len: usize) -> String {
    use rand::Rng;
    /// The characters to pick from for a randomly generated password
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                            abcdefghijklmnopqrstuvwxyz\
                            0123456789\
                            `~!@#$%^&*()-_=+[]{}\\|;:'\",<.>/?";
    let mut rng = rand::thread_rng();
    (0..len)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}

/// Hash and convert to der format
pub fn rsa_sha256(hash: &[u8]) -> Vec<u8> {
    let mut hash = hash.to_vec();
    // convert to der format, indicating sha-256 hash present
    let mut der_hash = vec![
        0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        0x05, 0x00, 0x04, 0x20,
    ];
    der_hash.append(&mut hash);
    der_hash
}

/// apply pkcs1.5 padding to pkcs1 hash, suitable for signing.
/// # Arguments
/// * total_size - Size in bits
/// * hash - The hash needs to be in der format.
pub fn pkcs15_sha256(total_size: usize, hash: &[u8]) -> Vec<u8> {
    // convert to der format, indicating sha-256 hash present
    let mut der_hash = rsa_sha256(hash);

    let plen = total_size - der_hash.len() - 3;
    let mut p = vec![0xff; plen];

    let mut total = Vec::new();
    total.append(&mut vec![0, 1]);
    total.append(&mut p);
    total.push(0);
    total.append(&mut der_hash);
    total
}

pub struct DroppingProcess {
    c: std::process::Child,
}

impl Drop for DroppingProcess {
    fn drop(&mut self) {
        self.c.kill();
        self.c.wait();
    }
}

/// Runs the java smartcard simulator
pub fn run_smartcard_sim() -> Option<DroppingProcess> {
    let mut p = std::process::Command::new("java");
    let a = p.args([
        "-classpath", 
        "jcardsim/target/jcardsim-3.0.5-SNAPSHOT.jar:javacard-sdk/jc305u3_kit/lib/api_classic.jar:PivApplet/bin", 
        "com.licel.jcardsim.remote.VSmartCard", 
        "jcardsim.cfg"]).spawn();
    if let Ok(a) = a {
        let mut b = std::process::Command::new("opensc-tool");
        let mut p = b.args([
            "--card-driver",
            "default",
            "--send-apdu",
            "80b80000120ba000000308000010000100050000020F0F7f",
        ]);
        std::thread::sleep(std::time::Duration::from_secs(5));
        let asdf = p
            .output()
            .expect("Failed to initialize smartcard simulator");
        service::log::info!(
            "Initialize output is {}",
            String::from_utf8(asdf.stdout).unwrap()
        );
        Some(DroppingProcess { c: a })
    } else {
        None
    }
}
