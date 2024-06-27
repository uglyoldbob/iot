use der::DecodePem;
use der::Encode;
use ring::signature::UnparsedPublicKey;
use ring::signature::RSA_PKCS1_2048_8192_SHA256;
use tokio::io::AsyncReadExt;
use yasna::parse_der;

//TODO: convert this to a test

use cert_common::oid;

/// Represents a raw certificate signing request, in pem format
pub struct RawCsrRequest {
    /// The csr, in pem format
    pub pem: String,
}

impl RawCsrRequest {
    /// Verifies the signature on the request
    pub fn verify_request(&self) -> Result<(), ()> {
        let pem = pem::parse(&self.pem).unwrap();
        let der = pem.contents();
        let parsed = yasna::parse_der(der, |r| {
            let info = r.read_sequence(|r| {
                let a = r.next().read_der()?;
                println!("A is {} {:02X?}", a.len(), a);
                let sig_alg = r.next().read_sequence(|r| {
                    let alg = r.next().read_oid()?;
                    r.next().read_null()?;
                    Ok(alg)
                })?;
                let (sig, _) = r.next().read_bitvec_bytes()?;
                Ok((a, sig_alg, sig))
            })?;
            Ok(info)
        });
        if let Ok((info, alg, sig)) = parsed {
            use der::Decode;
            let cinfo = x509_cert::request::CertReqInfo::from_der(&info).unwrap();
            let pubkey = cinfo.public_key.subject_public_key;
            let pder = pubkey.to_der().unwrap();
            let pkey = parse_der(&pder, |r| {
                let (data, _size) = r.read_bitvec_bytes()?;
                Ok(data)
            })
            .unwrap();

            if alg == oid::OID_PKCS1_SHA256_RSA_ENCRYPTION.to_yasna() {
                let csr_key = UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, &pkey);
                csr_key.verify(&info, &sig).map_err(|_| {
                    println!("Error verifying the signature2 on the csr 1");
                })
            } else {
                todo!();
            }
        } else {
            Err(())
        }
    }
}

pub async fn verify_request2(
    csr: &x509_cert::request::CertReq,
) -> Result<&x509_cert::request::CertReq, ()> {
    for (i, a) in csr.info.attributes.iter().enumerate() {
        println!("Attribute {} is {:?}", i, a);
    }
    let info = csr.info.to_der().unwrap();
    let pubkey = &csr.info.public_key;
    let signature = &csr.signature;

    let p = &pubkey.subject_public_key;
    let pder = p.to_der().unwrap();

    let pkey = parse_der(&pder, |r| {
        let (data, _size) = r.read_bitvec_bytes()?;
        Ok(data)
    })
    .unwrap();

    assert!(untrusted::Input::from(&pkey)
        .read_all(ring::error::Unspecified, |input| ring::io::der::nested(
            input,
            ring::io::der::Tag::Sequence,
            ring::error::Unspecified,
            |input| {
                let _ = ring::io::der::positive_integer(input)?;
                let _ = ring::io::der::positive_integer(input)?;
                Ok(())
            }
        ))
        .is_ok());

    let csr_key = UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, &pkey);
    use base64::Engine;
    let b64 = base64::prelude::BASE64_STANDARD.encode(&info);
    println!("BASE64 {}", b64);

    let info2 = [info.clone(), vec![0x80 as u8]].concat();

    let manual_sha256 = sha256::digest(&info);
    println!("Manual sha256 is {}", manual_sha256);

    let info2 = [&info, signature.as_bytes().unwrap()].concat();

    let e1 = csr_key
        .verify(&info, signature.as_bytes().unwrap())
        .map_err(|_| {
            println!("Error verifying the signature on the csr 1");
        });
    if e1.is_ok() {
        println!("SUCCESS VALIDATE SIGNATURE");
    }

    csr_key
        .verify(&info2, signature.as_bytes().unwrap())
        .map_err(|_| {
            println!("Error verifying the signature2 on the csr 1");
        })?;
    //TODO perform more validation of the csr
    Ok(csr)
}

#[tokio::main]
async fn main() {
    println!("Running test2 program");

    let mut settings_con = Vec::new();
    let mut f = tokio::fs::File::open("./test-csr.pem").await.unwrap();
    f.read_to_end(&mut settings_con).await.unwrap();
    let pem = std::str::from_utf8(&settings_con).unwrap();
    println!("{}", pem);

    let rawcsr = RawCsrRequest {
        pem: pem.to_string(),
    };
    let rawcheck = rawcsr.verify_request();
    println!("Rawcheck is {:?}", rawcheck);

    let csr = x509_cert::request::CertReq::from_pem(pem).unwrap();
    let a = verify_request2(&csr).await;
    println!("Result is {:?}", a);
}
