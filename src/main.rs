extern crate crypto;

// use crypto::ed25519;
use crypto::sha2::Sha256;
use crypto::digest::Digest;

fn main() {
    println!("start");

    let mut sha256 = Sha256::new();

    let hash_input: Vec<u8> = Vec::with_capacity(512);
    sha256.input(hash_input.as_ref());

    println!("sha256(NULL, NULL): {}", sha256.result_str());

    // let verify_key_path = "vk.bin";

    // let verify_key_path_utf8 = verify_key_path.as_bytes();

    // println!("len verify_key_path: {}", verify_key_path.len());
    // println!("len verify_key_path_utf8: {}", verify_key_path_utf8.len());
}

#[test]
fn test_sha_256_empty()
{
    let mut sha256 = Sha256::new();
    let hash_input: Vec<u8> = Vec::with_capacity(512);
    sha256.input(hash_input.as_ref());
    assert_eq!(sha256.result_str(), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}