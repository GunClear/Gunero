extern crate crypto;
extern crate libc;
extern crate rand;
extern crate secp256k1;
extern crate tiny_keccak;

use std::env;
use rand::Rng;
use secp256k1::{Secp256k1, SecretKey, PublicKey};
use tiny_keccak::keccak256;
// use std::io;
// use std::io::BufRead;
//use std::io::prelude::*;
// use std::fs::File;
// use crypto::ed25519;
use crypto::sha2::Sha256;
use crypto::digest::Digest;
use libc::c_char;
use std::ffi::CString;
// use std::str;

#[link(name="silencerd")]
extern "C" {
    //Prove Membership
    fn prove_membership(
        WHex: *const c_char,
        N_account: u8,
        V_accountHex: *const c_char,
        s_accountHex: *const c_char,
        M_accountPath: *const c_char,
        A_accountHex: *const c_char,
        r_accountHex: *const c_char,
        pkPath: *const c_char,
        vkPath: *const c_char,
        proofPath: *const c_char
        ) -> i32;
    //Verify Membership
    fn verify_membership(
        WHex: *const c_char,
        N_account: u8,
        V_accountHex: *const c_char,
        vkPath: *const c_char,
        proofPath: *const c_char
        ) -> i32;
}

fn main() {
    let _args: Vec<String> = env::args().collect();

    // let file = match File::open("my_file.txt") {
    //     Ok(file) => file,
    //     Err(..) => panic!("boom"),
    // };
    // let mut reader = std::io::BufReader::new(&file);
    // let buffer_string = &mut String::new();
    // reader.read_line(buffer_string);

    // let verify_key_path = "vk.bin";

    // let verify_key_path_utf8 = verify_key_path.as_bytes();

    // println!("len verify_key_path: {}", verify_key_path.len());
    // println!("len verify_key_path_utf8: {}", verify_key_path_utf8.len());

    // let reader: io::Stdin = io::stdin();
    // let mut input_text: String = String::new();
    // let result: Result<usize, io::Error> = reader.read_line(&mut input_text);
    // if result.is_err() {
    //     println!("failed to read from stdin");
    //     return;
    // }
    // let input_text_trimmed = input_text.trim();

    let mut rng = rand::thread_rng();

    //Generate basic variables
    let mut s_account: Vec<u8> = (0..32).map(|_v| rng.gen()).collect();
    let N_account = 1u8;
    let r_account: Vec<u8> = (0..32).map(|_v| rng.gen()).collect();

    //Check s_account for 252 compliance
    if s_account[0] > 15 {
        s_account[0] &= 0x0F;
    }

    //Create keys and account
    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(&secp, &s_account).expect("32 bytes, within curve order");
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);

    let public_key_bytes_extra: [u8; 65] = public_key.serialize_uncompressed();
    assert_eq!(public_key_bytes_extra[0], 4);
    let mut public_key_bytes = [0u8; 64];
    //Because of the tragicly bad copying system in Rust
    for index in 1..65
    {
        public_key_bytes[index - 1] = public_key_bytes_extra[index];
    }
    let public_key_bytes_keccak256 = keccak256(&public_key_bytes);
    let mut A_account = [0u8; 20];
    //Because of the tragicly bad copying system in Rust
    for index in 12..32
    {
        A_account[index - 12] = public_key_bytes_keccak256[index];
    }

    println!("s_account: {}", to_hex(&s_account));
    println!("secret_key: {}", secret_key);
    println!("public_key: {}", public_key);
    println!("A_account: {}", to_hex(&A_account));
    println!("N_account: {}", N_account);
    println!("r_account: {}", to_hex(&r_account));

    let test_variables = make_test_variables(&s_account, &A_account.to_vec(), N_account, &r_account);

    println!("P_proof: {}", to_hex(&test_variables.P_proof));
    println!("leaf: {}", to_hex(&test_variables.leaf));
    println!("M_account: {}", test_variables.M_account.len());
    println!("W: {}", to_hex(&test_variables.W));
    println!("V_account: {}", to_hex(&test_variables.V_account));

    // let W_hex = to_hex(&test_variables.W);
    let W_hex = CString::new(to_hex(&test_variables.W)).expect("CString::new failed");
    let V_account_hex = CString::new(to_hex(&test_variables.V_account)).expect("CString::new failed");
    let s_account_hex = CString::new(to_hex(&s_account)).expect("CString::new failed");
    let A_account_hex = CString::new(to_hex(&A_account)).expect("CString::new failed");
    let r_account_hex = CString::new(to_hex(&r_account)).expect("CString::new failed");

    let pk_path = CString::new("/home/sean/Gunero/demo/GTM.pk.bin").expect("CString::new failed");
    let vk_path = CString::new("/home/sean/Gunero/demo/GTM.vk.bin").expect("CString::new failed");
    let proof_path = CString::new("/home/sean/Gunero/demo/GTM.proof.bin").expect("CString::new failed");

    let ret = unsafe {
        prove_membership(
            W_hex.as_ptr(),
            N_account,
            V_account_hex.as_ptr(),
            s_account_hex.as_ptr(),
            M_account_hex.as_ptr(),
            A_account_hex.as_ptr(),
            r_account_hex.as_ptr(),
            pk_path.as_ptr(),
            vk_path.as_ptr(),
            proof_path.as_ptr()
        )
    };

    if ret == 0 {
        //Success

        let ret = unsafe {
            verify_membership(
                W_hex.as_ptr(),
                N_account,
                V_account_hex.as_ptr(),
                vk_path.as_ptr(),
                proof_path.as_ptr()
            )
        };
        if ret == 0 {
            //Success
            println!("Success!");
        }
        else {
            //Failure
            println!("Failure 2!");
        }
    }
    else {
        //Failure
        println!("Failure 1!");
    }
}

struct TestVariables {
    P_proof: Vec<u8>,
    leaf: Vec<u8>,
    M_account : Vec<Vec<u8>>,
    W: Vec<u8>,
    V_account: Vec<u8>,
}

fn make_test_variables(
        s_account : &Vec<u8>,
        A_account : &Vec<u8>,
        N_account : u8,
        r_account : &Vec<u8>)
        -> TestVariables {
    assert_eq!(s_account.len(), 32);
    assert_eq!(r_account.len(), 32);

    let mut sha256 = Sha256::new();

    //Generate P_proof from s_account
    //P_proof = Hash(0000b | (s_account&252b), 0)
    let mut hash_input_left = s_account.to_vec();
    let mut hash_input_right = [0u8; 32].to_vec();//: Vec<u8> = Vec::with_capacity(32);
    assert_eq!(hash_input_left.len(), 32);
    assert_eq!(hash_input_right.len(), 32);

    let mut hash_input: Vec<u8> = Vec::with_capacity(64);
    hash_input.append(&mut hash_input_left);
    hash_input.append(&mut hash_input_right);
    assert_eq!(hash_input_left.len(), 0);
    assert_eq!(hash_input_right.len(), 0);
    assert_eq!(hash_input.len(), 64);
    sha256.input(hash_input.as_ref());

    let mut P_proof = [0u8; 32];
    sha256.result(&mut P_proof);
    sha256.reset();

    //Generate leaf from P_proof and N_account
    //leaf = hash(P_proof,N_account)
    hash_input_left = P_proof.to_vec();
    hash_input_right = [0u8; 32].to_vec();//Vec::with_capacity(32);
    assert_eq!(hash_input_left.len(), 32);
    assert_eq!(hash_input_right.len(), 32);

    let mut hash_input = Vec::with_capacity(64);
    hash_input.append(&mut hash_input_left);
    hash_input.append(&mut hash_input_right);
    assert_eq!(hash_input_left.len(), 0);
    assert_eq!(hash_input_right.len(), 0);
    assert_eq!(hash_input.len(), 64);

    sha256.input(hash_input.as_ref());

    let mut leaf = [0u8; 32];
    sha256.result(&mut leaf);
    sha256.reset();

    //Generate M_account from A_account
    let mut prev_hash = leaf.clone();
    let mut M_account: Vec<Vec<u8>> = vec![vec![0u8; 32]; 160];
    let mut rng = rand::thread_rng();
    for level in (0..160).rev()
    {
        //Calculate uncle position
        //Bit [160-1-level] of [160]
        let byte: usize = (160-1-level) / 8;
        let bit: u8 = (7 - ((160-1-level) % 8)) as u8;//MSB = 7 - LSB
        let computed_is_right = A_account[byte] & 1u8.rotate_left(bit.into());

        //Generate random uncle
        let mut uncle: Vec<u8> = (0..32).map(|_v| rng.gen()).collect();

        //Add uncle to path
        M_account[level] = uncle.clone();

        //Create block of prev_hash + uncle
        let mut hash_input = Vec::with_capacity(64);
        let mut prev_hash_vec = prev_hash.to_vec();
        assert_eq!(prev_hash_vec.len(), 32);
        if computed_is_right > 0u8 {
            hash_input.append(&mut uncle);
            hash_input.append(&mut prev_hash_vec);
        }
        else {
            hash_input.append(&mut prev_hash_vec);
            hash_input.append(&mut uncle);
        }
        assert_eq!(prev_hash_vec.len(), 0);
        assert_eq!(uncle.len(), 0);
        assert_eq!(hash_input.len(), 64);

        //Compress block to new hash
        sha256.input(hash_input.as_ref());

        sha256.result(&mut prev_hash);
        sha256.reset();
    }
    let W: Vec<u8> = prev_hash.to_vec();

    //V_account = hash(P_proof, hash(W, r_account))
    let mut hash_input_left = W.clone();
    let mut hash_input_right = r_account.clone();
    assert_eq!(hash_input_left.len(), 32);
    assert_eq!(hash_input_right.len(), 32);

    let mut hash_input: Vec<u8> = Vec::with_capacity(64);
    hash_input.append(&mut hash_input_left);
    hash_input.append(&mut hash_input_right);
    assert_eq!(hash_input_left.len(), 0);
    assert_eq!(hash_input_right.len(), 0);
    assert_eq!(hash_input.len(), 64);
    sha256.input(hash_input.as_ref());

    let mut hash_output = [0u8; 32];
    sha256.result(&mut hash_output);
    sha256.reset();

    let mut hash_input_left = P_proof.to_vec();
    let mut hash_input_right = hash_output.to_vec();
    assert_eq!(hash_input_left.len(), 32);
    assert_eq!(hash_input_right.len(), 32);

    let mut hash_input: Vec<u8> = Vec::with_capacity(64);
    hash_input.append(&mut hash_input_left);
    hash_input.append(&mut hash_input_right);
    assert_eq!(hash_input_left.len(), 0);
    assert_eq!(hash_input_right.len(), 0);
    assert_eq!(hash_input.len(), 64);
    sha256.input(hash_input.as_ref());

    let mut V_account = [0u8; 32];
    sha256.result(&mut V_account);
    sha256.reset();

    //return
    let _test_variables = TestVariables{
        P_proof : P_proof.to_vec(),
        leaf : leaf.to_vec(),
        M_account: M_account,
        W : W,
        V_account : V_account.to_vec(),
    };

    return _test_variables;
}

#[test]
fn test_sha_256_empty() {
    let mut sha256 = Sha256::new();
    let hash_input: Vec<u8> = Vec::with_capacity(64);
    sha256.input(hash_input.as_ref());
    assert_eq!(sha256.result_str(), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

    sha256.reset();
    let mut hash_input_left: Vec<u8> = Vec::with_capacity(32);
    let mut hash_input_right: Vec<u8> = Vec::with_capacity(32);
    hash_input_left.append(&mut hash_input_right);
    sha256.input(hash_input_left.as_ref());
    assert_eq!(sha256.result_str(), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

pub fn hex_push(buf: &mut String, blob: &[u8]) {
    for ch in blob {
        fn hex_from_digit(num: u8) -> char {
            if num < 10 {
                (b'0' + num) as char
            } else {
                (b'A' + num - 10) as char
            }
        }
        buf.push(hex_from_digit(ch / 16));
        buf.push(hex_from_digit(ch % 16));
    }
}
pub fn to_hex(blob: &[u8]) -> String {
    let mut s: String = String::new();
    hex_push(&mut s, blob);
    return s;
}