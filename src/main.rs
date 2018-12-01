extern crate crypto;
extern crate libc;
extern crate rand;

use std::env;
use rand::Rng;
// use std::io;
// use std::io::BufRead;
//use std::io::prelude::*;
// use std::fs::File;
// use crypto::ed25519;
use crypto::sha2::Sha256;
use crypto::digest::Digest;
use libc::c_char;
// use std::ffi::CStr;
// use std::str;

#[link(name="silencerd")]
extern "C" {
// extern "C" {
    fn verify_membership(WHex: *const c_char, N_account: u8, V_accountHex: *const c_char, vkPath: *const c_char, proofPath: *const c_char) -> i32;
}

fn main() {
    let _args: Vec<String> = env::args().collect();

    // let mut sha256 = Sha256::new();

    // let hash_input: Vec<u8> = Vec::with_capacity(512);
    // sha256.input(hash_input.as_ref());

    // println!("sha256(NULL, NULL): {}", sha256.result_str());

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
    let s_account: Vec<u8> = (0..256).map(|_v| rng.gen_range(0, 255)).collect();
    let N_account = 1u8;
    let r_account: Vec<u8> = (0..256).map(|_v| rng.gen_range(0, 255)).collect();

    println!("P_proof: {}", s_account.len());//{:?}", s_account);
    println!("N_account: {}", N_account);
    println!("r_account: {}", r_account.len());//{:?}", r_account);

    let test_variables = makeTestVariables(&s_account, N_account, &r_account);

    println!("P_proof: {}", test_variables.P_proof.len());//{:?}", test_variables.P_proof);
    println!("leaf: {}", test_variables.leaf.len());//{:?}", test_variables.leaf);

    // let ret = unsafe { verify_membership(WHex, ) };

}

struct TestVariables {
    P_proof: Vec<u8>,
    leaf: Vec<u8>,
    M_account : Vec<Vec<u8>>,
    A_account: Vec<u8>,
    W: Vec<u8>,
    V_account: Vec<u8>,
}

fn makeTestVariables(
        s_account : &Vec<u8>,
        N_account : u8,
        r_account : &Vec<u8>)
        -> TestVariables {
    assert_eq!(s_account.len(), 256);
    assert_eq!(r_account.len(), 256);

    let mut sha256 = Sha256::new();

    //P_proof = Hash(0000b | (s_account&252b), 0)
    let mut hash_input_left = s_account.to_vec();
    let mut hash_input_right: Vec<u8> = Vec::with_capacity(256);

    hash_input_left.append(&mut hash_input_right);
    sha256.input(hash_input_left.as_ref());

    println!("3");

    let mut P_proof = [0u8; 256];
    sha256.result(&mut P_proof);

    println!("4");

    //leaf = hash(P_proof,N_account)
    hash_input_left = P_proof.to_vec();
    hash_input_right = Vec::with_capacity(256);

    println!("5");

    hash_input_left.append(&mut hash_input_right);
    sha256.input(hash_input_left.as_ref());

    println!("6");

    let mut leaf = [0u8; 256];
    sha256.result(&mut leaf);

    println!("7");

    let _test_variables = TestVariables{
        P_proof : P_proof.to_vec(),
        leaf : leaf.to_vec(),
        M_account: vec![vec![0u8; 256]; 160],
        A_account : vec![0u8; 160],
        W : vec![0u8; 256],
        V_account : vec![0u8; 256],
    };

    return _test_variables;
}

#[test]
fn test_sha_256_empty() {
    let mut sha256 = Sha256::new();
    let hash_input: Vec<u8> = Vec::with_capacity(512);
    sha256.input(hash_input.as_ref());
    assert_eq!(sha256.result_str(), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

    let mut sha256 = Sha256::new();
    let mut hash_input_left: Vec<u8> = Vec::with_capacity(256);
    let mut hash_input_right: Vec<u8> = Vec::with_capacity(256);
    hash_input_left.append(&mut hash_input_right);
    sha256.input(hash_input_left.as_ref());
    assert_eq!(sha256.result_str(), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}