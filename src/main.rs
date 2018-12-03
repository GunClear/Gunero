//#![feature(rand)]
extern crate crypto;
extern crate libc;
extern crate rand;
extern crate secp256k1;
extern crate tiny_keccak;

use std::env;
use rand::Rng;
// use rand::prelude::*;
use secp256k1::{Secp256k1, SecretKey, PublicKey};
use tiny_keccak::keccak256;
// use std::io;
// use std::io::BufRead;
//use std::io::prelude::*;
// use std::fs::File;
// use std::str;
use crypto::sha2::Sha256;
use crypto::digest::Digest;
use libc::c_char;
use std::ffi::CString;

#[link(name="silencerd")]
extern "C" {
    //Prove Membership
    fn prove_membership(
        WHex: *const c_char,
        N_account: u8,
        V_accountHex: *const c_char,
        s_accountHex: *const c_char,
        M_accountHexArray: *const c_char,
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
    //Prove Transaction Send
    fn prove_send(
        WHex: *const c_char,
        THex: *const c_char,
        V_SHex: *const c_char,
        V_RHex: *const c_char,
        L_PHex: *const c_char,
        s_SHex: *const c_char,
        r_SHex: *const c_char,
        r_RHex: *const c_char,
        A_PSHex: *const c_char,
        W_PHex: *const c_char,
        P_proof_RHex: *const c_char,
        pkPath: *const c_char,
        vkPath: *const c_char,
        proofPath: *const c_char
        ) -> i32;
    //Verify Transaction Send
    fn verify_send(
        WHex: *const c_char,
        cTHex: *const c_char,
        V_SHex: *const c_char,
        V_RHex: *const c_char,
        L_PHex: *const c_char,
        vkPath: *const c_char,
        proofPath: *const c_char
        ) -> i32;
    fn verify_send_wit(
        witnessPath: *const c_char,
        vkPath: *const c_char,
        proofPath: *const c_char
        ) -> i32;
}

fn main() {
    let _args: Vec<String> = env::args().collect();

    let EXECUTE_MEMBERSHIP = false;
    let EXECUTE_SEND = true;

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

    let test_variables = make_test_variables();

    // println!("s_account: {}", to_hex(&test_variables.s_account));
    // println!("A_account_secret_key: {}", test_variables.A_account_secret_key);
    // println!("A_account_public_key: {}", test_variables.A_account_public_key);
    // println!("A_account: {}", to_hex(&test_variables.A_account));
    // println!("N_account: {}", test_variables.N_account);
    // println!("r_account: {}", to_hex(&test_variables.r_account));

    // println!("P_proof: {}", to_hex(&test_variables.P_proof));
    // println!("leaf: {}", to_hex(&test_variables.leaf));
    // println!("M_account: {}", test_variables.M_account.len());
    // println!("W: {}", to_hex(&test_variables.W));
    // println!("V_account: {}", to_hex(&test_variables.V_account));

    // println!("s_S: {}", to_hex(&test_variables.s_S));
    // println!("A_PS: {}", to_hex(&test_variables.A_PS));

    //Public Input variables
    let W_hex = CString::new(to_hex(&test_variables.W)).expect("CString::new failed");
    let V_account_hex = CString::new(to_hex(&test_variables.V_account)).expect("CString::new failed");

    //Private Input variables
    let s_account_hex = CString::new(to_hex(&test_variables.s_account)).expect("CString::new failed");
    let A_account_hex = CString::new(to_hex(&test_variables.A_account)).expect("CString::new failed");
    let r_account_hex = CString::new(to_hex(&test_variables.r_account)).expect("CString::new failed");

    //Public Input variables
    let T_hex = CString::new(to_hex(&test_variables.T)).expect("CString::new failed");
    let V_S_hex = CString::new(to_hex(&test_variables.V_S)).expect("CString::new failed");
    let V_R_hex = CString::new(to_hex(&test_variables.V_R)).expect("CString::new failed");
    let L_P_hex = CString::new(to_hex(&test_variables.L_P)).expect("CString::new failed");

    //Private Input variables
    let s_S_hex = CString::new(to_hex(&test_variables.s_S)).expect("CString::new failed");
    let r_S_hex = CString::new(to_hex(&test_variables.r_S)).expect("CString::new failed");
    let r_R_hex = CString::new(to_hex(&test_variables.r_R)).expect("CString::new failed");
    let A_PS_hex = CString::new(to_hex(&test_variables.A_PS)).expect("CString::new failed");
    let W_P_hex = CString::new(to_hex(&test_variables.W_P)).expect("CString::new failed");
    let P_proof_R_hex = CString::new(to_hex(&test_variables.P_proof_R)).expect("CString::new failed");

    //Storage variables
    let F_hex = CString::new(to_hex(&test_variables.F)).expect("CString::new failed");
    let j_hex = CString::new(to_hex(&test_variables.j)).expect("CString::new failed");
    let L_hex = CString::new(to_hex(&test_variables.L)).expect("CString::new failed");
    let P_proof_S_hex = CString::new(to_hex(&test_variables.P_proof_S)).expect("CString::new failed");
    let A_R_hex = CString::new(to_hex(&test_variables.A_R)).expect("CString::new failed");
    let s_R_hex = CString::new(to_hex(&test_variables.s_R)).expect("CString::new failed");
    let A_S_hex = CString::new(to_hex(&test_variables.A_S)).expect("CString::new failed");

    //Build M_accountHexArray
    let mut M_accountHexArray_builder = String::new();
    for level in 0..160 {
        let level_hex = to_hex(&test_variables.M_account[level]);
        M_accountHexArray_builder.push_str(&level_hex);
        if level != 159 {
            M_accountHexArray_builder.push_str(";");
        }
    }
    // println!("M_accountHexArray_builder: {}", M_accountHexArray_builder);
    let M_accountHexArray = CString::new(M_accountHexArray_builder).expect("CString::new failed");

    if EXECUTE_MEMBERSHIP {
        let gtm_pk_path = CString::new("/home/sean/Gunero/demo/GTM.pk.bin").expect("CString::new failed");
        let gtm_vk_path = CString::new("/home/sean/Gunero/demo/GTM.vk.bin").expect("CString::new failed");
        let gtm_proof_path = CString::new("/home/sean/Gunero/demo/GTM.proof.002.bin").expect("CString::new failed");

        let ret = unsafe {
            prove_membership(
                W_hex.as_ptr(),
                test_variables.N_account,
                V_account_hex.as_ptr(),
                s_account_hex.as_ptr(),
                M_accountHexArray.as_ptr(),
                A_account_hex.as_ptr(),
                r_account_hex.as_ptr(),
                gtm_pk_path.as_ptr(),
                gtm_vk_path.as_ptr(),
                gtm_proof_path.as_ptr()
            )
        };

        if ret == 0 {
            //Success

            let ret = unsafe {
                verify_membership(
                    W_hex.as_ptr(),
                    test_variables.N_account,
                    V_account_hex.as_ptr(),
                    gtm_vk_path.as_ptr(),
                    gtm_proof_path.as_ptr()
                )
            };
            if ret == 0 {
                //Success
                println!("Success!");
            }
            else {
                //Failure
                println!("Failure 2: {}", ret);
            }
        }
        else {
            //Failure
            println!("Failure 1: {}", ret);
        }
    }

    if EXECUTE_SEND {
        let gts_pk_path = CString::new("/home/sean/Gunero/demo/GTS.pk.bin").expect("CString::new failed");
        let gts_vk_path = CString::new("/home/sean/Gunero/demo/GTS.vk.bin").expect("CString::new failed");
        let gts_proof_path = CString::new("/home/sean/Gunero/demo/GTS.proof.001.bin").expect("CString::new failed");
        // let gts_proof_path = CString::new("/home/sean/Gunero/demo/GTS.proof.bin").expect("CString::new failed");
        // let gts_witness_path = CString::new("/home/sean/Gunero/demo/GTS.witness.bin").expect("CString::new failed");

        // let ret = unsafe {
        //     verify_send_wit(
        //         gts_witness_path.as_ptr(),
        //         gts_vk_path.as_ptr(),
        //         gts_proof_path.as_ptr()
        //     )
        // };

        // if ret == 0 {
        //     //Success
        //     println!("Success 1!");
        // }
        // else {
        //     //Failure
        //     println!("Failure 1: {}", ret);
        // }

        // return;

        let ret = unsafe {
            prove_send(
                W_hex.as_ptr(),
                T_hex.as_ptr(),
                V_S_hex.as_ptr(),
                V_R_hex.as_ptr(),
                L_P_hex.as_ptr(),
                s_S_hex.as_ptr(),
                r_S_hex.as_ptr(),
                r_R_hex.as_ptr(),
                A_PS_hex.as_ptr(),
                W_P_hex.as_ptr(),
                P_proof_R_hex.as_ptr(),
                gts_pk_path.as_ptr(),
                gts_vk_path.as_ptr(),
                gts_proof_path.as_ptr()
            )
        };

        if ret == 0 {
            //Success
            println!("Success 1!");

            let ret = unsafe {
                verify_send(
                W_hex.as_ptr(),
                T_hex.as_ptr(),
                V_S_hex.as_ptr(),
                V_R_hex.as_ptr(),
                L_P_hex.as_ptr(),
                gts_vk_path.as_ptr(),
                gts_proof_path.as_ptr()
                )
            };
            if ret == 0 {
                //Success
                println!("Success 2!");
            }
            else {
                //Failure
                println!("Failure 2: {}", ret);
            }
        }
        else {
            //Failure
            println!("Failure 1: {}", ret);
        }
    }
}

struct TestVariables {
    N_account: u8,
    s_account: Vec<u8>,
    A_account_secret_key: SecretKey,
    A_account_public_key: PublicKey,
    r_account: Vec<u8>,
    A_account: Vec<u8>,
    P_proof: Vec<u8>,
    leaf: Vec<u8>,
    M_account : Vec<Vec<u8>>,
    W: Vec<u8>,
    V_account: Vec<u8>,
    T: Vec<u8>,
    V_S: Vec<u8>,
    V_R: Vec<u8>,
    L_P: Vec<u8>,
    s_S: Vec<u8>,
    r_S: Vec<u8>,
    r_R: Vec<u8>,
    A_PS: Vec<u8>,
    W_P: Vec<u8>,
    P_proof_R: Vec<u8>,
    F: Vec<u8>,
    j: Vec<u8>,
    L: Vec<u8>,
    P_proof_S: Vec<u8>,
    A_R: Vec<u8>,
    s_R: Vec<u8>,
    A_S: Vec<u8>,
}

fn make_test_variables()
        -> TestVariables {
    let mut rng = rand::thread_rng();

    //Generate basic variables
    let mut s_account: Vec<u8> = (0..32).map(|_v| rng.gen()).collect();//random_uint256(rng);
    let N_account = 1u8;
    let r_account: Vec<u8> = (0..32).map(|_v| rng.gen()).collect();//random_uint256(rng);

    let mut s_S: Vec<u8> = (0..32).map(|_v| rng.gen()).collect();//random_uint256(rng);
    let r_S: Vec<u8> = (0..32).map(|_v| rng.gen()).collect();//random_uint256(rng);

    //Check s_account for 252 compliance
    if s_account[0] > 15 {
        s_account[0] &= 0x0F;
    }
    //Check s_S for 252 compliance
    if s_S[0] > 15 {
        s_S[0] &= 0x0F;
    }

    //Create keys and account
    let secp = Secp256k1::new();
    let A_account_secret_key = SecretKey::from_slice(&secp, &s_account).expect("32 bytes, within curve order");
    let A_account_public_key = PublicKey::from_secret_key(&secp, &A_account_secret_key);

    let A_account_public_key_bytes_extra: [u8; 65] = A_account_public_key.serialize_uncompressed();
    assert_eq!(A_account_public_key_bytes_extra[0], 4);
    let mut A_account_public_key_bytes = [0u8; 64];
    //Because of the tragicly bad copying system in Rust
    for index in 1..65
    {
        A_account_public_key_bytes[index - 1] = A_account_public_key_bytes_extra[index];
    }
    let A_account_public_key_bytes_keccak256 = keccak256(&A_account_public_key_bytes);
    let mut A_account = [0u8; 20];
    //Because of the tragicly bad copying system in Rust
    for index in 12..32
    {
        A_account[index - 12] = A_account_public_key_bytes_keccak256[index];
    }

    let secp = Secp256k1::new();
    let A_S_secret_key = SecretKey::from_slice(&secp, &s_S).expect("32 bytes, within curve order");
    let A_S_public_key = PublicKey::from_secret_key(&secp, &A_S_secret_key);

    let A_S_public_key_bytes_extra: [u8; 65] = A_S_public_key.serialize_uncompressed();
    assert_eq!(A_S_public_key_bytes_extra[0], 4);
    let mut A_S_public_key_bytes = [0u8; 64];
    //Because of the tragicly bad copying system in Rust
    for index in 1..65
    {
        A_S_public_key_bytes[index - 1] = A_S_public_key_bytes_extra[index];
    }
    let A_S_public_key_bytes_keccak256 = keccak256(&A_S_public_key_bytes);
    let mut A_S = [0u8; 20];
    //Because of the tragicly bad copying system in Rust
    for index in 12..32
    {
        A_S[index - 12] = A_S_public_key_bytes_keccak256[index];
    }

    assert_eq!(s_account.len(), 32);
    assert_eq!(r_account.len(), 32);

    let mut sha256 = Sha256::new();

    //Generate P_proof from s_account
    let mut P_proof = [0u8; 32];
    {
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

        sha256.result(&mut P_proof);
        sha256.reset();
    }

    //Generate leaf from P_proof and N_account
    let mut leaf = [0u8; 32];
    {
        //leaf = hash(P_proof,N_account)
        let mut hash_input_left = P_proof.to_vec();
        let mut hash_input_right = [0u8; 32].to_vec();//Vec::with_capacity(32);
        assert_eq!(hash_input_left.len(), 32);
        assert_eq!(hash_input_right.len(), 32);

        let mut hash_input = Vec::with_capacity(64);
        hash_input.append(&mut hash_input_left);
        hash_input.append(&mut hash_input_right);
        assert_eq!(hash_input_left.len(), 0);
        assert_eq!(hash_input_right.len(), 0);
        assert_eq!(hash_input.len(), 64);

        sha256.input(hash_input.as_ref());

        sha256.result(&mut leaf);
        sha256.reset();
    }

    //Generate M_account from A_account
    let mut prev_hash = leaf.clone();
    let mut M_account: Vec<Vec<u8>> = vec![vec![0u8; 32]; 160];
    for level in (0..160).rev()
    {
        //Calculate uncle position
        //Bit [160-1-level] of [160]
        let byte: usize = (160-1-level) / 8;
        let bit: u8 = (7 - ((160-1-level) % 8)) as u8;//MSB = 7 - LSB
        let computed_is_right = A_account[byte] & 1u8.rotate_left(bit.into());

        //Generate random uncle
        let mut uncle: Vec<u8> = (0..32).map(|_v| rng.gen()).collect();//random_uint256(rng);

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
    let mut V_account = [0u8; 32];
    {
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

        sha256.result(&mut V_account);
        sha256.reset();
    }

    let V_R = V_account.clone();//hash(P_proof_R, hash(W, r_R)

    let r_R = r_account.clone();
    let A_PS: Vec<u8> = (0..20).map(|_v| rng.gen()).collect();//random_uint160(rng);
    let W_P: Vec<u8> = (0..32).map(|_v| rng.gen()).collect();//random_uint256(rng);
    let P_proof_R = P_proof.clone();

    let F: Vec<u8> = (0..32).map(|_v| rng.gen()).collect();//random_uint256(rng);

    let j: Vec<u8> = (0..32).map(|_v| rng.gen()).collect();//random_uint256(rng);
    let A_R = A_account.clone();
    let s_R = s_account.clone();

    //Generate P_proof_S from s_S
    let mut P_proof_S = [0u8; 32];
    {
        //P_proof_S = Hash(0000b | (s_S&252b), 0)
        let mut hash_input_left = s_S.to_vec();
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

        sha256.result(&mut P_proof_S);
        sha256.reset();
    }

    //T = hash(F, j)
    let mut T = [0u8; 32];
    {
        let mut hash_input_left = F.to_vec();
        let mut hash_input_right = j.to_vec();
        assert_eq!(hash_input_left.len(), 32);
        assert_eq!(hash_input_right.len(), 32);

        let mut hash_input: Vec<u8> = Vec::with_capacity(64);
        hash_input.append(&mut hash_input_left);
        hash_input.append(&mut hash_input_right);
        assert_eq!(hash_input_left.len(), 0);
        assert_eq!(hash_input_right.len(), 0);
        assert_eq!(hash_input.len(), 64);
        sha256.input(hash_input.as_ref());

        sha256.result(&mut T);
        sha256.reset();
    }

    //V_S = hash(P_proof_S, hash(W, r_S))
    let mut V_S = [0u8; 32];
    {
        let mut hash_input_left = W.clone();
        let mut hash_input_right = r_S.clone();
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

        let mut hash_input_left = P_proof_S.to_vec();
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

        sha256.result(&mut V_S);
        sha256.reset();
    }

    //L_P = hash(A_PS, hash(s_S, hash(T, W_P)))
    let mut L_P = [0u8; 32];
    {
        let mut hash_input_left = T.to_vec();
        let mut hash_input_right = W_P.clone();
        assert_eq!(hash_input_left.len(), 32);
        assert_eq!(hash_input_right.len(), 32);

        let mut hash_input: Vec<u8> = Vec::with_capacity(64);
        hash_input.append(&mut hash_input_left);
        hash_input.append(&mut hash_input_right);
        assert_eq!(hash_input_left.len(), 0);
        assert_eq!(hash_input_right.len(), 0);
        assert_eq!(hash_input.len(), 64);
        sha256.input(hash_input.as_ref());

        let mut hash_output_1 = [0u8; 32];
        sha256.result(&mut hash_output_1);
        sha256.reset();

        let mut hash_input_left = s_S.to_vec();
        let mut hash_input_right = hash_output_1.to_vec();
        assert_eq!(hash_input_left.len(), 32);
        assert_eq!(hash_input_right.len(), 32);

        let mut hash_input: Vec<u8> = Vec::with_capacity(64);
        hash_input.append(&mut hash_input_left);
        hash_input.append(&mut hash_input_right);
        assert_eq!(hash_input_left.len(), 0);
        assert_eq!(hash_input_right.len(), 0);
        assert_eq!(hash_input.len(), 64);
        sha256.input(hash_input.as_ref());

        let mut hash_output_2 = [0u8; 32];
        sha256.result(&mut hash_output_2);
        sha256.reset();

        let mut buffer = [0u8; 12].to_vec();
        let mut hash_input_left = A_PS.to_vec(); hash_input_left.append(&mut buffer);
        let mut hash_input_right = hash_output_2.to_vec();
        assert_eq!(hash_input_left.len(), 32);
        assert_eq!(hash_input_right.len(), 32);

        let mut hash_input: Vec<u8> = Vec::with_capacity(64);
        hash_input.append(&mut hash_input_left);
        hash_input.append(&mut hash_input_right);
        assert_eq!(hash_input_left.len(), 0);
        assert_eq!(hash_input_right.len(), 0);
        assert_eq!(hash_input.len(), 64);
        sha256.input(hash_input.as_ref());

        sha256.result(&mut L_P);
        sha256.reset();
    }

    //L = hash(A_S, hash(s_R, hash(T, W)))
    let mut L = [0u8; 32];
    {
        let mut hash_input_left = T.to_vec();
        let mut hash_input_right = W.clone();
        assert_eq!(hash_input_left.len(), 32);
        assert_eq!(hash_input_right.len(), 32);

        let mut hash_input: Vec<u8> = Vec::with_capacity(64);
        hash_input.append(&mut hash_input_left);
        hash_input.append(&mut hash_input_right);
        assert_eq!(hash_input_left.len(), 0);
        assert_eq!(hash_input_right.len(), 0);
        assert_eq!(hash_input.len(), 64);
        sha256.input(hash_input.as_ref());

        let mut hash_output_1 = [0u8; 32];
        sha256.result(&mut hash_output_1);
        sha256.reset();

        let mut hash_input_left = s_R.to_vec();
        let mut hash_input_right = hash_output_1.to_vec();
        assert_eq!(hash_input_left.len(), 32);
        assert_eq!(hash_input_right.len(), 32);

        let mut hash_input: Vec<u8> = Vec::with_capacity(64);
        hash_input.append(&mut hash_input_left);
        hash_input.append(&mut hash_input_right);
        assert_eq!(hash_input_left.len(), 0);
        assert_eq!(hash_input_right.len(), 0);
        assert_eq!(hash_input.len(), 64);
        sha256.input(hash_input.as_ref());

        let mut hash_output_2 = [0u8; 32];
        sha256.result(&mut hash_output_2);
        sha256.reset();

        let mut buffer = [0u8; 12].to_vec();
        let mut hash_input_left = A_S.to_vec(); hash_input_left.append(&mut buffer);
        let mut hash_input_right = hash_output_2.to_vec();
        assert_eq!(hash_input_left.len(), 32);
        assert_eq!(hash_input_right.len(), 32);

        let mut hash_input: Vec<u8> = Vec::with_capacity(64);
        hash_input.append(&mut hash_input_left);
        hash_input.append(&mut hash_input_right);
        assert_eq!(hash_input_left.len(), 0);
        assert_eq!(hash_input_right.len(), 0);
        assert_eq!(hash_input.len(), 64);
        sha256.input(hash_input.as_ref());

        sha256.result(&mut L);
        sha256.reset();
    }

    //return
    let _test_variables = TestVariables{
        N_account : N_account,
        s_account : s_account,
        A_account_secret_key : A_account_secret_key,
        A_account_public_key : A_account_public_key,
        r_account : r_account,
        A_account : A_account.to_vec(),
        P_proof : P_proof.to_vec(),
        leaf : leaf.to_vec(),
        M_account: M_account,
        W : W,
        V_account : V_account.to_vec(),
        T : T.to_vec(),
        V_S : V_S.to_vec(),
        V_R : V_R.to_vec(),
        L_P : L_P.to_vec(),
        s_S : s_S.to_vec(),
        r_S : r_S.to_vec(),
        r_R : r_R.to_vec(),
        A_PS : A_PS.to_vec(),
        W_P : W_P,
        P_proof_R : P_proof_R.to_vec(),
        F : F.to_vec(),
        j : j.to_vec(),
        L : L.to_vec(),
        P_proof_S : P_proof_S.to_vec(),
        A_R : A_R.to_vec(),
        s_R : s_R.to_vec(),
        A_S : A_S.to_vec(),
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

// fn random_uint256(mut rng: ThreadRng) -> Vec<u8> {
//     (0..32).map(|_v| rng.gen()).collect()
// }

// fn random_uint160(mut rng: ThreadRng) -> Vec<u8> {
//     (0..20).map(|_v| rng.gen()).collect()
// }
