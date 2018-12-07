extern crate crypto;
extern crate libc;
extern crate rand;
extern crate secp256k1;
extern crate tiny_keccak;

use std::env;
use rand::Rng;
use secp256k1::{Secp256k1, SecretKey, PublicKey};
use tiny_keccak::keccak256;
use crypto::sha2::Sha256;
use crypto::digest::Digest;
use libc::c_char;
use std::ffi::CString;

#[link(name="silencer")]
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
    //Prove Transaction Receive
    fn prove_receive(
        WHex: *const c_char,
        THex: *const c_char,
        V_SHex: *const c_char,
        V_RHex: *const c_char,
        LHex: *const c_char,
        s_RHex: *const c_char,
        r_RHex: *const c_char,
        A_SHex: *const c_char,
        r_SHex: *const c_char,
        FHex: *const c_char,
        jHex: *const c_char,
        A_RHex: *const c_char,
        P_proof_SHex: *const c_char,
        pkPath: *const c_char,
        vkPath: *const c_char,
        proofPath: *const c_char
    ) -> i32;
    fn verify_receive(
        WHex: *const c_char,
        THex: *const c_char,
        V_SHex: *const c_char,
        V_RHex: *const c_char,
        LHex: *const c_char,
        vkPath: *const c_char,
        proofPath: *const c_char
    ) -> i32;
}

fn main() {
    let _args: Vec<String> = env::args().collect();

    let EXECUTE_MEMBERSHIP = true;
    let EXECUTE_SEND = true;
    let EXECUTE_RECEIVE = true;

    let test_variables = make_test_variables();

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
            println!("Success 1.1!");

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
                println!("Success 1.2!");
            }
            else {
                //Failure
                println!("Failure 1.2: {}", ret);
            }
        }
        else {
            //Failure
            println!("Failure 1.1: {}", ret);
        }
    }

    if EXECUTE_SEND {
        let gts_pk_path = CString::new("/home/sean/Gunero/demo/GTS.pk.bin").expect("CString::new failed");
        let gts_vk_path = CString::new("/home/sean/Gunero/demo/GTS.vk.bin").expect("CString::new failed");
        let gts_proof_path = CString::new("/home/sean/Gunero/demo/GTS.proof.001.bin").expect("CString::new failed");

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
            println!("Success 2.1!");

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
                println!("Success 2.2!");
            }
            else {
                //Failure
                println!("Failure 2.2: {}", ret);
            }
        }
        else {
            //Failure
            println!("Failure 2.1: {}", ret);
        }
    }

    if EXECUTE_RECEIVE {
        let gtr_pk_path = CString::new("/home/sean/Gunero/demo/GTR.pk.bin").expect("CString::new failed");
        let gtr_vk_path = CString::new("/home/sean/Gunero/demo/GTR.vk.bin").expect("CString::new failed");
        let gtr_proof_path = CString::new("/home/sean/Gunero/demo/GTR.proof.001.bin").expect("CString::new failed");

        let ret = unsafe {
            prove_receive(
                W_hex.as_ptr(),
                T_hex.as_ptr(),
                V_S_hex.as_ptr(),
                V_R_hex.as_ptr(),
                L_hex.as_ptr(),
                s_R_hex.as_ptr(),
                r_R_hex.as_ptr(),
                A_S_hex.as_ptr(),
                r_S_hex.as_ptr(),
                F_hex.as_ptr(),
                j_hex.as_ptr(),
                A_R_hex.as_ptr(),
                P_proof_S_hex.as_ptr(),
                gtr_pk_path.as_ptr(),
                gtr_vk_path.as_ptr(),
                gtr_proof_path.as_ptr()
            )
        };

        if ret == 0 {
            //Success
            println!("Success 3.1!");

            let ret = unsafe {
                verify_receive(
                W_hex.as_ptr(),
                T_hex.as_ptr(),
                V_S_hex.as_ptr(),
                V_R_hex.as_ptr(),
                L_hex.as_ptr(),
                gtr_vk_path.as_ptr(),
                gtr_proof_path.as_ptr()
                )
            };
            if ret == 0 {
                //Success
                println!("Success 3.2!");
            }
            else {
                //Failure
                println!("Failure 3.2: {}", ret);
            }
        }
        else {
            //Failure
            println!("Failure 3.1: {}", ret);
        }
    }
}

struct TestVariables {
    N_account: u8,
    s_account: Vec<u8>,
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

fn make_test_variables() -> TestVariables {
    let mut rng = rand::thread_rng();

    if false {
        //prove_membership
        let W = parse_hex("976b2a10caa30c4e681c9388a72cac570338ef8e8b631800049ec9ab93e213dd");
        let N_account = 1u8;
        let V_account = parse_hex("076b941102be7766e71276432d95f61c33f383a9139e0ae4972dedb5952bfdea");
        let s_account = parse_hex("0b78f48c0883f2a8f955aa070b667e5f8e6a2acd37cbff11fbbdf98ac3dbbaae");
        let A_account = parse_hex("fcce4d304040e363d4fefc3970ac20fe874bd59c");
        let r_account = parse_hex("54af3a5c322c042b82af328d15b0eca41a167152e27063dd2d5d67f138219f8c");
        let mut M_account: Vec<Vec<u8>> = vec![vec![0u8; 32]; 160];
        M_account[0] = parse_hex("42aad60bf97adfe72628159d63ad035b2a82dca2a897537a8839daaac078a1c5");
        M_account[1] = parse_hex("0cdee6512555f2ea09b50617e72fc4ae04564173f6564bce22f2cf6022be6326");
        M_account[2] = parse_hex("c72c47b8a23d25ca0689675c97cac3d3d8b2cfd759df6af018ae166937564406");
        M_account[3] = parse_hex("92aaa2bcb6dfb3c23f55d3f2e2f1f8b545ff17f641f10a9e48ef78a9ef30f7eb");
        M_account[4] = parse_hex("d68c2afcf129175566cd9d50455110bbef6f41a33c4bb7b22886a37a483bb9da");
        M_account[5] = parse_hex("2d8af2b5783168d912bfa77d9a71555ecc318b72df949d5fc7ac399c9a1b5a6c");
        M_account[6] = parse_hex("98baeef53ceb3ad21bf9798494661844a44279bf2c4d7cdd761abaef0016e838");
        M_account[7] = parse_hex("376caaf4e21ecc4a9f88afcce215f1a9f698f3032835f81df641dfc702dae09a");
        M_account[8] = parse_hex("309983fb36a7a739400b60efb21441ea6d96678d51d6b1a651d54e9994240dca");
        M_account[9] = parse_hex("97d010e26a6f6dfb3bb0d8fd866d81c492836e3efef975c56072ae404d2128d9");
        M_account[10] = parse_hex("39d03489114867e202da9796c54d074edd7442e3c44be9fb66ebb5c6d56a2eba");
        M_account[11] = parse_hex("81b22ddbfcfe8b95450c94af2b77c056846a819f66884b0b85ef66cd2e389c02");
        M_account[12] = parse_hex("72b63042e83b1bf572398ed0b077eafe939de1e2fcd1671e3bd29672a3690f0c");
        M_account[13] = parse_hex("1c68e70b095a2acb799b28867a7cc81be9beef5a87857b5c9a4f79f6b239fd56");
        M_account[14] = parse_hex("92bf2bf5b067eb8a9bf571aeec62938d7694a3e6f1b7fe33ca9c0dd1eef374f8");
        M_account[15] = parse_hex("a1af94254b35adef6b0974c7a02f2c95fc54cef89bd7727a7af100a4202227be");
        M_account[16] = parse_hex("359ffdf6f4aa1a057e39864316ae8d7d9a720af5e9e000f577b7a5430ee699b0");
        M_account[17] = parse_hex("f1112ece792633ab806295e9bd5efc6780be7563023aaf04a06979016c4b8090");
        M_account[18] = parse_hex("71caf08d5c15537753490f7182c086349601b6e42ddabf64ae618f3a129c8224");
        M_account[19] = parse_hex("63e348cd072f59a92ac2d97dfe4990fc297c26a48612d7214668864bfbbedbe3");
        M_account[20] = parse_hex("45bc1caf287fc31dc9c64d8933cd811907ee4beffe1685e073d341d2eafbcaff");
        M_account[21] = parse_hex("75c68a71de56847c1e7364751b8f430237ed06b345c2623527f94cbdb852c5c6");
        M_account[22] = parse_hex("e9745321ef3e69fcc145751ab40b47ca296f2a8482d0124cb2b6a08a24fe93cf");
        M_account[23] = parse_hex("fe29bdee30cef41a6e52f792a2cc54b14e41817d1e02d8e676f35a02ac46e6df");
        M_account[24] = parse_hex("c848f6e419819e775835d3947e25112d4d670075af26db832b654f2330f52214");
        M_account[25] = parse_hex("40fa3279b5694da6ae1133281a706b1005da993feee87b1a8578ea31905ada2e");
        M_account[26] = parse_hex("a539cb8ec6b88a5c1b5a843c3188087f0ea412c63a24264237b2565fc321d70f");
        M_account[27] = parse_hex("82cf141a7acb45cd5ea24738f7bb64e99e39e5835f10ca428f493b4db44f848f");
        M_account[28] = parse_hex("ec0f22b5748f6ab44822cc2c85f39b6139db5e1103ebe915b1fc7e679465cdf7");
        M_account[29] = parse_hex("12855eb6b7e657d30ba908b0868ba70a5a782b5e30ca02d791b36b46b4e2b0ba");
        M_account[30] = parse_hex("dd90aa6c0bd849e7f88bfd39da5f826f5faa62941eb22867d6b9ed1d05757599");
        M_account[31] = parse_hex("92dbd0a8b3d98153df592591abddc3487877797c79f98612c8ec8db181c80e8a");
        M_account[32] = parse_hex("0dbaf4cb4358f3f89659d9d3f19110bab5d9b633252e24a324522dea92a06e85");
        M_account[33] = parse_hex("a1cc77a311af9a0d9178ebca031e1c848f56e813ab478195b0f37cab4b866494");
        M_account[34] = parse_hex("e87db8ac5ab5c82ceddae4de1d15f2a946cafa3563ec7682b389400e95bd7f57");
        M_account[35] = parse_hex("ce6e0d365651391fd190303183f4d9d1ba2d882ee92a768d2379f3cb7d58d7ee");
        M_account[36] = parse_hex("119bd0334584b4eb67c864141da44dbcb56657bf99d754f033c67aa4f9b8eb25");
        M_account[37] = parse_hex("b60e0225bb3b6dc227ca9d3bbc5e39571d327bf942bba0ebb78448a154d2a691");
        M_account[38] = parse_hex("c6b1b43a614849544e01309ba9795b587426a7046fb5f5f6ab434705ea90f098");
        M_account[39] = parse_hex("8cc0ca8373c88c867c05e447189ba09c3e71b7df80b307c64ddf6a0d67cde00f");
        M_account[40] = parse_hex("fb2aac88cf7cc849b43c89f9401a57112b792b3479e695c9d8403da7cf7ebcd5");
        M_account[41] = parse_hex("f4420ba542d8144b4f491f72d4890efbd81bec30a55cadccef4858c17933ce42");
        M_account[42] = parse_hex("43148761b4be0f356634807dfbd3fee7aaf19e1c57b59ebf9cfefeaca3a38ebe");
        M_account[43] = parse_hex("03782a309610696c8dbd6f09ac508a43af4ecc9ccd1e6c3e5be21b1fa39f8583");
        M_account[44] = parse_hex("3cb53ad6c03933c41f86949aaa1e6caccca953881b2bc7f6a7ea42ba51cdfa1f");
        M_account[45] = parse_hex("fce1b65b89b58d06ddd5ac8518f7b76630f8f9bb7e3c75f0e1c1462ebcd9f6a3");
        M_account[46] = parse_hex("783a3489528464199599498265903c040b52a49fe2f7beaa01b8c7a96cca6054");
        M_account[47] = parse_hex("cbf532c8a8d07e7c7e767440e5462e5a42fb043668780b0f32b36ba87fcf3cc0");
        M_account[48] = parse_hex("897cfa7c995c6d50af89ad9a87e5ca37f86e7a7534c0d628676bd5ff1423f50e");
        M_account[49] = parse_hex("b7071cef90443c63dbd200d58426dc27f6f1acd189d8c0f85c6cff5d1e18d519");
        M_account[50] = parse_hex("9cc91867fe027f755b21d99d7b3c335554764d1900b98b429226c89ee048fec4");
        M_account[51] = parse_hex("5d56940438bad12ca101a69e95b60ee198dfe1253cae193d7e8ca7d073e5ce7b");
        M_account[52] = parse_hex("bfc9687eae36363975d6bdf451932f0aeeb20b4c53205d3d04dd108813afd124");
        M_account[53] = parse_hex("8cdf77ffec2f2ab85b7216bf170da9c6c7e84ad41c7c1c003ead3fd9c80f9998");
        M_account[54] = parse_hex("8810e547ed08bf47808cc52ef7aed00cd4c56c8340d73b62cc0feb4dafd57651");
        M_account[55] = parse_hex("2b0e14eb23727a8fa222a3ea4ddde37a9d0b2b96f5397105d9ce20051c44fed1");
        M_account[56] = parse_hex("4bc2a2b2e123b35a9963018439d46ec95bd4737da3bd4f514cc2c43993def5c9");
        M_account[57] = parse_hex("a12c0c7323769a21fd4a76ca1b5f61fbe0b9d398db1a4f8178a9b920c886b5fc");
        M_account[58] = parse_hex("be171c7470387460c0339bc804955f7d2a42d552a2dd199c4e6fcaad16565377");
        M_account[59] = parse_hex("00658b644d3930ad7034f5f196f2bf1108b363584cb56aec53505a964e6d7af2");
        M_account[60] = parse_hex("e6551f0c5798e03cb148fcf7276d52e2060f73a4d12aba0d03a0e9e6031a1a92");
        M_account[61] = parse_hex("3dad865b1aaec98fa33934184df4e4a0b540c1370e1659092cbae6b49aa56a2a");
        M_account[62] = parse_hex("829271e4802bb7016d14f0b43fc55390460bd80bf6cf14a1d3f4bfb5de2c3d8e");
        M_account[63] = parse_hex("9cf7aa7951d480a66c3348613c6bf63ddb33007ceb2007157226e34204f28776");
        M_account[64] = parse_hex("a50dd05ccb42fee4865abe1a42fb44eaddc6471e0af129a920e61a13bed656dc");
        M_account[65] = parse_hex("5536d6d4909d9e7e6591163603919b60b87ca728762c0b7fb2c6eaacfc2a969b");
        M_account[66] = parse_hex("4ce632df3df1d78fb55827e22e34d57e9b0a4956a216e63fb6f844f145e40983");
        M_account[67] = parse_hex("294257c6a612de57b8327bd140ff5f4e03a8b03a5c77d9e874d56e3f13dbbf82");
        M_account[68] = parse_hex("4ed90bdd0dcfeb51277506f04ff6c5b6aa952145f7f6b40540e1f42e13baad77");
        M_account[69] = parse_hex("0788cc1171e9e642ba87040a178f6533d254d0b57bd1bce3876ce49529c1da6b");
        M_account[70] = parse_hex("05a7365dab6073c84a9b0781fa724a4b854ded26c66e500c4688b21e0cda2064");
        M_account[71] = parse_hex("6cf1ca93e7919622c782fb3e4808e6e25b814404ec9004f5414fd1e77d477567");
        M_account[72] = parse_hex("3eefcabf8c564c8c82cd381adec25b175a851029124394d0fbf5d34558f1ddf4");
        M_account[73] = parse_hex("22008f194cc8c112e41a82dc45884c1b98ed65137e144f8620d218004e6d80db");
        M_account[74] = parse_hex("435b570c065c280812d3ad7e210e541fbb7f0b42793931e9e4eef9e701c527b9");
        M_account[75] = parse_hex("82431e91692b283086a17cfec4c29abbadba7b07bc7f4ed4af188c2cf06c8dfa");
        M_account[76] = parse_hex("36a4c59df8424a2e81fb17aadc36f04556f1c4060c67bf0da4287fe60dc28e04");
        M_account[77] = parse_hex("fa8dbf8c7aafc3774851f9cf69ee7d32945f2f215673396abbb07fa5ce9217aa");
        M_account[78] = parse_hex("ebbb99e294f1a4dfc0f7ac0eda0fa6c579aa9e1c77acf3094e3f15a61d55830f");
        M_account[79] = parse_hex("0bc4ab1da72da2c20b1857fb2272fc6edeb672d3c589fb952935436610f3fbbb");
        M_account[80] = parse_hex("c77c4733461b47cf62ed1d226aacae9d68c1443c5321adc92b34d1e978bf4bb5");
        M_account[81] = parse_hex("4ee9a72be8c8633e3eef26c68ea9640db3349fbd4603507d224eb2aa0565fba5");
        M_account[82] = parse_hex("3197ec00782e0093db444cae7d20c339c4de6a6fbc8fa4181a6a44eb5ded2c79");
        M_account[83] = parse_hex("87e260e92a8d48efbe881567c3522f2d224de9c25bfca75e2357be61698a444a");
        M_account[84] = parse_hex("35555695d2e2e4a3e9b3f368dcf8b63e3e36f0e03a2525687ff209ed38dfcabd");
        M_account[85] = parse_hex("f76500abc7396c10d512a6e8992a29b7c4eb114398eb4631357d2a2540e7bb19");
        M_account[86] = parse_hex("69a81577231359c7a34ae523b46866da1a8bbadef3cea0bb07733306c2ea6b2b");
        M_account[87] = parse_hex("616b611d6f31a319f0304f82b7c9bdff83eeb8c607726c1246328ddf6945c1a2");
        M_account[88] = parse_hex("1ae36ede7bfbb744ce30b9bc3afa35beac34eebeadbe11445e8d6f3be370c35e");
        M_account[89] = parse_hex("aa05bb720dba30441c96db49c343cda3dc4e4378bf7ba75b8c77bd1c9a2ac0a1");
        M_account[90] = parse_hex("152ddf96f04356f1c8dd299013d07cedb0268bb5f607f9d14923d8b0cbdd4907");
        M_account[91] = parse_hex("ddd143dcc3964525306067b460b6194627886f47ab2456d5b5f70c0151c25901");
        M_account[92] = parse_hex("1c8993e101a50acbf5bd7e55994f562ef48bd239484e207481a96dbe4b39d869");
        M_account[93] = parse_hex("083e3548891f466c14af61ff9a1f38e7cdb911d5adc92c18af7477c32f022a46");
        M_account[94] = parse_hex("61fbb3ea91cc6e17c3898d01beec8b0171c0126f3524dd70f2377461846f3ff8");
        M_account[95] = parse_hex("f334a8d8cf6577a7e44605f389f0bd45339a2f494e769d82dfd78ecdc7413935");
        M_account[96] = parse_hex("267686b622bbba960578219259c69efaeeba3a1683168f414fdeebb2e35787b1");
        M_account[97] = parse_hex("fc950aaa35098e160b1354b006eae525bb3a44d146a66766d78d544e680f573a");
        M_account[98] = parse_hex("aa765705e28cbd99f9acae7d11413f2fe6d68c560ed7dbd6fae2789780cdcaf1");
        M_account[99] = parse_hex("bbba855791178b627cf6cdfb1761a552646e024c52844d2cb8b642c1e5df6568");
        M_account[100] = parse_hex("514e63c2dbdf15b3e18cbca6000165ad892d60501336367b796b1f5f12307555");
        M_account[101] = parse_hex("dcc5b20c359316c59adcf00f874549c7aa99e8b9613525d0da2a426c5ec9bbad");
        M_account[102] = parse_hex("b94baa4d146a85a6ad71b5fe864a0b532bdf546b1e7400e08d0bdb2c8b575d3b");
        M_account[103] = parse_hex("da77b79bde3dd10e7343fc1f4adc6d8f25093daed014aff74943270f79b9f0c5");
        M_account[104] = parse_hex("eb107ff45000e1406da500ad3d64a5eb34d8455f2c89d094ca5afc28841e125a");
        M_account[105] = parse_hex("dc5ba3a8bfcb7816f15d5f9abbc70a37ce1da4bc32760ead441fd7f0d58c3c23");
        M_account[106] = parse_hex("f842bc68ed9ebf12958947c90ba2c2d80304de6c86cc3f640ec0772485fc70f7");
        M_account[107] = parse_hex("14aaa0f21a3a37b104ea2858087b350012860249137b6f66b47c0ff6f2d25aba");
        M_account[108] = parse_hex("3a5feb86e9abb12c5df5ced62ebd619a17d1ffdb43d1f0b1fc69c878e56f7d5a");
        M_account[109] = parse_hex("90ab975e4a027504152199f359f838b0ee5bc86aa2ce52ea0641d9e9164f11a5");
        M_account[110] = parse_hex("8356d7689d0e465ee22898af37a57ed46782ad40aad30be85396dd34b02af965");
        M_account[111] = parse_hex("af5f060a1f46d4858c172da3490975b25959d4b2a187531a6e9d155f3ee78bc3");
        M_account[112] = parse_hex("f1d2cc3eb2e9a47a6894d6367f889c663da5b61ff56544370b9bff4694a159b3");
        M_account[113] = parse_hex("aa51fad7a90e782a12e1c9ea732e378d0239711a5a2f159fc81e6638fff2a94c");
        M_account[114] = parse_hex("312be8ab5dc5497c75b4031f07909d5246f514212c0b09b4ad95ea0a1fc29260");
        M_account[115] = parse_hex("b0c7904e089d09abed9daef88b0a70fe913288e4b4f7ee1a9862551ca4dbbdac");
        M_account[116] = parse_hex("32d4e56943c56685209bb33d41234a742569963b10cbddca6c588893bb87da31");
        M_account[117] = parse_hex("6ef51c39fa2daf88720b39ed97f0c3f5c6b747156151b6f2bfdd9cdcc52fca75");
        M_account[118] = parse_hex("3c00e401c12e3f63a7aa3907aa297ff21ded467ae751f3de02d8c7444caad76d");
        M_account[119] = parse_hex("29f2a2d20a285efacd371ce1b4aa6590f6972581d6e22ffe4cdcd1d6cc642628");
        M_account[120] = parse_hex("4f4d218779d043bd774b478c61a92b6575505d3cfd008a6554a53f2c2b3d39ac");
        M_account[121] = parse_hex("09ffcbd98271ee676422c0d0bfe890b0745b5ab6766bc54b9617fd33dfb8e74c");
        M_account[122] = parse_hex("7404409b8800b6eb6c05c4c2924248d8290da0a5303525af85ddf056c271c9a8");
        M_account[123] = parse_hex("de1c9aae7308ece06e81ae90e1383a4a87cb0416c65c9b9ffbad1a7c7eaf32a8");
        M_account[124] = parse_hex("5df34f8e76260a4456a85ff50e9751aec5c67df3f8d78b055c2366c21966456f");
        M_account[125] = parse_hex("07b63d7ffeb0c385e06edc432528c0cb51651a90bdf918213ea310da28904897");
        M_account[126] = parse_hex("11c9ccb91111c15cafcbf8f33c0a92b31e87cd4f1ef2cbafe0683163a9f23d34");
        M_account[127] = parse_hex("184b28ec7ece58df1e69923919ef84ef81dc89afb4a5eb759a9c30b83cbfbec9");
        M_account[128] = parse_hex("4093b9ddbe67a43ea00a1a28b6c868531700db4e6243c64d684fbe50c0d5d74c");
        M_account[129] = parse_hex("10bb8fc4d86accbf5a9e18e7003b250fa4ccc25a0193fe79b821d788ec002337");
        M_account[130] = parse_hex("d6f295d3e1de68b8d8747ea3d6668e20bbd58dc94bd363fc07f290bec7235f8c");
        M_account[131] = parse_hex("8c7214c588b02e46d7b68d3b479ecb8ff3cee3ae15556ec6e2d3ae6893ce39ea");
        M_account[132] = parse_hex("4c85b00425f5ec8962f29b7d975ef9c12aab8afe805c172824c2ffb6076a1d9f");
        M_account[133] = parse_hex("6a9062e2802461a5e9729498cafa9a750c5c85d1a4110a232b6da6b3a1e7e1d5");
        M_account[134] = parse_hex("9b6a072781eff4ba59739dccaf5d51f78f0f671ca00fb0704acc6412e1a4db4e");
        M_account[135] = parse_hex("8a42110e97f26d3fdcb3f438330756c9dd9e73f5c03a286adb4959e8ce02c9f3");
        M_account[136] = parse_hex("fec2837e5723f472efde29c1ac39c926c037cb37405c130d27c0b1acce4811c8");
        M_account[137] = parse_hex("637668b46af05ab9fe24ea10a96e0d25ef8484c64366408c15bb2412787696fc");
        M_account[138] = parse_hex("494f9889b08916834aeeacb0cea8186d61501b82ce665c08c0b98da3db032e68");
        M_account[139] = parse_hex("9a47edf75ff875f01ead48fdaa14373ea2439b0cdc95eb3bda78eb4ee07a99e1");
        M_account[140] = parse_hex("036fd595b1389838795986b74b830ea658091ed436a4a8d31b2ccf4b0201c610");
        M_account[141] = parse_hex("765eb0ac7bce24d38e7b218652866e0d4a72825f5e2afbe0bfa3179154c6ba49");
        M_account[142] = parse_hex("da0b38c51374da6694be6047f78a9b68c6177053ed90f620510465f6fec571fa");
        M_account[143] = parse_hex("8fba661138569ffc319a6a127c97e9bb83d1e15ff3ce6f70b0547221240296b4");
        M_account[144] = parse_hex("0efd6517755baeb9bf5577edc69928d091123624fd8de0773570c0f9fd1368a5");
        M_account[145] = parse_hex("1c4dc102a9996e9358abe07d1aca9750a1a170b7be2d49513953e2a213dc936d");
        M_account[146] = parse_hex("0433193ec9d67fbb75962b8f030c875526e5a67df391f718eaf59da4ceb11cc8");
        M_account[147] = parse_hex("5c3031767b26929f7b9d94ad78184019dbef5b511a9c39bf5fdba730b185f6b7");
        M_account[148] = parse_hex("e0940f4805f486e4d70897256213422469156dd9caf41a588c6932e83fef95ee");
        M_account[149] = parse_hex("1038cae26cf7cc4d72b3e0999323feea26a3c612417545c9fd9d2ba71a70232a");
        M_account[150] = parse_hex("ef1468368fed7ee13c50fe00759c702d7caebd50761750b9cd90fd593c93b42f");
        M_account[151] = parse_hex("6abf5560ccf0a2bc379cd950f1752741cbbe8f6775f2546066b2f72dfab55958");
        M_account[152] = parse_hex("c4f74cd00d4f78b68f5fa5f13e73be27565c8cd9d3c365874ae2d1bb5dfaa7f9");
        M_account[153] = parse_hex("4de23131bc442302e76922139d104868392d80ed8681329cd34b4861dd147d6a");
        M_account[154] = parse_hex("06d8e316c188c6f2d81a45deeee658e5454513e6412b71bc197e24f750d7bfd4");
        M_account[155] = parse_hex("b779ab1c297da2eb3f8a4c30383bd3058780a3f147932a69bcb4a0a7c1d05fbc");
        M_account[156] = parse_hex("29b2f939eeb312a7282295fb3b0ee7ce7da1bc52e30840cc04a77f7fd046261f");
        M_account[157] = parse_hex("3a7c4ad920e4857e93b7fba9030eea06ce88813bbb684b8239b283163101210d");
        M_account[158] = parse_hex("660f0ac9fb4fe935cec77dd897f2b1ed07046f22469bb4de4132bf08868cf000");
        M_account[159] = parse_hex("4c4ad559b2de70ae6c20b35451f7fbe5586638c750d67babda6f14cf12ab7ee2");

        let _test_variables = TestVariables{
            N_account : N_account,
            s_account : s_account,
            r_account : r_account,
            A_account : A_account,
            P_proof : Vec::with_capacity(0),
            leaf : Vec::with_capacity(0),
            M_account: M_account,
            W : W,
            V_account : V_account,
            T : Vec::with_capacity(0),
            V_S : Vec::with_capacity(0),
            V_R : Vec::with_capacity(0),
            L_P : Vec::with_capacity(0),
            s_S : Vec::with_capacity(0),
            r_S : Vec::with_capacity(0),
            r_R : Vec::with_capacity(0),
            A_PS : Vec::with_capacity(0),
            W_P : Vec::with_capacity(0),
            P_proof_R : Vec::with_capacity(0),
            F : Vec::with_capacity(0),
            j : Vec::with_capacity(0),
            L : Vec::with_capacity(0),
            P_proof_S : Vec::with_capacity(0),
            A_R : Vec::with_capacity(0),
            s_R : Vec::with_capacity(0),
            A_S : Vec::with_capacity(0),
        };

        return _test_variables;
    }
    if false {
        //Send test
        let W = parse_hex("8a05e4bb6ecc0891346c813960e2a03b496d04c719299278ce23a9c407317649");
        let T = parse_hex("a1dce3b29c0881c8e78c89adadf00f816ce77a2373a43ce154ac6f2c2743c3bb");
        let V_S = parse_hex("f5da29b399859f2f13bc4c51ed197a710d1a4a8f8f812b3bd1bf4e3add86b81f");
        let V_R = parse_hex("782791b7da8d329d0e169ae4642cec05eaa102b3f70f720f1dd2a535407c865a");
        let L_P = parse_hex("6f9127a505971eb2d995714337fdd2741922533fda6d4a21d1c1d9ccce33788c");
        let s_S = parse_hex("0c43a98ba9ec557c54a47826df6a4c694bc13b829e7fb68f066a1ccfb0daa34d");
        let r_S = parse_hex("1d4cd8c7382d438cd2bcb2b126fe1a72bf56f45ed5aaeddb150aaac5e44d1201");
        let r_R = parse_hex("beaaefcac20b6167e4fcc54d01bfbc1932eab75475232ed087e14f3680dd7c3e");
        let A_PS = parse_hex("99eac8d1180c5deac80f9bee0db660cd0c542be1");
        let W_P = parse_hex("ff18bc142266d906b4ec084dd6d01feedc7cd8a48c7493992af3663648911747");
        let P_proof_R = parse_hex("297177444968e060ef727bff8a333a0514a34db05b862dc0fc1e44fb06c9bd34");

        let _test_variables = TestVariables{
            N_account : 1u8,
            s_account : Vec::with_capacity(0),
            r_account : Vec::with_capacity(0),
            A_account : Vec::with_capacity(0),
            P_proof : Vec::with_capacity(0),
            leaf : Vec::with_capacity(0),
            M_account: vec![vec![0u8; 32]; 160],
            W : W,
            V_account : Vec::with_capacity(0),
            T : T,
            V_S : V_S,
            V_R : V_R,
            L_P : L_P,
            s_S : s_S,
            r_S : r_S,
            r_R : r_R,
            A_PS : A_PS,
            W_P : W_P,
            P_proof_R : P_proof_R,
            F : Vec::with_capacity(0),
            j : Vec::with_capacity(0),
            L : Vec::with_capacity(0),
            P_proof_S : Vec::with_capacity(0),
            A_R : Vec::with_capacity(0),
            s_R : Vec::with_capacity(0),
            A_S : Vec::with_capacity(0),
        };

        return _test_variables;
    }

    //Generate basic variables
    let mut s_account: Vec<u8> = (0..32).map(|_v| rng.gen()).collect();//=> P_proof, A_account_secret_key, A_account_public_key, A_account, A_R, L
    let N_account = 1u8;
    let r_account: Vec<u8> = (0..32).map(|_v| rng.gen()).collect();//=> V_account, r_R

    let mut s_S: Vec<u8> = (0..32).map(|_v| rng.gen()).collect();//=> A_S_secret_key, A_S_public_key, A_S, L, L_P
    let r_S: Vec<u8> = (0..32).map(|_v| rng.gen()).collect();//=> V_S

    let A_PS: Vec<u8> = (0..20).map(|_v| rng.gen()).collect();//=> L_P
    let W_P: Vec<u8> = (0..32).map(|_v| rng.gen()).collect();//=> L_P
    let F: Vec<u8> = (0..32).map(|_v| rng.gen()).collect();//=> T
    let j: Vec<u8> = (0..32).map(|_v| rng.gen()).collect();//=> T

    //Check s_account for 252 compliance
    if s_account[0] > 15 {
        s_account[0] &= 0x0F;
    }
    //Check s_S for 252 compliance
    if s_S[0] > 15 {
        s_S[0] &= 0x0F;
    }

    //Create keys and account
    let mut A_account = [0u8; 20];
    {
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
        //Because of the tragicly bad copying system in Rust
        for index in 12..32
        {
            A_account[index - 12] = A_account_public_key_bytes_keccak256[index];
        }
    }

    let mut A_S = [0u8; 20];
    {
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
        //Because of the tragicly bad copying system in Rust
        for index in 12..32
        {
            A_S[index - 12] = A_S_public_key_bytes_keccak256[index];
        }
    }

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
    let P_proof_R = P_proof.clone();

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
        let mut hash_input_left: Vec<u8> = F.clone();//reverse_vec(&j);//F.clone();
        let mut hash_input_right: Vec<u8> = j.clone();//reverse_vec(&F);//j.clone();
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
        let mut hash_input_left = T.to_vec().clone();
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
        let mut hash_input_left = T.to_vec().clone();
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


    // println!("s_S: {}", to_hex(&s_S));
    // println!("r_S: {}", to_hex(&r_S));
    // println!("A_PS: {}", to_hex(&A_PS));
    // println!("W_P: {}", to_hex(&W_P));
    // println!("F: {}", to_hex(&F));
    // println!("j: {}", to_hex(&j));

    // println!("");

    // println!("W: {}", to_hex(&W));
    // println!("T: {}", to_hex(&T));
    // println!("V_S: {}", to_hex(&V_S));
    // println!("V_R: {}", to_hex(&V_R));
    // println!("L_P: {}", to_hex(&L_P));
    // println!("s_S: {}", to_hex(&s_S));
    // println!("r_S: {}", to_hex(&r_S));
    // println!("r_R: {}", to_hex(&r_R));
    // println!("A_PS: {}", to_hex(&A_PS));
    // println!("W_P: {}", to_hex(&W_P));
    // println!("P_proof_R: {}", to_hex(&P_proof_R));

    //return
    let _test_variables = TestVariables{
        N_account : N_account,
        s_account : s_account,
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
fn parse_hex(hex_asm: &str) -> Vec<u8> {
    let mut hex_bytes = hex_asm.as_bytes().iter().filter_map(|b| {
        match b {
            b'0'...b'9' => Some(b - b'0'),
            b'a'...b'f' => Some(b - b'a' + 10),
            b'A'...b'F' => Some(b - b'A' + 10),
            _ => None,
        }
    }).fuse();

    let mut bytes = Vec::new();
    while let (Some(h), Some(l)) = (hex_bytes.next(), hex_bytes.next()) {
        bytes.push(h << 4 | l)
    }
    bytes
}

fn reverse_vec(blob: &Vec<u8>) -> Vec<u8> {
    let mut reverse: Vec<u8> = Vec::with_capacity(blob.len());
    for index in 0..blob.len() {
        reverse.insert(index, blob[blob.len() - index - 1]);
    }
    reverse
}

#[test]
fn test_sha_256_empty() {
    let mut sha256 = Sha256::new();
    let hash_input: Vec<u8> = Vec::with_capacity(64);
    sha256.input(hash_input.as_ref());
    assert_eq!(sha256.result_str(), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

    sha256.reset();
    let hash_input: Vec<u8> = [0u8; 64].to_vec();
    sha256.input(hash_input.as_ref());
    assert_eq!(sha256.result_str(), "f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b");

    sha256.reset();
    let mut hash_input_left: Vec<u8> = Vec::with_capacity(32);
    let mut hash_input_right: Vec<u8> = Vec::with_capacity(32);
    hash_input_left.append(&mut hash_input_right);
    sha256.input(hash_input_left.as_ref());
    assert_eq!(sha256.result_str(), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

#[test]
fn test_gts() {
    let gts_pk_path = CString::new("/home/sean/Gunero/demo/GTS.pk.bin").expect("CString::new failed");
    let gts_vk_path = CString::new("/home/sean/Gunero/demo/GTS.vk.bin").expect("CString::new failed");
    let gts_proof_path = CString::new("/home/sean/Gunero/demo/GTS.proof.test.bin").expect("CString::new failed");

    let W_hex = CString::new("3b6af04fea0230d4073f4f80c742dcb6772c1431190cf561466ab3ca10f5655a").expect("CString::new failed");
    let T_hex = CString::new("ebe3303ba9044d2f022d8de740e1d3bafcd23a4a736a48610c7232133189d41a").expect("CString::new failed");
    let V_S_hex = CString::new("a8e63e453d2eb057227430897d312c5be68b86fda8f644aceffcf5bbc223ea6b").expect("CString::new failed");
    let V_R_hex = CString::new("12d9878c93d8d559d0e924e3d53bfcf6f2199651a208a57e10ef929a396f111c").expect("CString::new failed");
    let L_P_hex = CString::new("ce610326d0fbc7de2e3fba8ca1fc2c968e1cacbaadf3c5c595837291cc2e00b0").expect("CString::new failed");
    let s_S_hex = CString::new("0f18990285a5798526ba0a8910af5b8b119977f30fcae2082af136fb46e310f5").expect("CString::new failed");
    let r_S_hex = CString::new("fba9f7804e7005742a0ffd3bbf58c6d0f13dc40107a6093297402ddd233ed21e").expect("CString::new failed");
    let r_R_hex = CString::new("e49298999ab48d7a001d6a3ea4a01a46b2a2e196b257f11187413bfb82f60566").expect("CString::new failed");
    let A_PS_hex = CString::new("e7ca9e363aa3aa65b3a8a072006642f2a306f3ab").expect("CString::new failed");
    let W_P_hex = CString::new("acfcdd433c0a205f48f37d30bd1b66f7bf105c72b8fce4b96226ab062d9eb1d9").expect("CString::new failed");
    let P_proof_R_hex = CString::new("4d36c4aa980719f2060ab46b1e838ca782ffafa1451295419b98e12d60f32d72").expect("CString::new failed");

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
    assert_eq!(ret, 0);
}