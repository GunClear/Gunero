#include <fstream>
//#include <libff/common/default_types/ec_pp.hpp>
#include <libsnark/common/default_types/r1cs_gg_ppzksnark_pp.hpp>
#include <libsnark/relations/constraint_satisfaction_problems/r1cs/examples/r1cs_examples.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>

#ifndef CURVE_BN128
#define CURVE_BN128
#endif

#ifdef CURVE_BN128
#include <libff/algebra/curves/bn128/bn128_pp.hpp>
#endif
#include <libff/algebra/curves/edwards/edwards_pp.hpp>
#include <libff/algebra/curves/mnt/mnt4/mnt4_pp.hpp>
#include <libff/algebra/curves/mnt/mnt6/mnt6_pp.hpp>

#include <libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/merkle_tree/merkle_tree_check_read_gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/merkle_tree/merkle_tree_check_update_gadget.hpp>

#include "sparse_merkle_tree_check_read_gadget.hpp"
#include "sparse_merkle_tree_check_update_gadget.hpp"

using namespace libsnark;
//using namespace gunero;

template<typename T>
void saveToFile(const std::string path, T& obj) {
    std::stringstream ss;
    ss << obj;
    std::ofstream fh;
    fh.open(path, std::ios::binary);
    ss.rdbuf()->pubseekpos(0, std::ios_base::out);
    fh << ss.rdbuf();
    fh.flush();
    fh.close();
}

template<typename T>
void loadFromFile(const std::string path, T& objIn) {
    std::stringstream ss;
    std::ifstream fh(path, std::ios::binary);

    if(!fh.is_open()) {
        throw std::runtime_error(strprintf("could not load param file at %s", path));
    }

    ss << fh.rdbuf();
    fh.close();

    ss.rdbuf()->pubseekpos(0, std::ios_base::in);

    T obj;
    ss >> obj;

    objIn = std::move(obj);
}

/**
 * The code below provides an example of all stages of running a R1CS GG-ppzkSNARK.
 *
 * Of course, in a real-life scenario, we would have three distinct entities,
 * mangled into one in the demonstration below. The three entities are as follows.
 * (1) The "generator", which runs the ppzkSNARK generator on input a given
 *     constraint system CS to create a proving and a verification key for CS.
 * (2) The "prover", which runs the ppzkSNARK prover on input the proving key,
 *     a primary input for CS, and an auxiliary input for CS.
 * (3) The "verifier", which runs the ppzkSNARK verifier on input the verification key,
 *     a primary input for CS, and a proof.
 */
template<typename ppT>
bool run_r1cs_gg_ppzksnark(const r1cs_example<libff::Fr<ppT> > &example)
{
    libff::print_header("R1CS GG-ppzkSNARK Generator");
    r1cs_gg_ppzksnark_keypair<ppT> keypair = r1cs_gg_ppzksnark_generator<ppT>(example.constraint_system);
    printf("\n"); libff::print_indent(); libff::print_mem("after generator");

    libff::print_header("Preprocess verification key");
    r1cs_gg_ppzksnark_processed_verification_key<ppT> pvk = r1cs_gg_ppzksnark_verifier_process_vk<ppT>(keypair.vk);

    libff::print_header("R1CS GG-ppzkSNARK Prover");
    r1cs_gg_ppzksnark_proof<ppT> proof = r1cs_gg_ppzksnark_prover<ppT>(keypair.pk, example.primary_input, example.auxiliary_input);
    printf("\n"); libff::print_indent(); libff::print_mem("after prover");

    libff::print_header("R1CS GG-ppzkSNARK Verifier");
    const bool ans = r1cs_gg_ppzksnark_verifier_strong_IC<ppT>(keypair.vk, example.primary_input, proof);
    printf("\n"); libff::print_indent(); libff::print_mem("after verifier");
    printf("* The verification result is: %s\n", (ans ? "PASS" : "FAIL"));

    libff::print_header("R1CS GG-ppzkSNARK Online Verifier");
    const bool ans2 = r1cs_gg_ppzksnark_online_verifier_strong_IC<ppT>(pvk, example.primary_input, proof);
    assert(ans == ans2);

    return ans;
}

template<typename ppT>
void test_r1cs_gg_ppzksnark(size_t num_constraints, size_t input_size)
{
    r1cs_example<libff::Fr<ppT> > example = generate_r1cs_example_with_binary_input<libff::Fr<ppT> >(num_constraints, input_size);
    const bool bit = run_r1cs_gg_ppzksnark<ppT>(example);
    assert(bit);
}


template<typename ppT>
void test_all_merkle_tree_gadgets()
{
    typedef libff::Fr<ppT> FieldT;
    test_merkle_tree_check_read_gadget<FieldT, CRH_with_bit_out_gadget<FieldT> >();
    test_merkle_tree_check_read_gadget<FieldT, sha256_two_to_one_hash_gadget<FieldT> >();

    test_merkle_tree_check_update_gadget<FieldT, CRH_with_bit_out_gadget<FieldT> >();
    test_merkle_tree_check_update_gadget<FieldT, sha256_two_to_one_hash_gadget<FieldT> >();
}

template<typename FieldT, typename BaseT, typename HashT>
void Gunero_test_merkle_tree_check_read_gadget(size_t tree_depth)
{
    libff::start_profiling();
    const size_t digest_len = HashT::get_digest_len();

    std::string r1csPath = "r1cs.bin";
    std::string vkPath = "vk.bin";
    std::string pkPath = "pk.bin";

    /* generate circuit */
    libff::print_header("Gunero Generator");
    protoboard<FieldT> pb;
    pb_variable_array<FieldT> address_bits_va;
    address_bits_va.allocate(pb, tree_depth, "address_bits");
    digest_variable<FieldT> leaf_digest(pb, digest_len, "input_block");
    digest_variable<FieldT> root_digest(pb, digest_len, "output_digest");
    merkle_authentication_path_variable<FieldT, HashT> path_var(pb, tree_depth, "path_var");
    merkle_tree_check_read_gadget<FieldT, HashT> ml(pb, tree_depth, address_bits_va, leaf_digest, root_digest, path_var, ONE, "ml");

    path_var.generate_r1cs_constraints();
    ml.generate_r1cs_constraints();

    printf("\n"); libff::print_indent(); libff::print_mem("after generator"); libff::print_time("after generator");

    const r1cs_constraint_system<FieldT> constraint_system = pb.get_constraint_system();

    saveToFile(r1csPath, constraint_system);

    r1cs_ppzksnark_keypair<BaseT> keypair = r1cs_ppzksnark_generator<BaseT>(constraint_system);

    saveToFile(vkPath, keypair.vk);
    saveToFile(pkPath, keypair.pk);

    /* prepare test variables */
    libff::print_header("Gunero prepare test variables");
    std::vector<merkle_authentication_node> path(tree_depth);

    libff::bit_vector prev_hash(digest_len);
    std::generate(prev_hash.begin(), prev_hash.end(), [&]() { return std::rand() % 2; });
    libff::bit_vector leaf = prev_hash;

    libff::bit_vector address_bits;

    size_t address = 0;
    for (long level = tree_depth-1; level >= 0; --level)
    {
        const bool computed_is_right = (std::rand() % 2);
        address |= (computed_is_right ? 1ul << (tree_depth-1-level) : 0);
        address_bits.push_back(computed_is_right);
        libff::bit_vector other(digest_len);
        std::generate(other.begin(), other.end(), [&]() { return std::rand() % 2; });

        libff::bit_vector block = prev_hash;
        block.insert(computed_is_right ? block.begin() : block.end(), other.begin(), other.end());
        libff::bit_vector h = HashT::get_hash(block);

        path[level] = other;

        prev_hash = h;
    }
    libff::bit_vector root = prev_hash;
    printf("\n"); libff::print_indent(); libff::print_mem("after prepare test variables"); libff::print_time("after prepare test variables");

    /* witness (proof) */
    libff::print_header("Gunero witness (proof)");
    address_bits_va.fill_with_bits(pb, address_bits);
    assert(address_bits_va.get_field_element_from_bits(pb).as_ulong() == address);
    leaf_digest.generate_r1cs_witness(leaf);
    path_var.generate_r1cs_witness(address, path);
    ml.generate_r1cs_witness();

    /* make sure that read checker didn't accidentally overwrite anything */
    address_bits_va.fill_with_bits(pb, address_bits);
    leaf_digest.generate_r1cs_witness(leaf);
    root_digest.generate_r1cs_witness(root);
    assert(pb.is_satisfied());
    printf("\n"); libff::print_indent(); libff::print_mem("after witness (proof)"); libff::print_time("after witness (proof)");

    /* verify */
    libff::print_header("Gunero verify");
    const size_t num_constraints = pb.num_constraints();
    const size_t expected_constraints = merkle_tree_check_read_gadget<FieldT, HashT>::expected_constraints(tree_depth);
    assert(num_constraints == expected_constraints);
    printf("\n"); libff::print_indent(); libff::print_mem("after verify"); libff::print_time("after verify");

    libff::clear_profiling_counters();
}

// template<typename FieldT, typename HashT>
// void Gunero_test_sparse_merkle_tree_check_read_gadget()
// {
//     /* prepare test variables */
//     std::clock_t    start = std::clock();
//     libff::print_header("Gunero prepare test variables");
//     const size_t digest_len = HashT::get_digest_len();
//     const size_t tree_depth = 8;
//     std::vector<merkle_authentication_node> path(tree_depth);

//     libff::bit_vector prev_hash(digest_len);
//     std::generate(prev_hash.begin(), prev_hash.end(), [&]() { return std::rand() % 2; });
//     libff::bit_vector leaf = prev_hash;

//     libff::bit_vector address_bits;

//     size_t address = 0;
//     for (long level = tree_depth-1; level >= 0; --level)
//     {
//         const bool computed_is_right = (std::rand() % 2);
//         address |= (computed_is_right ? 1ul << (tree_depth-1-level) : 0);
//         address_bits.push_back(computed_is_right);
//         libff::bit_vector other(digest_len);

//         //Decide on sparseness (with the computed_is_right ignored on read but used for update)
//         if (std::rand() % 2)
//         {//sparse/NULL
//             std::generate(other.begin(), other.end(), [&]() { return 0; });
//         }
//         else
//         {
//              std::generate(other.begin(), other.end(), [&]() { return std::rand() % 2; });
//         }

//         libff::bit_vector block = prev_hash;
//         block.insert(computed_is_right ? block.begin() : block.end(), other.begin(), other.end());
//         libff::bit_vector h = HashT::get_hash(block);

//         path[level] = other;

//         prev_hash = h;
//     }
//     libff::bit_vector root = prev_hash;
//     printf("\n"); libff::print_indent(); libff::print_mem("after prepare test variables"); libff::print_time("after prepare test variables");

//     /* generate circuit */
//     libff::print_header("Gunero Generator");
//     protoboard<FieldT> pb;
//     pb_variable_array<FieldT> address_bits_va;
//     address_bits_va.allocate(pb, tree_depth, "address_bits");
//     digest_variable<FieldT> leaf_digest(pb, digest_len, "input_block");
//     digest_variable<FieldT> root_digest(pb, digest_len, "output_digest");
//     merkle_authentication_path_variable<FieldT, HashT> path_var(pb, tree_depth, "path_var");
//     gunero::sparse_merkle_tree_check_read_gadget<FieldT, HashT> ml(pb, tree_depth, address_bits_va, leaf_digest, root_digest, path_var, ONE, "ml");

//     path_var.generate_r1cs_constraints();
//     ml.generate_r1cs_constraints();
//     printf("\n"); libff::print_indent(); libff::print_mem("after generator"); libff::print_time("after generator");

//     /* witness (proof) */
//     libff::print_header("Gunero witness (proof)");
//     address_bits_va.fill_with_bits(pb, address_bits);
//     assert(address_bits_va.get_field_element_from_bits(pb).as_ulong() == address);
//     leaf_digest.generate_r1cs_witness(leaf);
//     path_var.generate_r1cs_witness(address, path);
//     ml.generate_r1cs_witness();

//     /* make sure that read checker didn't accidentally overwrite anything */
//     address_bits_va.fill_with_bits(pb, address_bits);
//     leaf_digest.generate_r1cs_witness(leaf);
//     root_digest.generate_r1cs_witness(root);
//     printf("\n"); libff::print_indent(); libff::print_mem("after witness (proof)"); libff::print_time("after witness (proof)");

//     /* verify */
//     libff::print_header("Gunero verify");
//     assert(pb.is_satisfied());
//     const size_t num_constraints = pb.num_constraints();
//     const size_t expected_constraints = gunero::sparse_merkle_tree_check_read_gadget<FieldT, HashT>::expected_constraints(tree_depth);
//     assert(num_constraints == expected_constraints);
//     printf("\n"); libff::print_indent(); libff::print_mem("after verify"); libff::print_time("after verify");
// }

int main () {
//    default_r1cs_gg_ppzksnark_pp::init_public_params();
//    test_r1cs_gg_ppzksnark<default_r1cs_gg_ppzksnark_pp>(1000, 100);

//    libff::start_profiling();

//#ifdef CURVE_BN128       // BN128 has fancy dependencies so it may be disabled
//    libff::bn128_pp::init_public_params();
//    test_all_merkle_tree_gadgets<libff::bn128_pp>();
//#endif

//    libff::edwards_pp::init_public_params();
//    test_all_merkle_tree_gadgets<libff::edwards_pp>();

//    libff::mnt4_pp::init_public_params();
//    test_all_merkle_tree_gadgets<libff::mnt4_pp>();

//    libff::mnt6_pp::init_public_params();
//    test_all_merkle_tree_gadgets<libff::mnt6_pp>();

    //Gunero tests
 //   {//edwards_pp
 //       libff::start_profiling();
 //       libff::edwards_pp::init_public_params();

//        typedef libff::Fr<libff::edwards_pp> FieldT;
//        Gunero_test_merkle_tree_check_read_gadget<FieldT, sha256_two_to_one_hash_gadget<FieldT> >();
//
//        libff::clear_profiling_counters();
//    }

    {//bn128_pp
        libff::bn128_pp::init_public_params();

        typedef libff::Fr<libff::bn128_pp> FieldT;
        typedef libff::bn128_pp BaseT;
        Gunero_test_merkle_tree_check_read_gadget<FieldT, BaseT, sha256_two_to_one_hash_gadget<FieldT> >(64);
    }

//    {//bn128_pp
//        libff::start_profiling();
//        libff::bn128_pp::init_public_params();

//        typedef libff::Fr<libff::bn128_pp> FieldT;
//        Gunero_test_sparse_merkle_tree_check_read_gadget<FieldT, sha256_two_to_one_hash_gadget<FieldT> >();

//        libff::clear_profiling_counters();
//    }

    return 0;
}
