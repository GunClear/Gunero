#include <fstream>
//#include <libff/common/default_types/ec_pp.hpp> 
#include <libsnark/common/default_types/r1cs_gg_ppzksnark_pp.hpp>
#include <libsnark/common/default_types/r1cs_gg_ppzksnark_pp.hpp>
#include <libsnark/relations/constraint_satisfaction_problems/r1cs/examples/r1cs_examples.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/uscs_ppzksnark/uscs_ppzksnark.hpp>
#include <libff/algebra/fields/field_utils.hpp>
#include <libff/algebra/scalar_multiplication/multiexp.hpp>
#include <libsnark/common/default_types/r1cs_ppzksnark_pp.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>

// #ifndef CURVE_BN128
// #define CURVE_BN128
// #endif
#ifndef ALT_BN128
#define ALT_BN128
#endif

#ifdef CURVE_BN128
#include <libff/algebra/curves/bn128/bn128_pp.hpp>
#endif
#ifdef ALT_BN128
#include <libff/algebra/curves/alt_bn128/alt_bn128_init.hpp>
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#endif
#include <libff/algebra/curves/edwards/edwards_pp.hpp>
#include <libff/algebra/curves/mnt/mnt4/mnt4_pp.hpp>
#include <libff/algebra/curves/mnt/mnt6/mnt6_pp.hpp>
#include <libff/common/utils.hpp>

#include <libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/merkle_tree/merkle_tree_check_read_gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/merkle_tree/merkle_tree_check_update_gadget.hpp>

#include "sparse_merkle_tree_check_read_gadget.hpp"
#include "sparse_merkle_tree_check_update_gadget.hpp"

#include "serialize.h"
#include "crypto/sha256.h"

using namespace libsnark;
//using namespace libzcash;
//using namespace gunero;

const signed char p_util_hexdigit[256] =
{ -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  0,1,2,3,4,5,6,7,8,9,-1,-1,-1,-1,-1,-1,
  -1,0xa,0xb,0xc,0xd,0xe,0xf,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,0xa,0xb,0xc,0xd,0xe,0xf,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1, };

signed char HexDigit(char c)
{
    return p_util_hexdigit[(unsigned char)c];
}

/** Template base class for fixed-sized opaque blobs. */
template<unsigned int BITS>
class base_blob
{
protected:
    enum { WIDTH=BITS/8 };
    alignas(uint32_t) uint8_t data[WIDTH];
public:
    base_blob()
    {
        memset(data, 0, sizeof(data));
    }

    explicit base_blob(const std::vector<unsigned char>& vch);

    bool IsNull() const
    {
        for (int i = 0; i < WIDTH; i++)
            if (data[i] != 0)
                return false;
        return true;
    }

    void SetNull()
    {
        memset(data, 0, sizeof(data));
    }

    friend inline bool operator==(const base_blob& a, const base_blob& b) { return memcmp(a.data, b.data, sizeof(a.data)) == 0; }
    friend inline bool operator!=(const base_blob& a, const base_blob& b) { return memcmp(a.data, b.data, sizeof(a.data)) != 0; }
    friend inline bool operator<(const base_blob& a, const base_blob& b) { return memcmp(a.data, b.data, sizeof(a.data)) < 0; }

    std::string GetHex() const;
    void SetHex(const char* psz);
    void SetHex(const std::string& str);
    std::string ToString() const;

    unsigned char* begin()
    {
        return &data[0];
    }

    unsigned char* end()
    {
        return &data[WIDTH];
    }

    const unsigned char* begin() const
    {
        return &data[0];
    }

    const unsigned char* end() const
    {
        return &data[WIDTH];
    }

    unsigned int size() const
    {
        return sizeof(data);
    }

    unsigned int GetSerializeSize(int nType, int nVersion) const
    {
        return sizeof(data);
    }

    template<typename Stream>
    void Serialize(Stream& s, int nType, int nVersion) const
    {
        s.write((char*)data, sizeof(data));
    }

    template<typename Stream>
    void Unserialize(Stream& s, int nType, int nVersion)
    {
        s.read((char*)data, sizeof(data));
    }
};

/** 256-bit opaque blob.
 * @note This type is called uint256 for historical reasons only. It is an
 * opaque blob of 256 bits and has no integer operations. Use arith_uint256 if
 * those are required.
 */
class uint256 : public base_blob<256> {
public:
    uint256() {}
    uint256(const base_blob<256>& b) : base_blob<256>(b) {}
    explicit uint256(const std::vector<unsigned char>& vch) : base_blob<256>(vch) {}

    /** A cheap hash function that just returns 64 bits from the result, it can be
     * used when the contents are considered uniformly random. It is not appropriate
     * when the value can easily be influenced from outside as e.g. a network adversary could
     * provide values to trigger worst-case behavior.
     * @note The result of this function is not stable between little and big endian.
     */
    uint64_t GetCheapHash() const
    {
        uint64_t result;
        memcpy((void*)&result, (void*)data, 8);
        return result;
    }

    /** A more secure, salted hash function.
     * @note This hash is not stable between little and big endian.
     */
    uint64_t GetHash(const uint256& salt) const;
};

/* uint256 from const char *.
 * This is a separate function because the constructor uint256(const char*) can result
 * in dangerously catching uint256(0).
 */
inline uint256 uint256S(const char *str)
{
    uint256 rv;
    rv.SetHex(str);
    return rv;
}
/* uint256 from std::string.
 * This is a separate function because the constructor uint256(const std::string &str) can result
 * in dangerously catching uint256(0) via std::string(const char*).
 */
inline uint256 uint256S(const std::string& str)
{
    uint256 rv;
    rv.SetHex(str);
    return rv;
}

class uint252 {
private:
    uint256 contents;

public:
    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(contents);

        if ((*contents.begin()) & 0xF0) {
            throw std::ios_base::failure("spending key has invalid leading bits");
        }
    }

    const unsigned char* begin() const
    {
        return contents.begin();
    }

    const unsigned char* end() const
    {
        return contents.end();
    }

    uint252() : contents() {};
    explicit uint252(const uint256& in) : contents(in) {
        if (*contents.begin() & 0xF0) {
            throw std::domain_error("leading bits are set in argument given to uint252 constructor");
        }
    }

    uint256 inner() const {
        return contents;
    }

    friend inline bool operator==(const uint252& a, const uint252& b) { return a.contents == b.contents; }
};

class uint160 {
private:
    uint256 contents;

public:
    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(contents);

        if ((*contents.begin()) & 0xF0) {
            throw std::ios_base::failure("spending key has invalid leading bits");
        }
    }

    const unsigned char* begin() const
    {
        return contents.begin();
    }

    const unsigned char* end() const
    {
        return contents.end();
    }

    uint160() : contents() {};
    explicit uint160(const uint256& in) : contents(in) {
        if (*contents.begin() & 0xF0) {
            throw std::domain_error("leading bits are set in argument given to uint160 constructor");
        }
    }

    uint256 inner() const {
        return contents;
    }

    friend inline bool operator==(const uint160& a, const uint160& b) { return a.contents == b.contents; }
};

template <unsigned int BITS>
base_blob<BITS>::base_blob(const std::vector<unsigned char>& vch)
{
    assert(vch.size() == sizeof(data));
    memcpy(data, &vch[0], sizeof(data));
}

template <unsigned int BITS>
std::string base_blob<BITS>::GetHex() const
{
    char psz[sizeof(data) * 2 + 1];
    for (unsigned int i = 0; i < sizeof(data); i++)
        sprintf(psz + i * 2, "%02x", data[sizeof(data) - i - 1]);
    return std::string(psz, psz + sizeof(data) * 2);
}

template <unsigned int BITS>
void base_blob<BITS>::SetHex(const char* psz)
{
    memset(data, 0, sizeof(data));

    // skip leading spaces
    while (isspace(*psz))
        psz++;

    // skip 0x
    if (psz[0] == '0' && tolower(psz[1]) == 'x')
        psz += 2;

    // hex string to uint
    const char* pbegin = psz;
    while (::HexDigit(*psz) != -1)
        psz++;
    psz--;
    unsigned char* p1 = (unsigned char*)data;
    unsigned char* pend = p1 + WIDTH;
    while (psz >= pbegin && p1 < pend) {
        *p1 = ::HexDigit(*psz--);
        if (psz >= pbegin) {
            *p1 |= ((unsigned char)::HexDigit(*psz--) << 4);
            p1++;
        }
    }
}

template <unsigned int BITS>
void base_blob<BITS>::SetHex(const std::string& str)
{
    SetHex(str.c_str());
}

template <unsigned int BITS>
std::string base_blob<BITS>::ToString() const
{
    return (GetHex());
}

// Explicit instantiations for base_blob<160>
template base_blob<160>::base_blob(const std::vector<unsigned char>&);
template std::string base_blob<160>::GetHex() const;
template std::string base_blob<160>::ToString() const;
template void base_blob<160>::SetHex(const char*);
template void base_blob<160>::SetHex(const std::string&);

// Explicit instantiations for base_blob<256>
template base_blob<256>::base_blob(const std::vector<unsigned char>&);
template std::string base_blob<256>::GetHex() const;
template std::string base_blob<256>::ToString() const;
template void base_blob<256>::SetHex(const char*);
template void base_blob<256>::SetHex(const std::string&);

static void inline HashMix(uint32_t& a, uint32_t& b, uint32_t& c)
{
    // Taken from lookup3, by Bob Jenkins.
    a -= c;
    a ^= ((c << 4) | (c >> 28));
    c += b;
    b -= a;
    b ^= ((a << 6) | (a >> 26));
    a += c;
    c -= b;
    c ^= ((b << 8) | (b >> 24));
    b += a;
    a -= c;
    a ^= ((c << 16) | (c >> 16));
    c += b;
    b -= a;
    b ^= ((a << 19) | (a >> 13));
    a += c;
    c -= b;
    c ^= ((b << 4) | (b >> 28));
    b += a;
}

static void inline HashFinal(uint32_t& a, uint32_t& b, uint32_t& c)
{
    // Taken from lookup3, by Bob Jenkins.
    c ^= b;
    c -= ((b << 14) | (b >> 18));
    a ^= c;
    a -= ((c << 11) | (c >> 21));
    b ^= a;
    b -= ((a << 25) | (a >> 7));
    c ^= b;
    c -= ((b << 16) | (b >> 16));
    a ^= c;
    a -= ((c << 4) | (c >> 28));
    b ^= a;
    b -= ((a << 14) | (a >> 18));
    c ^= b;
    c -= ((b << 24) | (b >> 8));
}

uint64_t uint256::GetHash(const uint256& salt) const
{
    uint32_t a, b, c;
    const uint32_t *pn = (const uint32_t*)data;
    const uint32_t *salt_pn = (const uint32_t*)salt.data;
    a = b = c = 0xdeadbeef + WIDTH;

    a += pn[0] ^ salt_pn[0];
    b += pn[1] ^ salt_pn[1];
    c += pn[2] ^ salt_pn[2];
    HashMix(a, b, c);
    a += pn[3] ^ salt_pn[3];
    b += pn[4] ^ salt_pn[4];
    c += pn[5] ^ salt_pn[5];
    HashMix(a, b, c);
    a += pn[6] ^ salt_pn[6];
    b += pn[7] ^ salt_pn[7];
    HashFinal(a, b, c);

    return ((((uint64_t)b) << 32) | c);
}

uint256 PRF_addr_a_pk(const uint252& a_sk);
uint256 PRF_addr_sk_enc(const uint252& a_sk);
uint256 PRF_nf(const uint252& a_sk, const uint256& rho);
uint256 PRF_pk(const uint252& a_sk, size_t i0, const uint256& h_sig);
uint256 PRF_rho(const uint252& phi, size_t i0, const uint256& h_sig);

uint256 random_uint256();
uint252 random_uint252();
uint160 random_uint160();

#define NOTEENCRYPTION_AUTH_BYTES 16

template<size_t MLEN>
class NoteEncryption {
protected:
    enum { CLEN=MLEN+NOTEENCRYPTION_AUTH_BYTES };
    uint256 epk;
    uint256 esk;
    unsigned char nonce;
    uint256 hSig;

public:
    typedef boost::array<unsigned char, CLEN> Ciphertext;
    typedef boost::array<unsigned char, MLEN> Plaintext;

    NoteEncryption(uint256 hSig);

    // Gets the ephemeral public key
    uint256 get_epk() {
        return epk;
    }

    // Encrypts `message` with `pk_enc` and returns the ciphertext.
    // This is only called ZC_NUM_JS_OUTPUTS times for a given instantiation; 
    // but can be called 255 times before the nonce-space runs out.
    Ciphertext encrypt(const uint256 &pk_enc,
                       const Plaintext &message
                      );

    // Creates a NoteEncryption private key
    static uint256 generate_privkey(const uint252 &a_sk);

    // Creates a NoteEncryption public key from a private key
    static uint256 generate_pubkey(const uint256 &sk_enc);
};

template<size_t MLEN>
class NoteDecryption {
protected:
    enum { CLEN=MLEN+NOTEENCRYPTION_AUTH_BYTES };
    uint256 sk_enc;
    uint256 pk_enc;

public:
    typedef boost::array<unsigned char, CLEN> Ciphertext;
    typedef boost::array<unsigned char, MLEN> Plaintext;

    NoteDecryption() { }
    NoteDecryption(uint256 sk_enc);

    Plaintext decrypt(const Ciphertext &ciphertext,
                      const uint256 &epk,
                      const uint256 &hSig,
                      unsigned char nonce
                     ) const;

    friend inline bool operator==(const NoteDecryption& a, const NoteDecryption& b) {
        return a.sk_enc == b.sk_enc && a.pk_enc == b.pk_enc;
    }
    friend inline bool operator<(const NoteDecryption& a, const NoteDecryption& b) {
        return (a.sk_enc < b.sk_enc ||
                (a.sk_enc == b.sk_enc && a.pk_enc < b.pk_enc));
    }
};

#define ZC_NOTEPLAINTEXT_LEADING 1
#define ZC_V_SIZE 8
#define ZC_RHO_SIZE 32
#define ZC_R_SIZE 32
#define ZC_MEMO_SIZE 512
#define ZC_NOTEPLAINTEXT_SIZE (ZC_NOTEPLAINTEXT_LEADING + ZC_V_SIZE + ZC_RHO_SIZE + ZC_R_SIZE + ZC_MEMO_SIZE)

typedef NoteEncryption<ZC_NOTEPLAINTEXT_SIZE> ZCNoteEncryption;
typedef NoteDecryption<ZC_NOTEPLAINTEXT_SIZE> ZCNoteDecryption;

template<typename FieldT, typename BaseT, typename HashT, size_t tree_depth>
class guneromembership_gadget : public gadget<FieldT> {
public:
    const size_t digest_len;
    protoboard<FieldT> mpb;
    digest_variable<FieldT> leaf_digest;
    digest_variable<FieldT> root_digest;
    merkle_authentication_path_variable<FieldT, HashT> path_var;
    pb_variable_array<FieldT> address_bits_va;
    merkle_tree_check_read_gadget<FieldT, HashT> ml;

    // guneromembership_gadget()
    //     : gadget<FieldT>(pb, "guneromembership_gadget")
    //     , digest_len(HashT::get_digest_len())
    //     , leaf_digest(pb, digest_len, "input_block")
    //     , root_digest(pb, digest_len, "output_digest")
    //     , path_var(pb, tree_depth, "path_var")
    //     , address_bits_va(pb, tree_depth, "address_bits")
    //     , ml(pb, tree_depth, address_bits_va, leaf_digest, root_digest, path_var, ONE, "ml")
    // {
    //     // pb_variable_array<FieldT> address_bits_va;
    //     // address_bits_va.allocate(pb, tree_depth, "address_bits");
    //     //digest_variable<FieldT> leaf_digest(pb, digest_len, "input_block");
    //     //digest_variable<FieldT> root_digest(pb, digest_len, "output_digest");
    //     //merkle_tree_check_read_gadget<FieldT, HashT> ml(pb, tree_depth, address_bits_va, leaf_digest, root_digest, path_var, ONE, "ml");
    // }
    guneromembership_gadget(protoboard<FieldT>& pb)
        : gadget<FieldT>(pb, "guneromembership_gadget")
        , mpb(pb)
        , digest_len(HashT::get_digest_len())
        , leaf_digest(pb, digest_len, "input_block")
        , root_digest(pb, digest_len, "output_digest")
        , path_var(pb, tree_depth, "path_var")
        , address_bits_va(pb, tree_depth, "address_bits")
        , ml(pb, tree_depth, address_bits_va, leaf_digest, root_digest, path_var, ONE, "ml")
    {
        // pb_variable_array<FieldT> address_bits_va;
        // address_bits_va.allocate(pb, tree_depth, "address_bits");
        //digest_variable<FieldT> leaf_digest(pb, digest_len, "input_block");
        //digest_variable<FieldT> root_digest(pb, digest_len, "output_digest");
        //merkle_tree_check_read_gadget<FieldT, HashT> ml(pb, tree_depth, address_bits_va, leaf_digest, root_digest, path_var, ONE, "ml");
    }

    ~guneromembership_gadget()
    {

    }

    void load_r1cs_constraints()
    {
        libff::print_header("Gunero load constraints");

        path_var.generate_r1cs_constraints();
        ml.generate_r1cs_constraints();

        // const r1cs_constraint_system<FieldT> constraint_system = pb.get_constraint_system();

        // r1cs_constraint_system<FieldT> constraint_system;
        // loadFromFile(r1csPath, mpb.constraint_system);

        printf("\n"); libff::print_indent(); libff::print_mem("after load"); libff::print_time("after load");

        // r1cs_ppzksnark_keypair<BaseT> keypair = r1cs_ppzksnark_generator<BaseT>(constraint_system);

        // saveToFile(pkPath, keypair.pk);
        // saveToFile(vkPath, keypair.vk);

        // printf("\n"); libff::print_indent(); libff::print_mem("after constraints"); libff::print_time("after constraints");
    }

    void generate_r1cs_constraints(
        const std::string& r1csPath,
        const std::string& pkPath,
        const std::string& vkPath)
    {
        libff::print_header("Gunero constraints");

        path_var.generate_r1cs_constraints();
        ml.generate_r1cs_constraints();

        const r1cs_constraint_system<FieldT> constraint_system = this->pb.get_constraint_system();

        saveToFile(r1csPath, constraint_system);

        printf("\n"); libff::print_indent(); libff::print_mem("after generator"); libff::print_time("after generator");

        r1cs_ppzksnark_keypair<BaseT> keypair = r1cs_ppzksnark_generator<BaseT>(constraint_system);

        saveToFile(pkPath, keypair.pk);
        saveToFile(vkPath, keypair.vk);

        printf("\n"); libff::print_indent(); libff::print_mem("after constraints"); libff::print_time("after constraints");
    }

    // static r1cs_primary_input<FieldT> witness_map(
    //     const uint256& rt,
    //     const uint256& h_sig,
    //     const uint256& macs,
    //     const uint256& nullifiers,
    //     const uint256& commitments,
    //     uint64_t vpub_old,
    //     uint64_t vpub_new
    // ) {
    //     std::vector<bool> verify_inputs;

    //     insert_uint256(verify_inputs, rt);
    //     insert_uint256(verify_inputs, h_sig);
        
    //     // for (size_t i = 0; i < NumInputs; i++) {
    //         insert_uint256(verify_inputs, nullifiers);
    //         insert_uint256(verify_inputs, macs);
    //     // }

    //     // for (size_t i = 0; i < NumOutputs; i++) {
    //         insert_uint256(verify_inputs, commitments);
    //     // }

    //     insert_uint64(verify_inputs, vpub_old);
    //     insert_uint64(verify_inputs, vpub_new);

    //     assert(verify_inputs.size() == verifying_input_bit_size());
    //     auto verify_field_elements = libff::pack_bit_vector_into_field_element_vector<FieldT>(verify_inputs);
    //     assert(verify_field_elements.size() == verifying_field_element_size());
    //     return verify_field_elements;
    // }

    void generate_r1cs_witness(
        const size_t address,
        const libff::bit_vector& address_bits,
        const libff::bit_vector& leaf,
        const std::vector<merkle_authentication_node>& path
    )
    {
        address_bits_va.fill_with_bits(this->pb, address_bits);
        assert(address_bits_va.get_field_element_from_bits(this->pb).as_ulong() == address);
        leaf_digest.generate_r1cs_witness(leaf);
        path_var.generate_r1cs_witness(address, path);
        ml.generate_r1cs_witness();
    }

    void verify(
        const libff::bit_vector& address_bits,
        const libff::bit_vector& leaf,
        const libff::bit_vector& root,
        const std::string& vkPath
    )
    {
        libff::print_header("Gunero verify");

        r1cs_ppzksnark_verification_key<BaseT> vk;
        loadFromFile(vkPath, vk);

        r1cs_ppzksnark_processed_verification_key<BaseT> vk_precomp = r1cs_ppzksnark_verifier_process_vk(vk);

        /* make sure that read checker didn't accidentally overwrite anything */
        address_bits_va.fill_with_bits(this->pb, address_bits);
        leaf_digest.generate_r1cs_witness(leaf);
        root_digest.generate_r1cs_witness(root);
        assert(this->pb.is_satisfied());

        const size_t num_constraints = this->pb.num_constraints();
        const size_t expected_constraints = merkle_tree_check_read_gadget<FieldT, HashT>::expected_constraints(tree_depth);
        assert(num_constraints == expected_constraints);
        printf("\n"); libff::print_indent(); libff::print_mem("after verify"); libff::print_time("after verify");
    }

};

std::string strprintf(const char *fromat, ...)
{
    std::string s;
    s.resize(128); // best guess
    char *buff = const_cast<char *>(s.data());

    va_list arglist;
    va_start(arglist, fromat);
    auto len = vsnprintf(buff, 128, fromat, arglist);
    va_end(arglist);

    if (len > 127)
    {
        va_start(arglist, fromat);
        s.resize(len + 1); // leave room for null terminator
        buff = const_cast<char *>(s.data());
        len = vsnprintf(buff, len+1, fromat, arglist);
        va_end(arglist);
    }
    s.resize(len);
    return s; // move semantics FTW
}

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

template<typename FieldT, typename BaseT, typename HashT, size_t tree_depth>
void Gunero_test_merkle_tree_check_read_gadget()
{
    libff::start_profiling();
    //const size_t digest_len = HashT::get_digest_len();

    std::string r1csPath = "r1cs.bin";
    std::string vkPath = "vk.bin";
    std::string pkPath = "pk.bin";

    /* generate circuit */
    libff::print_header("Gunero Generator");

    guneromembership_gadget<FieldT, BaseT, HashT, tree_depth> gunero;

    //protoboard<FieldT> pb;
    // pb_variable_array<FieldT> address_bits_va;
    // address_bits_va.allocate(pb, tree_depth, "address_bits");
    // digest_variable<FieldT> leaf_digest(pb, digest_len, "input_block");
    // digest_variable<FieldT> root_digest(pb, digest_len, "output_digest");
    // merkle_authentication_path_variable<FieldT, HashT> path_var(pb, tree_depth, "path_var");
    // merkle_tree_check_read_gadget<FieldT, HashT> ml(pb, tree_depth, address_bits_va, leaf_digest, root_digest, path_var, ONE, "ml");

    // path_var.generate_r1cs_constraints();
    // ml.generate_r1cs_constraints();

    // {/* produce constraints */
    //     libff::print_header("Gunero constraints");
    //     const r1cs_constraint_system<FieldT> constraint_system = pb.get_constraint_system();

    //     saveToFile(r1csPath, constraint_system);

    //     r1cs_ppzksnark_keypair<BaseT> keypair = r1cs_ppzksnark_generator<BaseT>(constraint_system);

    //     saveToFile(vkPath, keypair.vk);
    //     saveToFile(pkPath, keypair.pk);

    //     printf("\n"); libff::print_indent(); libff::print_mem("after constraints"); libff::print_time("after constraints");
    // }

    gunero.generate_r1cs_constraints(r1csPath, pkPath, vkPath);

    /* prepare test variables */
    libff::print_header("Gunero prepare test variables");
    std::vector<merkle_authentication_node> path(tree_depth);

    libff::bit_vector prev_hash(gunero.digest_len);
    std::generate(prev_hash.begin(), prev_hash.end(), [&]() { return std::rand() % 2; });
    libff::bit_vector leaf = prev_hash;

    libff::bit_vector address_bits;

    size_t address = 0;
    for (long level = tree_depth-1; level >= 0; --level)
    {
        const bool computed_is_right = (std::rand() % 2);
        address |= (computed_is_right ? 1ul << (tree_depth-1-level) : 0);
        address_bits.push_back(computed_is_right);
        libff::bit_vector other(gunero.digest_len);
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
    // libff::print_header("Gunero witness (proof)");
    // gunero.address_bits_va.fill_with_bits(gunero.pb, address_bits);
    // assert(gunero.address_bits_va.get_field_element_from_bits(gunero.pb).as_ulong() == address);
    // gunero.leaf_digest.generate_r1cs_witness(leaf);
    // gunero.path_var.generate_r1cs_witness(address, path);
    // gunero.ml.generate_r1cs_witness();
    // printf("\n"); libff::print_indent(); libff::print_mem("after witness (proof)"); libff::print_time("after witness (proof)");
    gunero.prove(address, address_bits, leaf, path, pkPath);

    /* verify */
    // libff::print_header("Gunero verify");
    // {
    //     r1cs_ppzksnark_verification_key<BaseT> vk;
    //     loadFromFile(vkPath, vk);

    //     r1cs_ppzksnark_processed_verification_key<BaseT> vk_precomp = r1cs_ppzksnark_verifier_process_vk(vk);
    // }

    // /* make sure that read checker didn't accidentally overwrite anything */
    // address_bits_va.fill_with_bits(pb, address_bits);
    // leaf_digest.generate_r1cs_witness(leaf);
    // root_digest.generate_r1cs_witness(root);
    // assert(pb.is_satisfied());

    // const size_t num_constraints = pb.num_constraints();
    // const size_t expected_constraints = merkle_tree_check_read_gadget<FieldT, HashT>::expected_constraints(tree_depth);
    // assert(num_constraints == expected_constraints);
    // printf("\n"); libff::print_indent(); libff::print_mem("after verify"); libff::print_time("after verify");
    gunero.verify(address_bits, leaf, root, vkPath);

    libff::clear_profiling_counters();
}

const unsigned char G1_PREFIX_MASK = 0x02;
const unsigned char G2_PREFIX_MASK = 0x0a;

// Element in the base field
class Fq {
private:
    base_blob<256> data;
public:
    Fq() : data() { }

    template<typename libsnark_Fq>
    Fq(libsnark_Fq element);

    template<typename libsnark_Fq>
    libsnark_Fq to_libsnark_fq() const;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(data);
    }

    friend bool operator==(const Fq& a, const Fq& b)
    {
        return (
            a.data == b.data
        );
    }

    friend bool operator!=(const Fq& a, const Fq& b)
    {
        return !(a == b);
    }
};

// Element in the extension field
class Fq2 {
private:
    base_blob<512> data;
public:
    Fq2() : data() { }

    template<typename libsnark_Fq2>
    Fq2(libsnark_Fq2 element);

    template<typename libsnark_Fq2>
    libsnark_Fq2 to_libsnark_fq2() const;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(data);
    }

    friend bool operator==(const Fq2& a, const Fq2& b)
    {
        return (
            a.data == b.data
        );
    }

    friend bool operator!=(const Fq2& a, const Fq2& b)
    {
        return !(a == b);
    }
};

// Compressed point in G1
class CompressedG1 {
private:
    bool y_lsb;
    Fq x;

public:
    CompressedG1() : y_lsb(false), x() { }

    template<typename libsnark_G1>
    CompressedG1(libsnark_G1 point);

    template<typename libsnark_G1>
    libsnark_G1 to_libsnark_g1() const;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        unsigned char leadingByte = G1_PREFIX_MASK;

        if (y_lsb) {
            leadingByte |= 1;
        }

        READWRITE(leadingByte);

        if ((leadingByte & (~1)) != G1_PREFIX_MASK) {
            throw std::ios_base::failure("lead byte of G1 point not recognized");
        }

        y_lsb = leadingByte & 1;

        READWRITE(x);
    }

    friend bool operator==(const CompressedG1& a, const CompressedG1& b)
    {
        return (
            a.y_lsb == b.y_lsb &&
            a.x == b.x
        );
    }

    friend bool operator!=(const CompressedG1& a, const CompressedG1& b)
    {
        return !(a == b);
    }
};

template<typename libsnark_G1>
CompressedG1::CompressedG1(libsnark_G1 point)
{
    if (point.is_zero()) {
        throw std::domain_error("curve point is zero");
    }

    point.to_affine_coordinates();

    x = Fq(point.X);
    y_lsb = point.Y.as_bigint().data[0] & 1;
}

// Compressed point in G2
class CompressedG2 {
private:
    bool y_gt;
    Fq2 x;

public:
    CompressedG2() : y_gt(false), x() { }

    template<typename libsnark_G2>
    CompressedG2(libsnark_G2 point);

    template<typename libsnark_G2>
    libsnark_G2 to_libsnark_g2() const;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        unsigned char leadingByte = G2_PREFIX_MASK;

        if (y_gt) {
            leadingByte |= 1;
        }

        READWRITE(leadingByte);

        if ((leadingByte & (~1)) != G2_PREFIX_MASK) {
            throw std::ios_base::failure("lead byte of G2 point not recognized");
        }

        y_gt = leadingByte & 1;

        READWRITE(x);
    }

    friend bool operator==(const CompressedG2& a, const CompressedG2& b)
    {
        return (
            a.y_gt == b.y_gt &&
            a.x == b.x
        );
    }

    friend bool operator!=(const CompressedG2& a, const CompressedG2& b)
    {
        return !(a == b);
    }
};

typedef libff::alt_bn128_pp curve_pp;
typedef libff::alt_bn128_pp::Fq_type curve_Fq;
typedef libff::alt_bn128_pp::Fqe_type curve_Fq2;

libff::bigint<8> fq2_to_bigint(const curve_Fq2 &e)
{
    auto modq = curve_Fq::field_char();
    auto c0 = e.c0.as_bigint();
    auto c1 = e.c1.as_bigint();

    libff::bigint<8> temp = c1 * modq;
    temp += c0;
    return temp;
}

template<typename libsnark_G2>
CompressedG2::CompressedG2(libsnark_G2 point)
{
    if (point.is_zero()) {
        throw std::domain_error("curve point is zero");
    }

    point.to_affine_coordinates();

    x = Fq2(point.X);
    y_gt = fq2_to_bigint(point.Y) > fq2_to_bigint(-(point.Y));
}


// Compressed zkSNARK proof
class ZCProof {
private:
    CompressedG1 g_A;
    CompressedG1 g_A_prime;
    CompressedG2 g_B;
    CompressedG1 g_B_prime;
    CompressedG1 g_C;
    CompressedG1 g_C_prime;
    CompressedG1 g_K;
    CompressedG1 g_H;

public:
    ZCProof() : g_A(), g_A_prime(), g_B(), g_B_prime(), g_C(), g_C_prime(), g_K(), g_H() { }

    // Produces a compressed proof using a libsnark zkSNARK proof
    template<typename libsnark_proof>
    ZCProof(const libsnark_proof& proof);

    // Produces a libsnark zkSNARK proof out of this proof,
    // or throws an exception if it is invalid.
    template<typename libsnark_proof>
    libsnark_proof to_libsnark_proof() const;

    static ZCProof random_invalid();

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(g_A);
        READWRITE(g_A_prime);
        READWRITE(g_B);
        READWRITE(g_B_prime);
        READWRITE(g_C);
        READWRITE(g_C_prime);
        READWRITE(g_K);
        READWRITE(g_H);
    }

    friend bool operator==(const ZCProof& a, const ZCProof& b)
    {
        return (
            a.g_A == b.g_A &&
            a.g_A_prime == b.g_A_prime &&
            a.g_B == b.g_B &&
            a.g_B_prime == b.g_B_prime &&
            a.g_C == b.g_C &&
            a.g_C_prime == b.g_C_prime &&
            a.g_K == b.g_K &&
            a.g_H == b.g_H
        );
    }

    friend bool operator!=(const ZCProof& a, const ZCProof& b)
    {
        return !(a == b);
    }
};

template<typename libsnark_proof>
ZCProof::ZCProof(const libsnark_proof& proof)
{
    g_A = CompressedG1(proof.g_A.g);
    g_A_prime = CompressedG1(proof.g_A.h);
    g_B = CompressedG2(proof.g_B.g);
    g_B_prime = CompressedG1(proof.g_B.h);
    g_C = CompressedG1(proof.g_C.g);
    g_C_prime = CompressedG1(proof.g_C.h);
    g_K = CompressedG1(proof.g_K);
    g_H = CompressedG1(proof.g_H);
}

class ProofVerifier {
private:
    bool perform_verification;

    ProofVerifier(bool perform_verification) : perform_verification(perform_verification) { }

public:
    // ProofVerifier should never be copied
    ProofVerifier(const ProofVerifier&) = delete;
    ProofVerifier& operator=(const ProofVerifier&) = delete;
    ProofVerifier(ProofVerifier&&);
    ProofVerifier& operator=(ProofVerifier&&);

    // Creates a verification context that strictly verifies
    // all proofs using libsnark's API.
    static ProofVerifier Strict();

    // Creates a verification context that performs no
    // verification, used when avoiding duplicate effort
    // such as during reindexing.
    static ProofVerifier Disabled();

    template <typename VerificationKey,
              typename ProcessedVerificationKey,
              typename PrimaryInput,
              typename Proof
              >
    bool check(
        const VerificationKey& vk,
        const ProcessedVerificationKey& pvk,
        const PrimaryInput& pi,
        const Proof& p
    );
};

class ViewingKey : public uint256 {
public:
    ViewingKey(uint256 sk_enc) : uint256(sk_enc) { }

    uint256 pk_enc();
};

const size_t SerializedPaymentAddressSize = 64;
const size_t SerializedSpendingKeySize = 32;

class PaymentAddress {
public:
    uint256 a_pk;
    uint256 pk_enc;

    PaymentAddress() : a_pk(), pk_enc() { }
    PaymentAddress(uint256 a_pk, uint256 pk_enc) : a_pk(a_pk), pk_enc(pk_enc) { }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(a_pk);
        READWRITE(pk_enc);
    }

    //! Get the 256-bit SHA256d hash of this payment address.
    uint256 GetHash() const;

    friend inline bool operator==(const PaymentAddress& a, const PaymentAddress& b) {
        return a.a_pk == b.a_pk && a.pk_enc == b.pk_enc;
    }
    friend inline bool operator<(const PaymentAddress& a, const PaymentAddress& b) {
        return (a.a_pk < b.a_pk ||
                (a.a_pk == b.a_pk && a.pk_enc < b.pk_enc));
    }
};

class SpendingKey : public uint252 {
public:
    SpendingKey() : uint252() { }
    SpendingKey(uint252 a_sk) : uint252(a_sk) { }

    static SpendingKey random();

    ViewingKey viewing_key() const;
    PaymentAddress address() const;
};

class Note {
public:
    uint256 a_pk;
    uint64_t value;
    uint256 rho;
    uint256 r;

    Note(uint256 a_pk, uint64_t value, uint256 rho, uint256 r)
        : a_pk(a_pk), value(value), rho(rho), r(r) {}

    Note();

    uint256 cm() const;
    uint256 nullifier(const SpendingKey& a_sk) const;
};

class JSInput {
public:
    Note note;
    SpendingKey key;

    JSInput();
    JSInput(Note note,
            SpendingKey key) : note(note), key(key) { }

    uint256 nullifier() const {
        return note.nullifier(key);
    }
};

class JSOutput {
public:
    PaymentAddress addr;
    uint64_t value;
    boost::array<unsigned char, ZC_MEMO_SIZE> memo = {{0xF6}};  // 0xF6 is invalid UTF8 as per spec, rest of array is 0x00

    JSOutput();
    JSOutput(PaymentAddress addr, uint64_t value) : addr(addr), value(value) { }

    Note note(const uint252& phi, const uint256& r, size_t i, const uint256& h_sig) const;
};

Note JSOutput::note(const uint252& phi, const uint256& r, size_t i, const uint256& h_sig) const {
    uint256 rho = PRF_rho(phi, i, h_sig);

    return Note(addr.a_pk, value, rho, r);
}

class NotePlaintext {
public:
    uint64_t value = 0;
    uint256 rho;
    uint256 r;
    boost::array<unsigned char, ZC_MEMO_SIZE> memo;

    NotePlaintext() {}

    NotePlaintext(const Note& note, boost::array<unsigned char, ZC_MEMO_SIZE> memo);

    Note note(const PaymentAddress& addr) const;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        unsigned char leadingByte = 0x00;
        READWRITE(leadingByte);

        if (leadingByte != 0x00) {
            throw std::ios_base::failure("lead byte of NotePlaintext is not recognized");
        }

        READWRITE(value);
        READWRITE(rho);
        READWRITE(r);
        READWRITE(memo);
    }

    static NotePlaintext decrypt(const ZCNoteDecryption& decryptor,
                                 const ZCNoteDecryption::Ciphertext& ciphertext,
                                 const uint256& ephemeralKey,
                                 const uint256& h_sig,
                                 unsigned char nonce
                                );

    ZCNoteEncryption::Ciphertext encrypt(ZCNoteEncryption& encryptor,
                                         const uint256& pk_enc
                                        ) const;
};

uint256 PRF(bool a, bool b, bool c, bool d,
            const uint252& x,
            const uint256& y)
{
    uint256 res;
    unsigned char blob[64];

    memcpy(&blob[0], x.begin(), 32);
    memcpy(&blob[32], y.begin(), 32);

    blob[0] &= 0x0F;
    blob[0] |= (a ? 1 << 7 : 0) | (b ? 1 << 6 : 0) | (c ? 1 << 5 : 0) | (d ? 1 << 4 : 0);

    CSHA256 hasher;
    hasher.Write(blob, 64);
    hasher.FinalizeNoPadding(res.begin());

    return res;
}

uint256 PRF_addr(const uint252& a_sk, unsigned char t)
{
    uint256 y;
    *(y.begin()) = t;

    return PRF(1, 1, 0, 0, a_sk, y);
}

uint256 PRF_addr_a_pk(const uint252& a_sk)
{
    return PRF_addr(a_sk, 0);
}

uint256 PRF_addr_sk_enc(const uint252& a_sk)
{
    return PRF_addr(a_sk, 1);
}

uint256 PRF_nf(const uint252& a_sk, const uint256& rho)
{
    return PRF(1, 1, 1, 0, a_sk, rho);
}

uint256 PRF_pk(const uint252& a_sk, size_t i0, const uint256& h_sig)
{
    if ((i0 != 0) && (i0 != 1)) {
        throw std::domain_error("PRF_pk invoked with index out of bounds");
    }

    return PRF(0, i0, 0, 0, a_sk, h_sig);
}

uint256 PRF_rho(const uint252& phi, size_t i0, const uint256& h_sig)
{
    if ((i0 != 0) && (i0 != 1)) {
        throw std::domain_error("PRF_rho invoked with index out of bounds");
    }

    return PRF(0, i0, 1, 0, phi, h_sig);
}

template<typename FieldT, typename BaseT, typename HashT, size_t tree_depth>
class GuneroMembershipCircuit
{
public:
    // r1cs_ppzksnark_proving_key<BaseT> pk;
    // r1cs_ppzksnark_verification_key<BaseT> vk;
    // r1cs_ppzksnark_processed_verification_key<BaseT> vk_precomp;
    // std::string pkPath;
    const size_t digest_len;

    GuneroMembershipCircuit()
        : digest_len(HashT::get_digest_len())
    {}
    ~GuneroMembershipCircuit() {}

    // void setProvingKeyPath(std::string path) {
    //     pkPath = path;
    // }

    // void loadProvingKey() {
    //     if (!pk) {
    //         loadFromFile(pkPath, pk);
    //     }
    // }

    // void saveProvingKey(std::string path) {
    //     if (pk) {
    //         saveToFile(path, pk);
    //     } else {
    //         throw std::runtime_error("cannot save proving key; key doesn't exist");
    //     }
    // }
    // void loadVerifyingKey(std::string path) {
    //     loadFromFile(path, vk);

    //     processVerifyingKey();
    // }
    // void processVerifyingKey() {
    //     vk_precomp = r1cs_ppzksnark_verifier_process_vk(*vk);
    // }
    // void saveVerifyingKey(std::string path) {
    //     if (vk) {
    //         saveToFile(path, *vk);
    //     } else {
    //         throw std::runtime_error("cannot save verifying key; key doesn't exist");
    //     }
    // }
    // void saveR1CS(std::string path) {
    //     auto r1cs = generate_r1cs();

    //     saveToFile(path, r1cs);
    // }

    // r1cs_constraint_system<FieldT> generate_r1cs() {
    //     protoboard<FieldT> pb;

    //     guneromembership_gadget<FieldT, BaseT, HashT, tree_depth> g(pb);
    //     g.generate_r1cs_constraints();

    //     return pb.get_constraint_system();
    // }

    void generate(
        const std::string& r1csPath,
        const std::string& pkPath,
        const std::string& vkPath
    ) {
        // const r1cs_constraint_system<FieldT> constraint_system = generate_r1cs();
        // r1cs_ppzksnark_keypair<BaseT> keypair = r1cs_ppzksnark_generator<BaseT>(constraint_system);

        // pk = keypair.pk;
        // vk = keypair.vk;
        // processVerifyingKey();

        protoboard<FieldT> pb;
        guneromembership_gadget<FieldT, BaseT, HashT, tree_depth> gunero(pb);

        gunero.generate_r1cs_constraints(r1csPath, pkPath, vkPath);
    }

    void makeTestVariables(
        size_t& address,
        libff::bit_vector& address_bits,
        libff::bit_vector& leaf,
        std::vector<merkle_authentication_node>& path
    )
    {
        /* prepare test variables */
        libff::print_header("Gunero prepare test variables");
        // std::vector<merkle_authentication_node> path(tree_depth);
        path = std::vector<merkle_authentication_node>(tree_depth);

        libff::bit_vector prev_hash(digest_len);
        std::generate(prev_hash.begin(), prev_hash.end(), [&]() { return std::rand() % 2; });
        // libff::bit_vector leaf = prev_hash;
        leaf = prev_hash;

        // libff::bit_vector address_bits;

        // size_t address = 0;
        address = 0;
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
    }

    ZCProof prove(
        const size_t address,
        const libff::bit_vector& address_bits,
        const libff::bit_vector& leaf,
        const std::vector<merkle_authentication_node>& path,
        const std::string& pkPath


        
        // Note& out_notes,
        // ZCNoteEncryption::Ciphertext& out_ciphertexts,
        // uint256& out_ephemeralKey,
        // const uint256& pubKeyHash,
        // uint256& out_randomSeed,
        // uint256& out_macs,
        // uint256& out_nullifiers,
        // uint256& out_commitments,
        // uint64_t vpub_old,
        // uint64_t vpub_new,
        // const uint256& rt
    ) {
        libff::print_header("Gunero witness (proof)");

        r1cs_ppzksnark_proving_key<BaseT> pk;
        loadFromFile(pkPath, pk);

        protoboard<FieldT> pb;
        {
            guneromembership_gadget<FieldT, BaseT, HashT, tree_depth> g(pb);
            g.load_r1cs_constraints();
            g.generate_r1cs_witness(
                address,
                address_bits,
                leaf,
                path
            );
        }

        // The constraint system must be satisfied or there is an unimplemented
        // or incorrect sanity check above. Or the constraint system is broken!
        assert(pb.is_satisfied());

        // TODO: These are copies, which is not strictly necessary.
        auto primary_input = pb.primary_input();
        auto aux_input = pb.auxiliary_input();

        // Swap A and B if it's beneficial (less arithmetic in G2)
        // In our circuit, we already know that it's beneficial
        // to swap, but it takes so little time to perform this
        // estimate that it doesn't matter if we check every time.
        // pb.constraint_system.swap_AB_if_beneficial();

        printf("\n"); libff::print_indent(); libff::print_mem("after witness (proof)"); libff::print_time("after witness (proof)");

        return ZCProof(r1cs_ppzksnark_prover<BaseT>(
            pk,
            primary_input,
            aux_input
            // ,
            // pb.constraint_system
        ));
    }

    bool verify(
        // const ZCProof& proof,
        // ProofVerifier& verifier,
        // const uint256& pubKeyHash,
        // const uint256& randomSeed,
        // const uint256& macs,
        // const uint256& nullifiers,
        // const uint256& commitments,
        // uint64_t vpub_old,
        // uint64_t vpub_new,
        // const uint256& rt
    ) {
        // if (!vk || !vk_precomp) {
        //     throw std::runtime_error("JoinSplit verifying key not loaded");
        // }

        // try {
        //     auto r1cs_proof = proof.to_libsnark_proof<r1cs_ppzksnark_proof<BaseT>>();

        //     uint256 h_sig = this->h_sig(randomSeed, nullifiers, pubKeyHash);

        //     auto witness = guneromembership_gadget<FieldT, BaseT, HashT, tree_depth>::witness_map(
        //         rt,
        //         h_sig,
        //         macs,
        //         nullifiers,
        //         commitments,
        //         vpub_old,
        //         vpub_new
        //     );

        //     return verifier.check(
        //         *vk,
        //         *vk_precomp,
        //         witness,
        //         r1cs_proof
        //     );
        // } catch (...) {
        //     return false;
        // }

        return false;
    }
};

int main () {
    libff::start_profiling();

    // //bn128_pp
    // libff::bn128_pp::init_public_params();

    //alt_bn128_pp
    libff::init_alt_bn128_params();

    // typedef libff::Fr<libff::bn128_pp> FieldT;
    // typedef libff::bn128_pp BaseT;
    typedef libff::Fr<libff::alt_bn128_pp> FieldT;
    typedef libff::alt_bn128_pp BaseT;
    // Gunero_test_merkle_tree_check_read_gadget<FieldT, BaseT, sha256_two_to_one_hash_gadget<FieldT>, 64>();

    GuneroMembershipCircuit<FieldT, BaseT, sha256_two_to_one_hash_gadget<FieldT>, 64> gmc;

    std::string r1csPath = "r1cs.bin";
    std::string pkPath = "pk.bin";
    std::string vkPath = "vk.bin";

    /* generate circuit */
    libff::print_header("Gunero Generator");

    gmc.generate(r1csPath, pkPath, vkPath);

    size_t address;
    libff::bit_vector address_bits;
    libff::bit_vector leaf;
    std::vector<merkle_authentication_node> path;
    gmc.makeTestVariables(address, address_bits, leaf, path);

    gmc.prove(address, address_bits, leaf, path, pkPath);

    return 0;
}
