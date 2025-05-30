// fips205.cpp - Cleaned implementation
#include "fips205.h"
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <stdexcept>
#include <cstring>  //Todo : Revisar

// Thread-local optimization variables
namespace {
    thread_local EVP_MD_CTX* g_quick_shake_ctx = nullptr;
    thread_local bool g_quick_ctx_initialized = false;
}

// Context cleanup function
void cleanup_quick_shake_context() {
    if (g_quick_shake_ctx) {
        EVP_MD_CTX_free(g_quick_shake_ctx);
        g_quick_shake_ctx = nullptr;
        g_quick_ctx_initialized = false;
    }
}

// Asegura la inicializacion del contexto
bool ensure_quick_context_initialized() {

    // Verifica si el contexto ya esta inicializado
    if (!g_quick_ctx_initialized) {

        // Si no, libera el contexto anterior si existe
        if (g_quick_shake_ctx) {
            EVP_MD_CTX_free(g_quick_shake_ctx);
        }
        // Crea un nuevo contexto de digestión
        g_quick_shake_ctx = EVP_MD_CTX_new();
        g_quick_ctx_initialized = (g_quick_shake_ctx != nullptr);

        // Si no se pudo crear el contexto, lanza una excepción
        static bool cleanup_registered = false;
        if (!cleanup_registered) {
            // Cuando el programa termine se ejecutara limpiando el contexto
            std::atexit(cleanup_quick_shake_context);
            cleanup_registered = true;
        }
    }
    return g_quick_ctx_initialized && g_quick_shake_ctx;
}

// Fast SHAKEd256 computation with context reuse
bool computeShake_quick(const ByteVector& input, ByteVector& output, size_t outputLen) {
    if (!ensure_quick_context_initialized()) {
        return computeShake(input, output, outputLen);
    }

    output.resize(outputLen);

    if (!EVP_DigestInit_ex(g_quick_shake_ctx, EVP_shake256(), nullptr) ||
        !EVP_DigestUpdate(g_quick_shake_ctx, input.data(), input.size()) ||
        !EVP_DigestFinalXOF(g_quick_shake_ctx, output.data(), outputLen)) {
        return false;
    }

    return true;
}

// Fast concatenate and hash with context reuse
bool concatenateAndHash_quick(const std::vector<ByteVector>& inputs, ByteVector& output, size_t outputLen) {
    if (!ensure_quick_context_initialized()) {
        return concatenateAndHash(inputs, output, outputLen);
    }

    output.resize(outputLen);

    if (!EVP_DigestInit_ex(g_quick_shake_ctx, EVP_shake256(), nullptr)) {
        return false;
    }

    for (const auto& input : inputs) {
        if (!input.empty() && !EVP_DigestUpdate(g_quick_shake_ctx, input.data(), input.size())) {
            return false;
        }
    }

    return EVP_DigestFinalXOF(g_quick_shake_ctx, output.data(), outputLen);
}

// Static member initialization
SLH_DSA_ParamSet FIPS205ConfigManager::current_schema = SLH_DSA_ParamSet::SLH_DSA_SHAKE_256s;
const SLH_DSA_Params* FIPS205ConfigManager::current_params = nullptr;
std::mutex FIPS205ConfigManager::config_mutex;
bool FIPS205ConfigManager::is_initialized = false;

// Parameter table
const SLH_DSA_Params PARAMS[static_cast<size_t>(SLH_DSA_ParamSet::PARAM_COUNT)] = {
        {"SLH-DSA-SHA2-128s",   16, 63,  7,  9, 12, 14, 4, 30, 1, 32,  7856,  false},
        {"SLH-DSA-SHAKE-128s",  16, 63,  7,  9, 12, 14, 4, 30, 1, 32,  7856,  true },
        {"SLH-DSA-SHA2-128f",   16, 66, 22,  3,  6, 33, 4, 34, 1, 32, 17088,  false},
        {"SLH-DSA-SHAKE-128f",  16, 66, 22,  3,  6, 33, 4, 34, 1, 32, 17088,  true },
        //No se puede ya que OpenSSL no soporta SHAKE192
        {"SLH-DSA-SHA2-192s",   24, 63,  7,  9, 14, 17, 4, 39, 3, 48, 16224,  false},
        {"SLH-DSA-SHAKE-192s",  24, 63,  7,  9, 14, 17, 4, 39, 3, 48, 16224,  true },
        {"SLH-DSA-SHA2-192f",   24, 66, 22,  3,  8, 33, 4, 42, 3, 48, 35664,  false},
        {"SLH-DSA-SHAKE-192f",  24, 66, 22,  3,  8, 33, 4, 42, 3, 48, 35664,  true },

        {"SLH-DSA-SHA2-256s",   32, 64,  8,  8, 14, 22, 4, 47, 5, 64, 29792,  false},
        {"SLH-DSA-SHAKE-256s",  32, 64,  8,  8, 14, 22, 4, 47, 5, 64, 29792,  true },
        {"SLH-DSA-SHA2-256f",   32, 68, 17,  4,  9, 35, 4, 49, 5, 64, 49856,  false},
        {"SLH-DSA-SHAKE-256f",  32, 68, 17,  4,  9, 35, 4, 49, 5, 64, 49856,  true }
};

const SLH_DSA_Params* get_params(SLH_DSA_ParamSet set) {
    auto index = static_cast<size_t>(set);
    if (index >= static_cast<size_t>(SLH_DSA_ParamSet::PARAM_COUNT)) {
        return nullptr;
    }
    return &PARAMS[index];
}

// Public Key methods
ByteVector SLH_DSA_PublicKey::toBytes() const {
    ByteVector result;
    result.reserve(seed.size() + root.size());
    result.insert(result.end(), seed.begin(), seed.end());
    result.insert(result.end(), root.begin(), root.end());
    return result;
}

SLH_DSA_PublicKey SLH_DSA_PublicKey::fromBytes(const ByteVector& data) {
    const SLH_DSA_Params* params = FIPS205ConfigManager::getCurrentParams();
    if (!params) {
        throw std::runtime_error("SLH_DSA_Params not initialized. Call FIPS205ConfigManager::initialize() first.");
    }

    const size_t n = params->n;
    const size_t expected_size = 2 * n;

    if (data.size() != expected_size) {
        throw std::invalid_argument("Invalid public key size. Expected " +
                                    std::to_string(expected_size) + " bytes, got " +
                                    std::to_string(data.size()) + " bytes");
    }

    SLH_DSA_PublicKey pk;
    pk.seed = ByteVector(data.begin(), data.begin() + n);
    pk.root = ByteVector(data.begin() + n, data.begin() + 2 * n);
    return pk;
}

// Private Key methods
ByteVector SLH_DSA_PrivateKey::toBytes() const {
    ByteVector result;
    result.reserve(seed.size() + prf.size() + pkSeed.size() + pkRoot.size());
    result.insert(result.end(), seed.begin(), seed.end());
    result.insert(result.end(), prf.begin(), prf.end());
    result.insert(result.end(), pkSeed.begin(), pkSeed.end());
    result.insert(result.end(), pkRoot.begin(), pkRoot.end());
    return result;
}

SLH_DSA_PrivateKey SLH_DSA_PrivateKey::fromBytes(const ByteVector& data) {
    const SLH_DSA_Params* params = FIPS205ConfigManager::getCurrentParams();
    if (!params) {
        throw std::runtime_error("SLH_DSA_Params not initialized. Call FIPS205ConfigManager::initialize() first.");
    }

    const size_t n = params->n;
    const size_t expected_size = 4 * n;

    if (data.size() != expected_size) {
        throw std::invalid_argument("Invalid private key size. Expected " +
                                    std::to_string(expected_size) + " bytes, got " +
                                    std::to_string(data.size()) + " bytes");
    }

    SLH_DSA_PrivateKey sk;
    sk.seed = ByteVector(data.begin(), data.begin() + n);
    sk.prf = ByteVector(data.begin() + n, data.begin() + 2 * n);
    sk.pkSeed = ByteVector(data.begin() + 2 * n, data.begin() + 3 * n);
    sk.pkRoot = ByteVector(data.begin() + 3 * n, data.begin() + 4 * n);
    return sk;
}

SLH_DSA_PublicKey SLH_DSA_PrivateKey::getPublicKey() const {
    SLH_DSA_PublicKey pk;
    pk.seed = pkSeed;
    pk.root = pkRoot;
    return pk;
}

// Signature methods
ByteVector SLH_DSA_Signature::toBytes() const {
    ByteVector result;
    result.reserve(randomness.size() + forsSignature.size() + htSignature.size());
    result.insert(result.end(), randomness.begin(), randomness.end());
    result.insert(result.end(), forsSignature.begin(), forsSignature.end());
    result.insert(result.end(), htSignature.begin(), htSignature.end());
    return result;
}

SLH_DSA_Signature SLH_DSA_Signature::fromBytes(const ByteVector& data) {
    const SLH_DSA_Params* params = FIPS205ConfigManager::getCurrentParams();
    if (!params) {
        throw std::runtime_error("SLH_DSA_Params not initialized. Call FIPS205ConfigManager::initialize() first.");
    }

    const size_t n = params->n;
    const uint32_t k = params->k;
    const uint32_t a = params->a;
    const uint32_t h = params->h;
    const uint32_t d = params->d;
    const uint32_t lg_w = params->lg_w;

    const size_t len1 = (8 * n + lg_w - 1) / lg_w;
    const size_t len2 = gen_len2(n, lg_w);
    const size_t len = len1 + len2;

    const size_t r_size = n;
    const size_t fors_size = k * (1 + a) * n;
    const size_t ht_size = (h + d * len) * n;
    const size_t expected_total = r_size + fors_size + ht_size;

    if (data.size() != expected_total) {
        throw std::invalid_argument("Invalid signature size. Expected " +
                                    std::to_string(expected_total) + " bytes, got " +
                                    std::to_string(data.size()) + " bytes");
    }

    SLH_DSA_Signature sig;
    sig.randomness = ByteVector(data.begin(), data.begin() + r_size);

    size_t fors_start = r_size;
    sig.forsSignature = ByteVector(data.begin() + fors_start,
                                   data.begin() + fors_start + fors_size);

    size_t ht_start = fors_start + fors_size;
    sig.htSignature = ByteVector(data.begin() + ht_start, data.end());

    return sig;
}

// SHAKE256 computation
bool computeShake(const ByteVector& input, ByteVector& output, size_t outputLen) {
    // Determine SHAKE variant based on security level
    const SLH_DSA_Params* params = FIPS205ConfigManager::getCurrentParams();
    const EVP_MD* shake_variant = EVP_shake256(); // Default fallback

    if (params) {
        if (params->n == 16) {        // Se compara con el n = 16 ya que hay dos versiones que usan Shake 128
            shake_variant = EVP_shake128();
        } else if (params->n == 24) {

            return false; // SHAKE128 is not defined for n = 24
        } else if (params->n == 32) {
            shake_variant = EVP_shake256();
        }
    }

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        return false;
    }

    output.resize(outputLen);
    bool success = EVP_DigestInit_ex(ctx, shake_variant, nullptr) &&
                   EVP_DigestUpdate(ctx, input.data(), input.size()) &&
                   EVP_DigestFinalXOF(ctx, output.data(), outputLen);

    EVP_MD_CTX_free(ctx);
    return success;
}

// Concatenate and hash function
bool concatenateAndHash(const std::vector<ByteVector>& inputs, ByteVector& output, size_t outputLen) {
    size_t totalSize = 0;
    for (const auto& input : inputs) {
        totalSize += input.size();
    }

    ByteVector concatenated;
    concatenated.reserve(totalSize);
    for (const auto& input : inputs) {
        concatenated.insert(concatenated.end(), input.begin(), input.end());
    }

    return computeShake(concatenated, output, outputLen);
}

// Hash function implementations
bool H_msg(const ByteVector& R, const ByteVector& PKseed, const ByteVector& PKroot,
           const ByteVector& M, ByteVector& output) {
    const SLH_DSA_Params* params = FIPS205ConfigManager::getCurrentParams();
    if (!params) {
        throw std::runtime_error("SLH_DSA_Params not initialized.");
    }

    return concatenateAndHash_quick({R, PKseed, PKroot, M}, output, params->m);
}

bool PRF(const ByteVector& PKseed, const ByteVector& SKseed, const ByteVector& ADRS,
         ByteVector& output) {
    const SLH_DSA_Params* params = FIPS205ConfigManager::getCurrentParams();
    if (!params) {
        throw std::runtime_error("SLH_DSA_Params not initialized.");
    }

    return concatenateAndHash_quick({PKseed, ADRS, SKseed}, output, params->n);
}

bool PRF_msg(const ByteVector& SKprf, const ByteVector& opt_rand, const ByteVector& M,
             ByteVector& output) {
    const SLH_DSA_Params* params = FIPS205ConfigManager::getCurrentParams();
    if (!params) {
        throw std::runtime_error("SLH_DSA_Params not initialized.");
    }

    return concatenateAndHash_quick({SKprf, opt_rand, M}, output, params->n);
}

bool F(const ByteVector& PKseed, const ByteVector& ADRS, const ByteVector& M1,
       ByteVector& output) {
    const SLH_DSA_Params* params = FIPS205ConfigManager::getCurrentParams();
    if (!params) {
        throw std::runtime_error("SLH_DSA_Params not initialized.");
    }

    return concatenateAndHash_quick({PKseed, ADRS, M1}, output, params->n);
}

bool H(const ByteVector& PKseed, const ByteVector& ADRS, const ByteVector& M2,
       ByteVector& output) {
    const SLH_DSA_Params* params = FIPS205ConfigManager::getCurrentParams();
    if (!params) {
        throw std::runtime_error("SLH_DSA_Params not initialized.");
    }

    return concatenateAndHash_quick({PKseed, ADRS, M2}, output, params->n);
}

bool T_l(const ByteVector& PKseed, const ByteVector& ADRS, std::vector<ByteVector> Ml,
         ByteVector& output) {
    const SLH_DSA_Params* params = FIPS205ConfigManager::getCurrentParams();
    if (!params) {
        throw std::runtime_error("SLH_DSA_Params not initialized.");
    }

    if (Ml.empty()) {
        return false;
    }

    ByteVector concatenated_Ml;
    for (const auto& vec : Ml) {
        concatenated_Ml.insert(concatenated_Ml.end(), vec.begin(), vec.end());
    }

    return concatenateAndHash_quick({PKseed, ADRS, concatenated_Ml}, output, params->n);
}

// Utility functions
ByteVector uint32ToBytes(uint32_t value) {
    return {
            static_cast<uint8_t>((value >> 24) & 0xFF),
            static_cast<uint8_t>((value >> 16) & 0xFF),
            static_cast<uint8_t>((value >> 8) & 0xFF),
            static_cast<uint8_t>(value & 0xFF)
    };
}

uint32_t bytesToUint32(const ByteVector& bytes, size_t offset) {
    if (bytes.size() < offset + 4) {
        throw std::invalid_argument("Array too small for uint32_t conversion");
    }

    return (static_cast<uint32_t>(bytes[offset]) << 24) |
           (static_cast<uint32_t>(bytes[offset+1]) << 16) |
           (static_cast<uint32_t>(bytes[offset+2]) << 8) |
           static_cast<uint32_t>(bytes[offset+3]);
}

// ADRS implementation
ADRS::ADRS() : addr() {
    addr.fill(0);
}

uint8_t& ADRS::operator[](size_t index) {
    return addr[index];
}

const uint8_t& ADRS::operator[](size_t index) const {
    return addr[index];
}

const uint8_t* ADRS::data() const {
    return addr.data();
}

ByteVector ADRS::toVector() const {
    return {addr.begin(), addr.end()};
}

void ADRS::setLayerAddress(uint32_t layer) {
    ByteVector bytes = uint32ToBytes(layer);
    std::copy(bytes.begin(), bytes.end(), addr.begin());
}

void ADRS::setTreeAddress(const uint8_t tree[12]) {
    std::copy(tree, tree + 12, addr.begin() + 4);
}

void ADRS::setTypeAndClear(uint32_t type) {
    ByteVector bytes = uint32ToBytes(type);
    std::copy(bytes.begin(), bytes.end(), addr.begin() + 16);
    std::fill(addr.begin() + 20, addr.end(), 0);
}

void ADRS::setKeyPairAddress(uint32_t keyPair) {
    ByteVector bytes = uint32ToBytes(keyPair);
    std::copy(bytes.begin(), bytes.end(), addr.begin() + 20);
}

void ADRS::setChainAddress(uint32_t chain) {
    ByteVector bytes = uint32ToBytes(chain);
    std::copy(bytes.begin(), bytes.end(), addr.begin() + 24);
}

void ADRS::setTreeHeight(uint32_t height) {
    ByteVector bytes = uint32ToBytes(height);
    std::copy(bytes.begin(), bytes.end(), addr.begin() + 24);
}

void ADRS::setHashAddress(uint32_t hash) {
    ByteVector bytes = uint32ToBytes(hash);
    std::copy(bytes.begin(), bytes.end(), addr.begin() + 28);
}

void ADRS::setTreeIndex(uint32_t index) {
    ByteVector bytes = uint32ToBytes(index);
    std::copy(bytes.begin(), bytes.end(), addr.begin() + 28);
}

uint32_t ADRS::getKeyPairAddress() const {
    return bytesToUint32(ByteVector(addr.begin() + 20, addr.begin() + 24));
}

uint32_t ADRS::getTreeIndex() const {
    return bytesToUint32(ByteVector(addr.begin() + 28, addr.begin() + 32));
}

// Algorithm 1: gen_len2
uint32_t gen_len2(uint64_t n, uint64_t lg_w) {
    uint64_t w = 1ULL << lg_w;
    uint64_t len1 = (8 * n + lg_w - 1) / lg_w;
    uint64_t max_checksum = len1 * (w - 1);
    uint64_t len2 = 1;
    uint64_t capacity = w;

    while (capacity <= max_checksum) {
        len2 += 1;
        capacity *= w;
    }

    return static_cast<uint32_t>(len2);
}

// Algorithm 2: toInt
uint32_t toInt(const ByteVector& X, uint64_t n) {
    if (X.size() < n) {
        throw std::invalid_argument("Input array is too short");
    }

    uint64_t total = 0;
    for (uint64_t i = 0; i < n; ++i) {
        total = 256 * total + static_cast<uint64_t>(X[i]);
    }
    return static_cast<uint32_t>(total);
}

// Algorithm 3: toByte helper function
uint8_t divmod256(ByteVector& num) {
    uint16_t carry = 0;
    for (size_t i = num.size(); i-- > 0;) {
        uint16_t cur = (carry << 8) | num[i];
        num[i] = static_cast<uint8_t>(cur / 256);
        carry = cur % 256;
    }
    return static_cast<uint8_t>(carry);
}

ByteVector toByte(const ByteVector& X, uint64_t n) {
    ByteVector S(n, 0);
    ByteVector total = X;

    for (uint64_t i = 0; i < n; ++i) {
        S[n - 1 - i] = divmod256(total);
    }
    return S;
}

// Algorithm 4: base_2b
std::vector<uint32_t> base_2b(const ByteVector& X, int b, int out_len) {
    if (b <= 0 || b > 31) {
        throw std::invalid_argument("b must be between 1 and 31");
    }

    int required_bytes = (out_len * b + 7) / 8;
    if (static_cast<int>(X.size()) < required_bytes) {
        throw std::invalid_argument("Input byte array X is too short for requested output length");
    }

    std::vector<uint32_t> baseb(out_len);
    size_t in = 0;
    int bits = 0;
    uint32_t total = 0;

    for (int out = 0; out < out_len; out++) {
        while (bits < b) {
            if (in >= X.size()) {
                break;
            }
            total = (total << 8) | X[in];
            in++;
            bits += 8;
        }

        bits -= b;
        baseb[out] = (total >> bits) & ((1U << b) - 1);
        total &= (1U << bits) - 1;
    }

    return baseb;
}

// Algorithm 5: chain
ByteVector chain(ByteVector X, uint32_t i, uint32_t s, const ByteVector& PKseed, ADRS adrs) {
    if (s == 0) {
        return X;
    }

    ByteVector temp = std::move(X);

    for (uint32_t j = i; j < i + s; j++) {
        adrs.setHashAddress(j);
        ByteVector result;
        if (!F(PKseed, adrs.toVector(), temp, result)) {
            throw std::runtime_error("Error in F during chain");
        }
        temp = std::move(result);
    }

    return temp;
}

// Algorithm 6: wots_pkGen
ByteVector wots_pkGen(const ByteVector& SKseed, const ByteVector& PKseed, ADRS adrs) {
    const SLH_DSA_Params* params = FIPS205ConfigManager::getCurrentParams();
    if (!params) {
        throw std::runtime_error("SLH_DSA_Params not initialized.");
    }

    const size_t n = params->n;
    const uint32_t lg_w = params->lg_w;
    const size_t len1 = (8 * n + lg_w - 1) / lg_w;
    const size_t len2 = gen_len2(n, lg_w);
    const size_t len = len1 + len2;
    const uint32_t w = 1 << lg_w;

    ADRS skADRS = adrs;
    skADRS.setTypeAndClear(WOTS_PRF);
    skADRS.setKeyPairAddress(adrs.getKeyPairAddress());

    std::vector<ByteVector> tmp(len);

    for (size_t i = 0; i < len; i++) {
        skADRS.setChainAddress(i);
        ByteVector sk;
        if (!PRF(PKseed, SKseed, skADRS.toVector(), sk)) {
            throw std::runtime_error("Error in PRF during wots_pkGen");
        }

        adrs.setChainAddress(i);
        tmp[i] = chain(sk, 0, w - 1, PKseed, adrs);
    }

    ADRS wotsADRS = adrs;
    wotsADRS.setTypeAndClear(WOTS_PK);
    wotsADRS.setKeyPairAddress(adrs.getKeyPairAddress());

    ByteVector pk(n);
    if (!T_l(PKseed, wotsADRS.toVector(), tmp, pk)) {
        throw std::runtime_error("Error in T_l during wots_pkGen");
    }

    return pk;
}

// Algorithm 7: wots_sign
ByteVector wots_sign(const ByteVector& M, const ByteVector& SKseed, const ByteVector& PKseed, ADRS adrs) {
    const SLH_DSA_Params* params = FIPS205ConfigManager::getCurrentParams();
    if (!params) {
        throw std::runtime_error("SLH_DSA_Params not initialized.");
    }

    const size_t n = params->n;
    const uint32_t w = 1 << params->lg_w;
    const uint32_t lg_w = params->lg_w;
    const size_t len1 = (8 * n + lg_w - 1) / lg_w;
    const size_t len2 = gen_len2(n, lg_w);
    const size_t len = len1 + len2;

    uint32_t csum = 0;
    std::vector<uint32_t> msg_base_w = base_2b(M, lg_w, static_cast<int>(len1));

    for (size_t i = 0; i < len1; i++) {
        csum += w - 1 - msg_base_w[i];
    }

    uint32_t shift_amount = (8 - ((len2 * lg_w) % 8)) % 8;
    csum = (csum << shift_amount) % (1 << (len2 * lg_w));

    ByteVector csum_bytes;
    size_t csum_byte_len = (len2 * lg_w + 7) / 8;
    for (size_t i = csum_byte_len; i > 0; i--) {
        csum_bytes.insert(csum_bytes.begin(), static_cast<uint8_t>(csum & 0xFF));
        csum >>= 8;
    }

    std::vector<uint32_t> csum_base_w = base_2b(csum_bytes, lg_w, len2);
    std::vector<uint32_t> msg_complete(len);

    for (size_t i = 0; i < len1; i++) {
        msg_complete[i] = msg_base_w[i];
    }
    for (size_t i = 0; i < len2; i++) {
        msg_complete[len1 + i] = csum_base_w[i];
    }

    ADRS skADRS = adrs;
    skADRS.setTypeAndClear(WOTS_PRF);
    skADRS.setKeyPairAddress(adrs.getKeyPairAddress());

    ByteVector sig(len * n);

    for (size_t i = 0; i < len; i++) {
        skADRS.setChainAddress(i);
        ByteVector sk;
        if (!PRF(PKseed, SKseed, skADRS.toVector(), sk)) {
            throw std::runtime_error("Error in PRF during wots_sign");
        }

        adrs.setChainAddress(i);
        ByteVector sig_part = chain(sk, 0, msg_complete[i], PKseed, adrs);
        std::copy(sig_part.begin(), sig_part.end(), sig.begin() + i * n);
    }

    return sig;
}

// Algorithm 8: wots_pkFromSig
ByteVector wots_pkFromSig(const ByteVector& sig, const ByteVector& M, const ByteVector& PKseed, ADRS adrs) {
    const SLH_DSA_Params* params = FIPS205ConfigManager::getCurrentParams();
    if (!params) {
        throw std::runtime_error("SLH_DSA_Params not initialized.");
    }

    const size_t n = params->n;
    const uint32_t w = 1 << params->lg_w;
    const uint32_t lg_w = params->lg_w;
    const size_t len1 = (8 * n + lg_w - 1) / lg_w;
    const size_t len2 = gen_len2(n, lg_w);
    const size_t len = len1 + len2;

    if (sig.size() != len * n) {
        throw std::invalid_argument("Incorrect signature size for wots_pkFromSig");
    }

    uint32_t csum = 0;
    std::vector<uint32_t> msg_base_w = base_2b(M, lg_w, len1);

    for (size_t i = 0; i < len1; i++) {
        csum += w - 1 - msg_base_w[i];
    }

    uint32_t shift_amount = (8 - ((len2 * lg_w) % 8)) % 8;
    csum = (csum << shift_amount) % (1 << (len2 * lg_w));

    ByteVector csum_bytes;
    size_t csum_byte_len = (len2 * lg_w + 7) / 8;
    for (int i = csum_byte_len - 1; i >= 0; i--) {
        csum_bytes.insert(csum_bytes.begin(), static_cast<uint8_t>(csum & 0xFF));
        csum >>= 8;
    }

    std::vector<uint32_t> csum_base_w = base_2b(csum_bytes, lg_w, len2);
    std::vector<uint32_t> msg_complete(len);

    for (size_t i = 0; i < len1; i++) {
        msg_complete[i] = msg_base_w[i];
    }
    for (size_t i = 0; i < len2; i++) {
        msg_complete[len1 + i] = csum_base_w[i];
    }

    ADRS pkADRS = adrs;
    std::vector<ByteVector> tmp(len);

    for (size_t i = 0; i < len; i++) {
        ByteVector sig_i(sig.begin() + i * n, sig.begin() + (i + 1) * n);
        pkADRS.setChainAddress(i);
        tmp[i] = chain(sig_i, msg_complete[i], w - 1 - msg_complete[i], PKseed, pkADRS);
    }

    ADRS wotsADRS = adrs;
    wotsADRS.setTypeAndClear(WOTS_PK);
    wotsADRS.setKeyPairAddress(adrs.getKeyPairAddress());

    ByteVector pk(n);
    if (!T_l(PKseed, wotsADRS.toVector(), tmp, pk)) {
        throw std::runtime_error("Error in T_l during wots_pkFromSig");
    }

    return pk;
}

// Algorithm 9: xmss_node
ByteVector xmss_node(const ByteVector& SKseed, uint32_t i, uint32_t z, const ByteVector& PKseed, ADRS adrs) {
    ByteVector node;

    if (z == 0) {
        adrs.setKeyPairAddress(i);
        node = wots_pkGen(SKseed, PKseed, adrs);
    } else {
        ByteVector lnode = xmss_node(SKseed, 2*i, z-1, PKseed, adrs);
        ByteVector rnode = xmss_node(SKseed, 2*i+1, z-1, PKseed, adrs);

        adrs.setTypeAndClear(WOTS_TREES);
        adrs.setTreeHeight(z);
        adrs.setTreeIndex(i);

        ByteVector combined;
        combined.reserve(lnode.size() + rnode.size());
        combined.insert(combined.end(), lnode.begin(), lnode.end());
        combined.insert(combined.end(), rnode.begin(), rnode.end());

        if (!H(PKseed, adrs.toVector(), combined, node)) {
            throw std::runtime_error("Error in H during xmss_node");
        }
    }

    return node;
}

// Algorithm 10: xmss_sign
ByteVector xmss_sign(const ByteVector& M, const ByteVector& SKseed, uint32_t idx,
                     const ByteVector& PKseed, ADRS adrs) {
    const SLH_DSA_Params* params = FIPS205ConfigManager::getCurrentParams();
    if (!params) {
        throw std::runtime_error("SLH_DSA_Params not initialized.");
    }

    const uint32_t h_prima = params->h_prima;

    std::vector<ByteVector> AUTH(h_prima);
    for (uint32_t j = 0; j < h_prima; j++) {
        uint32_t k = (idx >> j) ^ 1;
        AUTH[j] = xmss_node(SKseed, k, j, PKseed, adrs);
    }

    adrs.setTypeAndClear(WOTS_HASH);
    adrs.setKeyPairAddress(idx);

    ByteVector sig = wots_sign(M, SKseed, PKseed, adrs);

    size_t auth_size = 0;
    for (const auto& auth_node : AUTH) {
        auth_size += auth_node.size();
    }

    ByteVector SIG_XMSS;
    SIG_XMSS.reserve(sig.size() + auth_size);
    SIG_XMSS.insert(SIG_XMSS.end(), sig.begin(), sig.end());

    for (const auto& auth_node : AUTH) {
        SIG_XMSS.insert(SIG_XMSS.end(), auth_node.begin(), auth_node.end());
    }

    return SIG_XMSS;
}

// Algorithm 11: xmss_pkFromSig
ByteVector xmss_pkFromSig(uint32_t idx, const ByteVector& SIG_XMSS,
                          const ByteVector& M, const ByteVector& PKseed, ADRS adrs) {
    const SLH_DSA_Params* params = FIPS205ConfigManager::getCurrentParams();
    if (!params) {
        throw std::runtime_error("SLH_DSA_Params not initialized.");
    }

    const size_t n = params->n;
    const uint32_t h_prima = params->h_prima;
    const uint32_t lg_w = params->lg_w;
    const size_t len1 = (8 * n + lg_w - 1) / lg_w;
    const size_t len2 = gen_len2(n, lg_w);
    const size_t len = len1 + len2;
    const size_t wots_sig_size = len * n;

    adrs.setTypeAndClear(WOTS_HASH);
    adrs.setKeyPairAddress(idx);

    ByteVector sig(SIG_XMSS.begin(), SIG_XMSS.begin() + wots_sig_size);

    std::vector<ByteVector> AUTH(h_prima);
    for (uint32_t i = 0; i < h_prima; i++) {
        size_t offset = wots_sig_size + i * n;
        AUTH[i] = ByteVector(SIG_XMSS.begin() + offset, SIG_XMSS.begin() + offset + n);
    }

    std::vector<ByteVector> node(2);
    node[0] = wots_pkFromSig(sig, M, PKseed, adrs);

    adrs.setTypeAndClear(WOTS_TREES);
    adrs.setTreeIndex(idx);

    for (uint32_t k = 0; k < h_prima; k++) {
        adrs.setTreeHeight(k + 1);

        if ((idx >> k) % 2 == 0) {
            adrs.setTreeIndex(adrs.getTreeIndex() / 2);

            ByteVector concatenated;
            concatenated.reserve(node[0].size() + AUTH[k].size());
            concatenated.insert(concatenated.end(), node[0].begin(), node[0].end());
            concatenated.insert(concatenated.end(), AUTH[k].begin(), AUTH[k].end());

            if (!H(PKseed, adrs.toVector(), concatenated, node[1])) {
                throw std::runtime_error("Error in H during xmss_pkFromSig");
            }
        } else {
            adrs.setTreeIndex((adrs.getTreeIndex() - 1) / 2);

            ByteVector concatenated;
            concatenated.reserve(AUTH[k].size() + node[0].size());
            concatenated.insert(concatenated.end(), AUTH[k].begin(), AUTH[k].end());
            concatenated.insert(concatenated.end(), node[0].begin(), node[0].end());

            if (!H(PKseed, adrs.toVector(), concatenated, node[1])) {
                throw std::runtime_error("Error in H during xmss_pkFromSig");
            }
        }

        node[0] = node[1];
    }

    return node[0];
}

// Algorithm 12: ht_sign
ByteVector ht_sign(const ByteVector& M, const ByteVector& SKseed, const ByteVector& PKseed,
                   uint64_t idx_tree, uint32_t idx_leaf) {
    const SLH_DSA_Params* params = FIPS205ConfigManager::getCurrentParams();
    if (!params) {
        throw std::runtime_error("SLH_DSA_Params not initialized.");
    }

    const uint32_t d = params->d;
    const uint32_t h_prima = params->h_prima;

    ADRS adrs;
    adrs.setTreeAddress(reinterpret_cast<const uint8_t*>(&idx_tree));

    ByteVector SIG_tmp = xmss_sign(M, SKseed, idx_leaf, PKseed, adrs);
    ByteVector SIG_HT = SIG_tmp;
    ByteVector root = xmss_pkFromSig(idx_leaf, SIG_tmp, M, PKseed, adrs);

    for (uint32_t j = 1; j < d; j++) {
        uint32_t idx_leaf_j = idx_tree & ((1 << h_prima) - 1);
        idx_tree = idx_tree >> h_prima;

        adrs.setLayerAddress(j);
        adrs.setTreeAddress(reinterpret_cast<const uint8_t*>(&idx_tree));

        SIG_tmp = xmss_sign(root, SKseed, idx_leaf_j, PKseed, adrs);
        SIG_HT.insert(SIG_HT.end(), SIG_tmp.begin(), SIG_tmp.end());

        if (j < d - 1) {
            root = xmss_pkFromSig(idx_leaf_j, SIG_tmp, root, PKseed, adrs);
        }
    }

    return SIG_HT;
}

// Algorithm 13: ht_verify
bool ht_verify(const ByteVector& M, const ByteVector& SIG_HT, const ByteVector& PKseed,
               uint64_t idx_tree, uint32_t idx_leaf, const ByteVector& PKroot) {
    const SLH_DSA_Params* params = FIPS205ConfigManager::getCurrentParams();
    if (!params) {
        throw std::runtime_error("SLH_DSA_Params not initialized.");
    }

    const size_t n = params->n;
    const uint32_t d = params->d;
    const uint32_t h_prima = params->h_prima;
    const uint32_t lg_w = params->lg_w;
    const size_t len1 = (8 * n + lg_w - 1) / lg_w;
    const size_t len2 = gen_len2(n, lg_w);
    const size_t len = len1 + len2;
    const size_t wots_sig_size = len * n;
    const size_t xmss_sig_size = wots_sig_size + h_prima * n;

    ADRS adrs;
    adrs.setTreeAddress(reinterpret_cast<const uint8_t*>(&idx_tree));

    ByteVector SIG_tmp(SIG_HT.begin(), SIG_HT.begin() + xmss_sig_size);
    ByteVector node = xmss_pkFromSig(idx_leaf, SIG_tmp, M, PKseed, adrs);

    for (uint32_t j = 1; j < d; j++) {
        uint32_t idx_leaf_j = idx_tree & ((1 << h_prima) - 1);
        idx_tree = idx_tree >> h_prima;

        adrs.setLayerAddress(j);
        adrs.setTreeAddress(reinterpret_cast<const uint8_t*>(&idx_tree));

        size_t offset = j * xmss_sig_size;
        SIG_tmp = ByteVector(SIG_HT.begin() + offset,
                             SIG_HT.begin() + offset + xmss_sig_size);

        node = xmss_pkFromSig(idx_leaf_j, SIG_tmp, node, PKseed, adrs);
    }

    return node == PKroot;
}

// Algorithm 14: fors_skGen
ByteVector fors_skGen(const ByteVector& SKseed, const ByteVector& PKseed, ADRS adrs, uint32_t idx) {
    const SLH_DSA_Params* params = FIPS205ConfigManager::getCurrentParams();
    if (!params) {
        throw std::runtime_error("SLH_DSA_Params not initialized.");
    }

    const size_t n = params->n;

    ADRS skADRS = adrs;
    skADRS.setTypeAndClear(FORS_PRF);
    skADRS.setKeyPairAddress(adrs.getKeyPairAddress());
    skADRS.setTreeIndex(idx);

    ByteVector sk(n);
    if (!PRF(PKseed, SKseed, skADRS.toVector(), sk)) {
        throw std::runtime_error("Error in PRF during fors_skGen");
    }

    return sk;
}

// Algorithm 15: fors_node
ByteVector fors_node(const ByteVector& SKseed, uint32_t i, uint32_t z,
                     const ByteVector& PKseed, ADRS adrs) {
    const SLH_DSA_Params* params = FIPS205ConfigManager::getCurrentParams();
    if (!params) {
        throw std::runtime_error("SLH_DSA_Params not initialized.");
    }

    ByteVector node;

    if (z == 0) {
        ByteVector sk = fors_skGen(SKseed, PKseed, adrs, i);
        adrs.setTreeHeight(0);
        adrs.setTreeIndex(i);

        if (!F(PKseed, adrs.toVector(), sk, node)) {
            throw std::runtime_error("Error in F during fors_node");
        }
    } else {
        ByteVector lnode = fors_node(SKseed, 2*i, z-1, PKseed, adrs);
        ByteVector rnode = fors_node(SKseed, 2*i+1, z-1, PKseed, adrs);

        adrs.setTreeHeight(z);
        adrs.setTreeIndex(i);

        ByteVector concatenated;
        concatenated.reserve(lnode.size() + rnode.size());
        concatenated.insert(concatenated.end(), lnode.begin(), lnode.end());
        concatenated.insert(concatenated.end(), rnode.begin(), rnode.end());

        if (!H(PKseed, adrs.toVector(), concatenated, node)) {
            throw std::runtime_error("Error in H during fors_node");
        }
    }

    return node;
}

// Algorithm 16: fors_sign
ByteVector fors_sign(const ByteVector& md, const ByteVector& SKseed,
                     const ByteVector& PKseed, ADRS adrs) {
    const SLH_DSA_Params* params = FIPS205ConfigManager::getCurrentParams();
    if (!params) {
        throw std::runtime_error("SLH_DSA_Params not initialized.");
    }

    const size_t n = params->n;
    const uint32_t k = params->k;
    const uint32_t a = params->a;
    const uint32_t t = 1 << a;

    ByteVector SIG_FORS;
    std::vector<uint32_t> indices = base_2b(md, a, k);
    std::vector<ByteVector> AUTH;

    for (uint32_t i = 0; i < k; i++) {
        uint32_t leaf_index = i * t + indices[i];
        ByteVector sk = fors_skGen(SKseed, PKseed, adrs, leaf_index);
        SIG_FORS.insert(SIG_FORS.end(), sk.begin(), sk.end());

        for (uint32_t j = 0; j < a; j++) {
            uint32_t s = (indices[i] >> j) ^ 1;
            uint32_t node_index = i * (t >> j) + s;
            ByteVector auth_node = fors_node(SKseed, node_index, j, PKseed, adrs);
            AUTH.push_back(auth_node);
        }
    }

    for (const auto& auth_node : AUTH) {
        SIG_FORS.insert(SIG_FORS.end(), auth_node.begin(), auth_node.end());
    }

    return SIG_FORS;
}

// Algorithm 17: fors_pkFromSig
ByteVector fors_pkFromSig(const ByteVector& SIG_FORS, const ByteVector& md,
                          const ByteVector& PKseed, ADRS adrs) {
    const SLH_DSA_Params* params = FIPS205ConfigManager::getCurrentParams();
    if (!params) {
        throw std::runtime_error("SLH_DSA_Params not initialized.");
    }

    const size_t n = params->n;
    const uint32_t k = params->k;
    const uint32_t a = params->a;
    const uint32_t t = 1 << a;

    std::vector<uint32_t> indices = base_2b(md, a, k);
    std::vector<ByteVector> roots(k);

    size_t sk_size = n;
    size_t auth_size = a * n;
    size_t tree_sig_size = sk_size + auth_size;

    for (uint32_t i = 0; i < k; i++) {
        size_t sk_offset = i * tree_sig_size;
        ByteVector sk(SIG_FORS.begin() + sk_offset, SIG_FORS.begin() + sk_offset + n);

        adrs.setTreeHeight(0);
        adrs.setTreeIndex(i * t + indices[i]);

        std::vector<ByteVector> node(2);
        if (!F(PKseed, adrs.toVector(), sk, node[0])) {
            throw std::runtime_error("Error in F during fors_pkFromSig");
        }

        std::vector<ByteVector> auth(a);
        for (uint32_t j = 0; j < a; j++) {
            size_t auth_offset = sk_offset + n + j * n;
            auth[j] = ByteVector(SIG_FORS.begin() + auth_offset,
                                 SIG_FORS.begin() + auth_offset + n);
        }

        for (uint32_t j = 0; j < a; j++) {
            adrs.setTreeHeight(j + 1);

            if ((indices[i] >> j) % 2 == 0) {
                adrs.setTreeIndex(adrs.getTreeIndex() / 2);

                ByteVector concatenated;
                concatenated.reserve(node[0].size() + auth[j].size());
                concatenated.insert(concatenated.end(), node[0].begin(), node[0].end());
                concatenated.insert(concatenated.end(), auth[j].begin(), auth[j].end());

                if (!H(PKseed, adrs.toVector(), concatenated, node[1])) {
                    throw std::runtime_error("Error in H during fors_pkFromSig");
                }
            } else {
                adrs.setTreeIndex((adrs.getTreeIndex() - 1) / 2);

                ByteVector concatenated;
                concatenated.reserve(auth[j].size() + node[0].size());
                concatenated.insert(concatenated.end(), auth[j].begin(), auth[j].end());
                concatenated.insert(concatenated.end(), node[0].begin(), node[0].end());

                if (!H(PKseed, adrs.toVector(), concatenated, node[1])) {
                    throw std::runtime_error("Error in H during fors_pkFromSig");
                }
            }

            node[0] = node[1];
        }

        roots[i] = node[0];
    }

    ADRS forspkADRS = adrs;
    forspkADRS.setTypeAndClear(FORS_ROOTS);
    forspkADRS.setKeyPairAddress(adrs.getKeyPairAddress());

    ByteVector pk;
    if (!T_l(PKseed, forspkADRS.toVector(), roots, pk)) {
        throw std::runtime_error("Error in T_l during fors_pkFromSig");
    }

    return pk;
}

// Algorithm 18: slh_keygen_internal
std::pair<SLH_DSA_PrivateKey, SLH_DSA_PublicKey> slh_keygen_internal(
        const ByteVector& SKseed, const ByteVector& SKprf, const ByteVector& PKseed) {
    const SLH_DSA_Params* params = FIPS205ConfigManager::getCurrentParams();
    if (!params) {
        throw std::runtime_error("SLH_DSA_Params not initialized.");
    }

    const uint32_t d = params->d;
    const uint32_t h_prima = params->h_prima;

    ADRS adrs;
    adrs.setLayerAddress(d - 1);

    ByteVector PKroot = xmss_node(SKseed, 0, h_prima, PKseed, adrs);

    SLH_DSA_PrivateKey privateKey;
    privateKey.seed = SKseed;
    privateKey.prf = SKprf;
    privateKey.pkSeed = PKseed;
    privateKey.pkRoot = PKroot;

    SLH_DSA_PublicKey publicKey;
    publicKey.seed = PKseed;
    publicKey.root = PKroot;

    return std::make_pair(privateKey, publicKey);
}

// Algorithm 19: slh_sign_internal - CORREGIDO
SLH_DSA_Signature slh_sign_internal(const ByteVector& M,
                                    const SLH_DSA_PrivateKey& privateKey,
                                    const ByteVector& addrnd) {

    // Obtener los parametros definidos en params
    const SLH_DSA_Params* params = FIPS205ConfigManager::getCurrentParams();
    if (!params) {
        throw std::runtime_error("SLH_DSA_Params not initialized.");
    }

    const size_t n = params->n;
    const uint32_t k = params->k;
    const uint32_t a = params->a;
    const uint32_t h = params->h;
    const uint32_t d = params->d;
    const uint32_t h_prima = params->h_prima;

    ADRS adrs;
    // Si se proporciona addrnd, se usa como semilla aleatoria; de lo contrario, se usa pkSeed siendo determinista
    ByteVector opt_rand = addrnd.empty() ? privateKey.pkSeed : addrnd;

    ByteVector R;
    if (!PRF_msg(privateKey.prf, opt_rand, M, R)) {
        throw std::runtime_error("Error in PRF_msg");
    }

    ByteVector digest;
    if (!H_msg(R, privateKey.pkSeed, privateKey.pkRoot, M, digest)) {
        throw std::runtime_error("Error in H_msg");
    }

    // 𝑚𝑑 ← 𝑑𝑖𝑔𝑒𝑠𝑡 [0 ∶ ⌈𝑘⋅𝑎/8 ⌉]
    const size_t md_bits = k * a;
    const size_t md_bytes = (md_bits + 7) / 8;  // El +7 es para hacer el redondeo haia arriba

    // �𝑚𝑝_𝑖𝑑𝑥𝑡𝑟𝑒𝑒 ← 𝑑𝑖𝑔𝑒𝑠𝑡 [⌈𝑘⋅𝑎/8 ⌉ ∶ ⌈𝑘⋅𝑎/8 ⌉+⌈(ℎ−ℎ/𝑑)/8 ⌉]
    const size_t tree_idx_bits = h - (h / d);                       // 64 - 8 = 56 bits
    const size_t leaf_idx_bits = h / d;                             // 64/8 = 8 bits (NO h_prima/d)
    const size_t tree_idx_bytes = (tree_idx_bits + 7) / 8;          // 7 bytes
    const size_t leaf_idx_bytes = (leaf_idx_bits + 7) / 8;          // 1 byte

    const size_t required_bytes = md_bytes + tree_idx_bytes + leaf_idx_bytes;

    if (digest.size() < required_bytes) {
        throw std::runtime_error("Digest insuficiente: necesarios " +
                                 std::to_string(required_bytes) + " bytes, disponibles " +
                                 std::to_string(digest.size()));
    }
    // 𝑚𝑑 ← 𝑑𝑖𝑔𝑒𝑠𝑡 [0 ∶ ⌈𝑘⋅𝑎/8 ⌉]
    ByteVector md(digest.begin(), digest.begin() + md_bytes);

    const size_t tree_idx_start = md_bytes;
    ByteVector tmp_idx_tree(digest.begin() + tree_idx_start,
                            digest.begin() + tree_idx_start + tree_idx_bytes);

    const size_t leaf_idx_start = tree_idx_start + tree_idx_bytes;
    ByteVector tmp_idx_leaf(digest.begin() + leaf_idx_start,
                            digest.begin() + leaf_idx_start + leaf_idx_bytes);

    // CORRECCIÓN: Usar uint64_t para idx_tree (56 bits no cabe en uint32_t)
    uint64_t idx_tree_64 = 0;
    for (size_t i = 0; i < tmp_idx_tree.size() && i < 8; i++) {
        idx_tree_64 = (idx_tree_64 << 8) | static_cast<uint64_t>(tmp_idx_tree[i]);
    }
    idx_tree_64 &= ((1ULL << tree_idx_bits) - 1);

    uint32_t idx_leaf = 0;
    for (size_t i = 0; i < tmp_idx_leaf.size() && i < 4; i++) {
        idx_leaf = (idx_leaf << 8) | static_cast<uint32_t>(tmp_idx_leaf[i]);
    }
    idx_leaf &= ((1ULL << leaf_idx_bits) - 1);

    // CORRECCIÓN: Convertir idx_tree_64 a array de bytes para setTreeAddress
    // Crear array de 12 bytes (tamaño esperado por setTreeAddress) en big-endian
    uint8_t tree_addr_bytes[12] = {0};

    // Colocar idx_tree_64 en los últimos 8 bytes del array (big-endian)
    for (int i = 7; i >= 0; i--) {
        tree_addr_bytes[4 + i] = static_cast<uint8_t>(idx_tree_64 & 0xFF);
        idx_tree_64 >>= 8;
    }

    adrs.setTreeAddress(tree_addr_bytes);
    adrs.setTypeAndClear(FORS_TREE);
    adrs.setKeyPairAddress(idx_leaf);
    ByteVector SIG_FORS = fors_sign(md, privateKey.seed, privateKey.pkSeed, adrs);

    ByteVector PK_FORS = fors_pkFromSig(SIG_FORS, md, privateKey.pkSeed, adrs);

    // CORRECCIÓN: Restaurar idx_tree_64 para ht_sign
    idx_tree_64 = 0;
    for (size_t i = 0; i < tmp_idx_tree.size() && i < 8; i++) {
        idx_tree_64 = (idx_tree_64 << 8) | static_cast<uint64_t>(tmp_idx_tree[i]);
    }
    idx_tree_64 &= ((1ULL << tree_idx_bits) - 1);

    // Para ht_sign, si acepta uint32_t, usar solo los bits bajos necesarios
    // Si acepta uint64_t, pasar idx_tree_64 directamente
    uint32_t idx_tree_for_ht = static_cast<uint32_t>(idx_tree_64 & 0xFFFFFFFF);

    ByteVector SIG_HT = ht_sign(PK_FORS, privateKey.seed, privateKey.pkSeed, idx_tree_for_ht, idx_leaf);

    SLH_DSA_Signature signature;
    signature.randomness = R;
    signature.forsSignature = SIG_FORS;
    signature.htSignature = SIG_HT;

    return signature;
}
// Algorithm 20: slh_verify_internal
bool slh_verify_internal(const ByteVector& M, const ByteVector& SIG, const SLH_DSA_PublicKey& PK) {
    const SLH_DSA_Params* params = FIPS205ConfigManager::getCurrentParams();
    if (!params) {
        return false;
    }

    const size_t n = params->n;
    const uint32_t k = params->k;
    const uint32_t a = params->a;
    const uint32_t h = params->h;
    const uint32_t d = params->d;
    const uint32_t h_prima = params->h_prima;
    const uint32_t lg_w = params->lg_w;

    const size_t len1 = (8 * n + lg_w - 1) / lg_w;
    const size_t len2 = gen_len2(n, lg_w);
    const size_t len = len1 + len2;

    if (SIG.size() != (1 + k * (1 + a) + h + d * len) * n) {
        return false;
    }

    ADRS adrs;

    ByteVector R(SIG.begin(), SIG.begin() + n);

    size_t fors_offset = n;
    size_t fors_size = k * (1 + a) * n;
    ByteVector SIG_FORS(SIG.begin() + fors_offset, SIG.begin() + fors_offset + fors_size);

    size_t ht_offset = fors_offset + fors_size;
    ByteVector SIG_HT(SIG.begin() + ht_offset, SIG.end());

    ByteVector digest;
    if (!H_msg(R, PK.seed, PK.root, M, digest)) {
        return false;
    }

    const size_t md_bits = k * a;
    const size_t md_bytes = (md_bits + 7) / 8;
    ByteVector md(digest.begin(), digest.begin() + md_bytes);

    const size_t tree_idx_start = md_bytes;
    const size_t tree_idx_bits = h - h_prima / d;
    const size_t tree_idx_bytes = (tree_idx_bits + 7) / 8;
    ByteVector tmp_idx_tree(digest.begin() + tree_idx_start,
                            digest.begin() + tree_idx_start + tree_idx_bytes);

    const size_t leaf_idx_start = tree_idx_start + tree_idx_bytes;
    const size_t leaf_idx_bits = h_prima / d;
    const size_t leaf_idx_bytes = (leaf_idx_bits + 7) / 8;
    ByteVector tmp_idx_leaf(digest.begin() + leaf_idx_start,
                            digest.begin() + leaf_idx_start + leaf_idx_bytes);

    uint32_t idx_tree = toInt(tmp_idx_tree, tmp_idx_tree.size()) & ((1ULL << tree_idx_bits) - 1);
    uint32_t idx_leaf = toInt(tmp_idx_leaf, tmp_idx_leaf.size()) & ((1ULL << leaf_idx_bits) - 1);

    adrs.setTreeAddress(reinterpret_cast<const uint8_t*>(&idx_tree));
    adrs.setTypeAndClear(FORS_TREE);
    adrs.setKeyPairAddress(idx_leaf);

    ByteVector PK_FORS = fors_pkFromSig(SIG_FORS, md, PK.seed, adrs);

    return ht_verify(PK_FORS, SIG_HT, PK.seed, idx_tree, idx_leaf, PK.root);
}

// Algorithm 21: slh_keygen
std::pair<SLH_DSA_PrivateKey, SLH_DSA_PublicKey> slh_keygen() {
    const SLH_DSA_Params* params = FIPS205ConfigManager::getCurrentParams();
    if (!params) {
        throw std::runtime_error("SLH_DSA_Params not initialized.");
    }

    const size_t n = params->n;

    ByteVector SKseed(n);
    ByteVector SKprf(n);
    ByteVector PKseed(n);

    if (RAND_bytes(SKseed.data(), n) != 1 ||
        RAND_bytes(SKprf.data(), n) != 1 ||
        RAND_bytes(PKseed.data(), n) != 1) {
        throw std::runtime_error("Error generating secure random bytes with OpenSSL");
    }

    return slh_keygen_internal(SKseed, SKprf, PKseed);
}

// Algorithm 22: slh_sign
ByteVector slh_sign(const ByteVector& M, const ByteVector& ctx, const SLH_DSA_PrivateKey& SK) {
    if (ctx.size() > 255) {
        throw std::invalid_argument("Context string is too long (must be <= 255 bytes)");
    }

    ByteVector addrnd; // For deterministic variant

    ByteVector M_prime;
    M_prime.push_back(0); // toByte(0,1) - indicates "message"
    M_prime.push_back(static_cast<uint8_t>(ctx.size())); // toByte(|ctx|,1)
    M_prime.insert(M_prime.end(), ctx.begin(), ctx.end()); // ctx
    M_prime.insert(M_prime.end(), M.begin(), M.end()); // M

    SLH_DSA_Signature signature = slh_sign_internal(M_prime, SK, addrnd);
    return signature.toBytes();
}

// Algorithm 24: slh_verify
bool slh_verify(const ByteVector& M, const ByteVector& SIG, const ByteVector& ctx, const SLH_DSA_PublicKey& PK) {
    if (ctx.size() > 255) {
        return false;
    }

    ByteVector M_prime;
    M_prime.push_back(0); // toByte(0,1) - indicates "message"
    M_prime.push_back(static_cast<uint8_t>(ctx.size())); // toByte(|ctx|,1)
    M_prime.insert(M_prime.end(), ctx.begin(), ctx.end()); // ctx
    M_prime.insert(M_prime.end(), M.begin(), M.end()); // M

    return slh_verify_internal(M_prime, SIG, PK);
}