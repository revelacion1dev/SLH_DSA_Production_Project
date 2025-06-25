// fips205.cpp - Cleaned implementation
#include "fips205.h"
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <stdexcept>
#include <cstring>
#include <cstdint>
// Thread-local optimization variables
namespace {
    thread_local EVP_MD_CTX* g_quick_shake_ctx = nullptr;
    thread_local bool g_quick_ctx_initialized = false;
}

//
class uint128_t {
private:
    uint64_t low_;
    uint64_t high_;

public:
    // Constructores
    uint128_t() : low_(0), high_(0) {}

    explicit uint128_t(uint64_t val) : low_(val), high_(0) {}

    explicit uint128_t(uint32_t val) : low_(static_cast<uint64_t>(val)), high_(0) {}

    uint128_t(uint64_t high, uint64_t low) : low_(low), high_(high) {}

    // Getters
    uint64_t low() const { return low_; }
    uint64_t high() const { return high_; }

    uint128_t operator+(const uint128_t& other) const {
        uint64_t result_low = low_ + other.low_;
        uint64_t carry = (result_low < low_) ? 1 : 0;
        uint64_t result_high = high_ + other.high_ + carry;
        return uint128_t(result_high, result_low);
    }

    uint128_t operator*(const uint128_t& other) const {
        // Para simplificar, solo el producto de la parte baja
        // (suficiente para nuestros casos de uso)
        return (*this) * other.low_;
    }

    uint128_t operator*(uint64_t rhs) const {
        // Multiplicación 64x64 -> 128 usando partes de 32 bits
        uint64_t a_low = low_ & 0xFFFFFFFFULL;
        uint64_t a_high = low_ >> 32;
        uint64_t b_low = rhs & 0xFFFFFFFFULL;
        uint64_t b_high = rhs >> 32;

        uint64_t p0 = a_low * b_low;
        uint64_t p1 = a_low * b_high;
        uint64_t p2 = a_high * b_low;
        uint64_t p3 = a_high * b_high;

        uint64_t middle = p1 + p2;
        uint64_t middle_carry = (middle < p1) ? 1 : 0;

        uint64_t result_low = p0 + (middle << 32);
        uint64_t low_carry = (result_low < p0) ? 1 : 0;

        uint64_t result_high = p3 + (middle >> 32) + middle_carry +
                               (high_ * rhs) + low_carry;

        return uint128_t(result_high, result_low);
    }

    uint128_t operator<<(int shift) const {
        if (shift >= 128 || shift < 0) return uint128_t();
        if (shift == 0) return *this;

        if (shift >= 64) {
            return uint128_t(low_ << (shift - 64), 0);
        } else {
            uint64_t new_high = (high_ << shift) | (low_ >> (64 - shift));
            uint64_t new_low = low_ << shift;
            return uint128_t(new_high, new_low);
        }
    }

    uint128_t operator>>(int shift) const {
        if (shift >= 128 || shift < 0) return uint128_t();
        if (shift == 0) return *this;

        if (shift >= 64) {
            return uint128_t(0, high_ >> (shift - 64));
        } else {
            uint64_t new_low = (low_ >> shift) | (high_ << (64 - shift));
            uint64_t new_high = high_ >> shift;
            return uint128_t(new_high, new_low);
        }
    }

    uint128_t operator&(const uint128_t& mask) const {
        return uint128_t(high_ & mask.high_, low_ & mask.low_);
    }

    uint128_t operator^(const uint128_t& other) const {
        return uint128_t(high_ ^ other.high_, low_ ^ other.low_);
    }

    uint128_t operator^(uint64_t val) const {
        return uint128_t(high_, low_ ^ val);
    }

    bool operator==(const uint128_t& other) const {
        return low_ == other.low_ && high_ == other.high_;
    }

    bool operator!=(const uint128_t& other) const {
        return !(*this == other);
    }

    explicit operator uint64_t() const {
        return low_;
    }

    explicit operator uint32_t() const {
        return static_cast<uint32_t>(low_);
    }

    static uint128_t create_mask(int bits) {
        if (bits <= 0) return uint128_t();
        if (bits >= 128) return uint128_t(0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL);

        if (bits <= 64) {
            uint64_t mask = (bits == 64) ? 0xFFFFFFFFFFFFFFFFULL : ((1ULL << bits) - 1);
            return uint128_t(0, mask);
        } else {
            uint64_t high_mask = (1ULL << (bits - 64)) - 1;
            return uint128_t(high_mask, 0xFFFFFFFFFFFFFFFFULL);
        }
    }
};
inline uint128_t operator*(uint64_t lhs, const uint128_t& rhs) {
    return rhs * lhs;
}
uint128_t toInt128(const ByteVector& X, uint64_t n) {
    if (X.size() < n || n == 0) {
        return uint128_t();
    }

    uint128_t total;
    for (size_t i = 0; i < n && i < 16; ++i) {
        total = (total << 8) + uint128_t(static_cast<uint64_t>(X[i]));
    }

    return total;
}

uint128_t create_bit_mask_128(size_t bits) {
    return uint128_t::create_mask(static_cast<int>(bits));
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

// Fast concatenate and hash with context reuse
bool concatenateAndHash_quick(const std::vector<ByteVector>& inputs, ByteVector& output, size_t outputLen) {
    if (!ensure_quick_context_initialized()) {
        return concatenateAndHash(inputs, output, outputLen);
    }

    output.resize(outputLen);
    EVP_MD_CTX_reset(g_quick_shake_ctx);

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
SLH_DSA_ParamSet FIPS205ConfigManager::current_schema = SLH_DSA_ParamSet::SLH_DSA_SHAKE_128s; // Esquema por defecto
const SLH_DSA_Params* FIPS205ConfigManager::current_params = nullptr;
std::mutex FIPS205ConfigManager::config_mutex;
bool FIPS205ConfigManager::is_initialized = false;

// Parameter table
const SLH_DSA_Params PARAMS[static_cast<size_t>(SLH_DSA_ParamSet::PARAM_COUNT)] = {
        {"SLH-DSA-SHAKE-128s",  16, 63,  7,  9, 12, 14, 4, 30, 1, 32,  7856,  true },
        {"SLH-DSA-SHAKE-128f",  16, 66, 22,  3,  6, 33, 4, 34, 1, 32, 17088,  true },
        {"SLH-DSA-SHAKE-192s",  24, 63,  7,  9, 14, 17, 4, 39, 3, 48, 16224,  true },
        {"SLH-DSA-SHAKE-192f",  24, 66, 22,  3,  8, 33, 4, 42, 3, 48, 35664,  true },
        {"SLH-DSA-SHAKE-256s",  32, 64,  8,  8, 14, 22, 4, 47, 5, 64, 29792,  true },
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
    const SLH_DSA_Params* params = FIPS205ConfigManager::getCurrentParams();


    const EVP_MD* shake_variant = EVP_shake256();

    if (params && params->is_shake) {
        // Siempre SHAKE256 para variantes SHAKE, independiente de n
        shake_variant = EVP_shake256();

    } else if (params) {

        //Si no es shake lanzamos una escepcion que diga to be done
        throw std::runtime_error("SHA variant not supported for this parameter set.");
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
// Algoritmo 2: toInt
uint32_t toInt32(const ByteVector& X, uint64_t n) {
    if (X.size() < n) {
        throw std::invalid_argument("Input array is too short");
    }
    if (n == 0) {
        return 0;
    }
    uint32_t total = 0;
    for (size_t i = 0; i < n; ++i) {
        total = (total << 8) | static_cast<uint32_t>(X[i]);
    }

    return total;
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

ByteVector toByte(uint64_t x, size_t n) {
    // Según FIPS 205 Algoritmo 3:
    // Convierte un entero a byte string de longitud n en big-endian

    ByteVector S(n, 0);  // Byte string de longitud n
    uint64_t total = x;

    // for i from 0 to n-1 do
    //     S[n-1-i] ← total mod 256
    //     total ← total >> 8
    for (size_t i = 0; i < n; i++) {
        S[n - 1 - i] = static_cast<uint8_t>(total & 0xFF);  // total mod 256
        total >>= 8;  // total >> 8
    }

    return S;
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

void ADRS::setTreeAddress(uint64_t tree) {
    ByteVector tree_bytes = toByte(tree, 12);
    std::copy(tree_bytes.begin(), tree_bytes.end(), addr.begin() + 4);
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

// Algoritmo 1: gen_len2
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


// Algoritmo 2: toInt
uint64_t toInt64(const ByteVector& X, uint64_t n) {
    if (X.size() < n) {
        throw std::invalid_argument("Input array is too short");
    }

    if (n == 0) {
        return 0;
    }

    uint64_t total = 0;
    for (size_t i = 0; i < n; ++i) {
        total = (total << 8) | static_cast<uint64_t>(X[i]);
    }

    return total;
}

// Algoritmo 3: toByte helper function
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

// Algoritmo 4: base_2b
std::vector<uint32_t> base_2b(const ByteVector& X, int b, int out_len) {
    if (b <= 0 || b > 31) {
        throw std::invalid_argument("b must be between 1 and 31");
    }

    // Calcular bytes requeridos según fórmula FIPS 205
    int required_bytes = (out_len * b + 7) / 8;
    if (static_cast<int>(X.size()) < required_bytes) {
        throw std::invalid_argument("Input byte array X is too short for requested output length");
    }

    std::vector<uint32_t> baseb(out_len);
    size_t in = 0;
    int bits = 0;
    uint32_t total = 0;

    for (int out = 0; out < out_len; out++) {
        // Acumular suficientes bits
        while (bits < b) {
            total = (total << 8) | X[in];
            in++;
            bits += 8;
        }

        // Extraer b bits
        bits -= b;
        baseb[out] = (total >> bits) & ((1U << b) - 1);

        // Mantener solo los bits no consumidos
        total &= (1U << bits) - 1;
    }

    return baseb;
}

// Algoritmo 5: chain
ByteVector chain(ByteVector X, uint32_t i, uint32_t s, const ByteVector& PKseed, ADRS& adrs) {
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

// Algoritmo 6: wots_pkGen
ByteVector wots_pkGen(const ByteVector& SKseed, const ByteVector& PKseed, ADRS& adrs) {
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

    ByteVector pk(len * n);
    if (!T_l(PKseed, wotsADRS.toVector(), tmp, pk)) {
        throw std::runtime_error("Error in T_l during wots_pkGen");
    }

    return pk;
}

// Algoritmo 7: wots_sign
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

    // LÍNEA 1: csum ← 0
    uint32_t csum = 0;

    // LÍNEA 2: msg ← base_2^b(M, lg_w, len_1)
    std::vector<uint32_t> msg_base_w = base_2b(M, lg_w, static_cast<int>(len1));

    // LÍNEAS 3-5: Compute checksum
    for (size_t i = 0; i < len1; i++) {
        csum += w - 1 - msg_base_w[i];
    }

    // LÍNEA 6: csum ← csum << ((8 - ((len_2 · lg_w) mod 8)) mod 8)
    uint32_t shift_amount = (8 - ((len2 * lg_w) % 8)) % 8;
    csum = csum << shift_amount;

    // LÍNEA 7: msg ← msg || base_2^b(toByte(csum, ⌈len_2·lg_w/8⌉), lg_w, len_2)
    size_t csum_byte_len = (len2 * lg_w + 7) / 8;
    ByteVector csum_bytes = toByte(static_cast<uint64_t>(csum), csum_byte_len);
    std::vector<uint32_t> csum_base_w = base_2b(csum_bytes, lg_w, static_cast<int>(len2));

    // Concatenar msg y csum_base_w
    std::vector<uint32_t> msg_complete(len);
    for (size_t i = 0; i < len1; i++) {
        msg_complete[i] = msg_base_w[i];
    }
    for (size_t i = 0; i < len2; i++) {
        msg_complete[len1 + i] = csum_base_w[i];
    }

    // LÍNEAS 8-10: Setup skADRS
    ADRS skADRS = adrs;  // Copia para operaciones PRF
    skADRS.setTypeAndClear(WOTS_PRF);
    skADRS.setKeyPairAddress(adrs.getKeyPairAddress());

    // Preparar buffer de firma
    ByteVector sig(len * n);

    // LÍNEAS 11-16: Main signing loop
    for (size_t i = 0; i < len; i++) {
        // LÍNEA 12: skADRS.setChainAddress(i)
        skADRS.setChainAddress(static_cast<uint32_t>(i));

        // LÍNEA 13: sk ← PRF(PK.seed, SK.seed, skADRS)
        ByteVector sk;
        if (!PRF(PKseed, SKseed, skADRS.toVector(), sk)) {
            throw std::runtime_error("Error in PRF during wots_sign");
        }

        // LÍNEA 14: ADRS.setChainAddress(i)
        adrs.setChainAddress(static_cast<uint32_t>(i));

        // LÍNEA 15: sig[i] ← chain(sk, 0, msg[i], PK.seed, ADRS)
        ByteVector sig_part = chain(sk, 0, msg_complete[i], PKseed, adrs);

        // Copiar al buffer de firma
        std::copy(sig_part.begin(), sig_part.end(), sig.begin() + i * n);
    }

    // LÍNEA 17: return sig
    return sig;
}

// Algoritmo 8: wots_pkFromSig
ByteVector wots_pkFromSig(const ByteVector& sig, const ByteVector& M, const ByteVector& PKseed, ADRS& adrs) {
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

    // LÍNEA 1: csum ← 0
    uint32_t csum = 0;

    // LÍNEA 2: msg ← base_2^b(M, lg_w, len_1)
    std::vector<uint32_t> msg_base_w = base_2b(M, lg_w, static_cast<int>(len1));

    // LÍNEAS 3-5: Checksum
    for (size_t i = 0; i < len1; i++) {
        csum += w - 1 - msg_base_w[i];
    }

    // LÍNEA 6: csum ← csum << ((8 - ((len_2 · lg_w) mod 8)) mod 8)
    uint32_t shift_amount = (8 - ((len2 * lg_w) % 8)) % 8;
    csum = csum << shift_amount;  // ← SIN operación módulo adicional

    // LÍNEA 7: msg ← msg || base_2^b(toByte(csum, ⌈len_2·lg_w/8⌉), lg_w, len_2)
    size_t csum_byte_len = (len2 * lg_w + 7) / 8;
    ByteVector csum_bytes = toByte(static_cast<uint64_t>(csum), csum_byte_len);
    std::vector<uint32_t> csum_base_w = base_2b(csum_bytes, lg_w, static_cast<int>(len2));

    // Concatenar msg y csum_base_w
    std::vector<uint32_t> msg_complete(len);
    for (size_t i = 0; i < len1; i++) {
        msg_complete[i] = msg_base_w[i];
    }
    for (size_t i = 0; i < len2; i++) {
        msg_complete[len1 + i] = csum_base_w[i];
    }

    // LÍNEAS 8-11: Principal loop de verificacion
    std::vector<ByteVector> tmp(len);

    for (size_t i = 0; i < len; i++) {
        // Extraer sig[i] del buffer de firma
        ByteVector sig_i(sig.begin() + i * n, sig.begin() + (i + 1) * n);

        // LÍNEA 9: ADRS.setChainAddress(i) - usar ADRS directamente
        adrs.setChainAddress(static_cast<uint32_t>(i));

        // LÍNEA 10: tmp[i] ← chain(sig[i], msg[i], w - 1 - msg[i], PK.seed, ADRS)
        tmp[i] = chain(sig_i, msg_complete[i], w - 1 - msg_complete[i], PKseed, adrs);
    }

    // LÍNEAS 12-14: Setup wotspkADRS
    ADRS wotspkADRS = adrs;  // Copia del ADRS actual
    wotspkADRS.setTypeAndClear(WOTS_PK);
    wotspkADRS.setKeyPairAddress(adrs.getKeyPairAddress());

    // LÍNEA 15: pk_sig ← T_len(PK.seed, wotspkADRS, tmp)
    ByteVector pk(n);
    if (!T_l(PKseed, wotspkADRS.toVector(), tmp, pk)) {
        throw std::runtime_error("Error in T_l during wots_pkFromSig");
    }

    // LÍNEA 16: return pk_sig
    return pk;
}

// Algoritmo 9: xmss_node
ByteVector xmss_node(const ByteVector& SKseed, uint64_t i, uint32_t z, const ByteVector& PKseed, ADRS& adrs) {

    ByteVector node;
    if (z == 0) {
        // LÍNEAS 2-4: Caso base - generar hoja WOTS
        adrs.setTypeAndClear(WOTS_HASH);
        adrs.setKeyPairAddress(i);
        node = wots_pkGen(SKseed, PKseed, adrs);
    } else {
        // LÍNEAS 6-7: Llamadas recursivas
        ByteVector lnode = xmss_node(SKseed, 2*i, z-1, PKseed, adrs);
        ByteVector rnode = xmss_node(SKseed, 2*i+1, z-1, PKseed, adrs);

        // LÍNEAS 8-10: Configurar ADRS para nodo interno
        adrs.setTypeAndClear(TREE);  // O TREE según definición de constantes
        adrs.setTreeHeight(z);
        adrs.setTreeIndex(i);

        // LÍNEA 11: H(PK.seed, ADRS, lnode || rnode)
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

// Algoritmo 10: xmss_sign
ByteVector xmss_sign(const ByteVector& M, const ByteVector& SKseed, uint32_t idx,
                     const ByteVector& PKseed, ADRS &adrs) {
    const SLH_DSA_Params* params = FIPS205ConfigManager::getCurrentParams();
    if (!params) {
        throw std::runtime_error("SLH_DSA_Params not initialized.");
    }

    const uint32_t h_prima = params->h_prima;

    std::vector<ByteVector> AUTH(h_prima);
    for (uint32_t j = 0; j < h_prima; j++) {
        uint32_t k = (idx >> j) ^ 1;            // ⊕ = The bitwise exclusive-or of 𝑎 and 𝑏. For example, 115 ⊕ 1 = 114 (115 ⊕ 1 = 0b01110011 ⊕ 0b00000001 = 0b01110010 = 114).
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

// Algoritmo 11: xmss_pkFromSig
ByteVector xmss_pkFromSig(uint32_t idx, const ByteVector& SIG_XMSS,
                          const ByteVector& M, const ByteVector& PKseed, ADRS& adrs) {
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

    adrs.setTypeAndClear(TREE);
    adrs.setTreeIndex(idx);

    for (uint32_t k = 0; k < h_prima; k++) {
        adrs.setTreeHeight(k + 1);

        if ((idx / (1 << k)) % 2 == 0) {
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

// Algoritmo 12: ht_sign
ByteVector ht_sign(const ByteVector& M, const ByteVector& SKseed, const ByteVector& PKseed,
                   uint64_t idx_tree, uint64_t idx_leaf) {
    const SLH_DSA_Params* params = FIPS205ConfigManager::getCurrentParams();
    if (!params) {
        throw std::runtime_error("SLH_DSA_Params not initialized.");
    }

    const uint32_t d = params->d;
    const uint32_t h_prima = params->h_prima;

    ADRS adrs;
    adrs.setTreeAddress(idx_tree);

    ByteVector SIG_tmp = xmss_sign(M, SKseed, idx_leaf, PKseed, adrs);
    ByteVector SIG_HT = SIG_tmp;
    ByteVector root = xmss_pkFromSig(idx_leaf, SIG_tmp, M, PKseed, adrs);

    for (uint64_t j = 1; j < d; j++) {
        uint64_t idx_leaf_j = idx_tree & ((1 << h_prima) - 1);
        idx_tree = idx_tree >> h_prima;

        adrs.setLayerAddress(j);
        adrs.setTreeAddress(idx_tree);

        SIG_tmp = xmss_sign(root, SKseed, idx_leaf_j, PKseed, adrs);
        SIG_HT.insert(SIG_HT.end(), SIG_tmp.begin(), SIG_tmp.end());

        if (j < d - 1) {
            root = xmss_pkFromSig(idx_leaf_j, SIG_tmp, root, PKseed, adrs);
        }
    }

    return SIG_HT;
}

// Algoritmo 13: ht_verify
bool ht_verify(const ByteVector& M, const ByteVector& SIG_HT, const ByteVector& PKseed,
               uint64_t idx_tree, uint64_t idx_leaf, const ByteVector& PKroot) {
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
    adrs.setTreeAddress(idx_tree);

    ByteVector SIG_tmp(SIG_HT.begin(), SIG_HT.begin() + xmss_sig_size);
    ByteVector node = xmss_pkFromSig(idx_leaf, SIG_tmp, M, PKseed, adrs);

    for (uint64_t j = 1; j < d; j++) {
        uint64_t idx_leaf_j = idx_tree & ((1 << h_prima) - 1);
        idx_tree = idx_tree >> h_prima;

        adrs.setLayerAddress(j);
        adrs.setTreeAddress(idx_tree);

        size_t offset = j * xmss_sig_size;
        SIG_tmp = ByteVector(SIG_HT.begin() + offset,
                             SIG_HT.begin() + offset + xmss_sig_size);

        node = xmss_pkFromSig(idx_leaf_j, SIG_tmp, node, PKseed, adrs);
    }

    return node == PKroot;
}

// Algoritmo 14: fors_skGen
ByteVector fors_skGen(const ByteVector& SKseed, const ByteVector& PKseed, ADRS& adrs, uint32_t idx) {
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

// Algoritmo 15: fors_node
ByteVector fors_node(const ByteVector& SKseed, uint32_t i, uint32_t z,
                     const ByteVector& PKseed, ADRS& adrs) {
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

// Algoritmo 16: forst_sign
ByteVector fors_sign(const ByteVector& md, const ByteVector& SKseed,
                     const ByteVector& PKseed, ADRS& adrs) {
    const SLH_DSA_Params* params = FIPS205ConfigManager::getCurrentParams();
    if (!params) {
        throw std::runtime_error("SLH_DSA_Params not initialized.");
    }

    const size_t n = params->n;
    const uint32_t k = params->k;
    const uint32_t a = params->a;
    const uint128_t t = uint128_t(static_cast<uint64_t>(1)) << a;

    ByteVector SIG_FORS;
    std::vector<uint32_t> indices = base_2b(md, static_cast<int>(a), static_cast<int>(k));

    for (uint32_t i = 0; i < k; i++) {

        uint128_t i_128 = uint128_t(static_cast<uint64_t>(i));
        uint128_t indices_i_128 = uint128_t(static_cast<uint64_t>(indices[i]));
        uint128_t leaf_index_128 = i_128 * t + indices_i_128;
        uint32_t leaf_index = static_cast<uint32_t>(leaf_index_128);

        ByteVector sk = fors_skGen(SKseed, PKseed, adrs, leaf_index);
        SIG_FORS.insert(SIG_FORS.end(), sk.begin(), sk.end());

        std::vector<ByteVector> AUTH_i(a);

        for (uint32_t j = 0; j < a; j++) {

            uint128_t indices_i_shifted = uint128_t(static_cast<uint64_t>(indices[i])) >> j;
            uint128_t s = indices_i_shifted ^ uint128_t(static_cast<uint64_t>(1));

            uint128_t t_shifted = t >> j;
            uint128_t node_index_128 = i_128 * t_shifted + s;
            uint32_t node_index = static_cast<uint32_t>(node_index_128);

            AUTH_i[j] = fors_node(SKseed, node_index, j, PKseed, adrs);
        }

        for (const auto& auth_node : AUTH_i) {
            SIG_FORS.insert(SIG_FORS.end(), auth_node.begin(), auth_node.end());
        }
    }

    return SIG_FORS;
}



// Algoritmo 17: fors_pkFromSig
ByteVector fors_pkFromSig(const ByteVector& SIG_FORS, const ByteVector& md,
                          const ByteVector& PKseed, ADRS& adrs) {
    const SLH_DSA_Params* params = FIPS205ConfigManager::getCurrentParams();
    if (!params) {
        throw std::runtime_error("SLH_DSA_Params not initialized.");
    }

    const size_t n = params->n;
    const uint32_t k = params->k;
    const uint32_t a = params->a;


    const uint128_t t = uint128_t(static_cast<uint64_t>(1)) << a;

    std::vector<uint32_t> indices = base_2b(md, a, k);
    std::vector<ByteVector> roots(k);

    size_t sk_size = n;
    size_t auth_size = a * n;
    size_t tree_sig_size = sk_size + auth_size;

    for (size_t i = 0; i < k; i++) {
        size_t sk_offset = i * tree_sig_size;
        ByteVector sk(SIG_FORS.begin() + sk_offset, SIG_FORS.begin() + sk_offset + n);

        adrs.setTreeHeight(0);


        uint128_t i_128 = uint128_t(static_cast<uint64_t>(i));
        uint128_t indices_i_128 = uint128_t(static_cast<uint64_t>(indices[i]));
        uint128_t tree_idx_128 = i_128 * t + indices_i_128;
        adrs.setTreeIndex(static_cast<uint32_t>(tree_idx_128));

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

// Algoritmo 18: slh_keygen_internal
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

SLH_DSA_Signature slh_sign_internal(const ByteVector& M,
                                    const SLH_DSA_PrivateKey& privateKey,
                                    const ByteVector& addrnd) {
    const SLH_DSA_Params* params = FIPS205ConfigManager::getCurrentParams();
    if (!params) {
        throw std::runtime_error("SLH_DSA_Params not initialized.");
    }

    const size_t n = params->n;
    const uint32_t k = params->k;
    const uint32_t a = params->a;
    const uint32_t h = params->h;
    const uint32_t d = params->d;

    const size_t tree_idx_bits = h - (h / d);
    const size_t leaf_idx_bits = h / d;

    ADRS adrs;
    ByteVector opt_rand = addrnd.empty() ? privateKey.pkSeed : addrnd;

    ByteVector R;
    if (!PRF_msg(privateKey.prf, opt_rand, M, R)) {
        throw std::runtime_error("Error in PRF_msg");
    }

    ByteVector SIG = R;

    ByteVector digest;
    if (!H_msg(R, privateKey.pkSeed, privateKey.pkRoot, M, digest)) {
        throw std::runtime_error("Error in H_msg");
    }

    const size_t md_bits = k * a;
    const size_t md_bytes = (md_bits + 7) / 8;
    ByteVector md(digest.begin(), digest.begin() + md_bytes);

    const size_t tree_idx_bytes = (tree_idx_bits + 7) / 8;
    const size_t leaf_idx_bytes = (leaf_idx_bits + 7) / 8;

    const size_t tree_idx_start = md_bytes;
    ByteVector tmp_idx_tree(digest.begin() + tree_idx_start,
                            digest.begin() + tree_idx_start + tree_idx_bytes);

    const size_t leaf_idx_start = tree_idx_start + tree_idx_bytes;
    ByteVector tmp_idx_leaf(digest.begin() + leaf_idx_start,
                            digest.begin() + leaf_idx_start + leaf_idx_bytes);


    uint128_t idx_tree_128 = toInt128(tmp_idx_tree, tree_idx_bytes);
    uint128_t idx_leaf_128 = toInt128(tmp_idx_leaf, leaf_idx_bytes);

    // Aplicar máscaras con precisión completa - SIEMPRE SEGURO
    idx_tree_128 = idx_tree_128 & create_bit_mask_128(tree_idx_bits);
    idx_leaf_128 = idx_leaf_128 & create_bit_mask_128(leaf_idx_bits);

    // Convertir de vuelta a uint64_t para APIs existentes
    uint64_t idx_tree = static_cast<uint64_t>(idx_tree_128);
    uint64_t idx_leaf = static_cast<uint64_t>(idx_leaf_128);

    adrs.setTreeAddress(idx_tree);
    adrs.setTypeAndClear(FORS_TREE);
    adrs.setKeyPairAddress(idx_leaf);

    ByteVector SIG_FORS = fors_sign(md, privateKey.seed, privateKey.pkSeed, adrs);
    SIG.insert(SIG.end(), SIG_FORS.begin(), SIG_FORS.end());

    ByteVector PK_FORS = fors_pkFromSig(SIG_FORS, md, privateKey.pkSeed, adrs);
    ByteVector SIG_HT = ht_sign(PK_FORS, privateKey.seed, privateKey.pkSeed, idx_tree, idx_leaf);
    SIG.insert(SIG.end(), SIG_HT.begin(), SIG_HT.end());

    SLH_DSA_Signature signature;
    signature.randomness = R;
    signature.forsSignature = SIG_FORS;
    signature.htSignature = SIG_HT;

    return signature;
}



// Algoritmo 20: slh_verify_internal
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
    const size_t tree_idx_bits = h - (h / d);
    const size_t tree_idx_bytes = (tree_idx_bits + 7) / 8;
    ByteVector tmp_idx_tree(digest.begin() + tree_idx_start,
                            digest.begin() + tree_idx_start + tree_idx_bytes);

    const size_t leaf_idx_start = tree_idx_start + tree_idx_bytes;
    const size_t leaf_idx_bits = h / d;
    const size_t leaf_idx_bytes = (leaf_idx_bits + 7) / 8;
    ByteVector tmp_idx_leaf(digest.begin() + leaf_idx_start,
                            digest.begin() + leaf_idx_start + leaf_idx_bytes);


    uint128_t idx_tree_128 = toInt128(tmp_idx_tree, tree_idx_bytes);
    uint128_t idx_leaf_128 = toInt128(tmp_idx_leaf, leaf_idx_bytes);

    idx_tree_128 = idx_tree_128 & create_bit_mask_128(tree_idx_bits);
    idx_leaf_128 = idx_leaf_128 & create_bit_mask_128(leaf_idx_bits);

    uint64_t idx_tree = static_cast<uint64_t>(idx_tree_128);
    uint64_t idx_leaf = static_cast<uint64_t>(idx_leaf_128);

    adrs.setTreeAddress(idx_tree);
    adrs.setTypeAndClear(FORS_TREE);
    adrs.setKeyPairAddress(idx_leaf);

    ByteVector PK_FORS = fors_pkFromSig(SIG_FORS, md, PK.seed, adrs);

    return ht_verify(PK_FORS, SIG_HT, PK.seed, idx_tree, idx_leaf, PK.root);
}

// Algoritmo 21: slh_keygen
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

// Algoritmo 22: slh_sign
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

// Algoritmo 24: slh_verify
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