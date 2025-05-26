// fips205.cpp
#include "fips205.h"
#include <openssl/evp.h>  // SHAKE256
#include <openssl/err.h>  // Error handling
#include <openssl/rand.h> // Random number generation
#include <stdexcept>


// Inicialización de miembros estáticos
SLH_DSA_ParamSet FIPS205ConfigManager::current_schema = SLH_DSA_ParamSet::SLH_DSA_SHAKE_256s;
const SLH_DSA_Params* FIPS205ConfigManager::current_params = nullptr;
std::mutex FIPS205ConfigManager::config_mutex;
bool FIPS205ConfigManager::is_initialized = false;

// Tabla de parámetros
const SLH_DSA_Params PARAMS[static_cast<size_t>(SLH_DSA_ParamSet::PARAM_COUNT)] = {
        {"SLH-DSA-SHA2-128s",   16, 63,  7,  9, 12, 14, 4, 30, 1, 32,  7856,  false},
        {"SLH-DSA-SHAKE-128s",  16, 63,  7,  9, 12, 14, 4, 30, 1, 32,  7856,  true },
        {"SLH-DSA-SHA2-128f",   16, 66, 22,  3,  6, 33, 4, 34, 1, 32, 17088,  false},
        {"SLH-DSA-SHAKE-128f",  16, 66, 22,  3,  6, 33, 4, 34, 1, 32, 17088,  true },
        {"SLH-DSA-SHA2-192s",   24, 63,  7,  9, 14, 17, 4, 39, 3, 48, 16224,  false},
        {"SLH-DSA-SHAKE-192s",  24, 63,  7,  9, 14, 17, 4, 39, 3, 48, 16224,  true },
        {"SLH-DSA-SHA2-192f",   24, 66, 22,  3,  8, 33, 4, 42, 3, 48, 35664,  false},
        {"SLH-DSA-SHAKE-192f",  24, 66, 22,  3,  8, 33, 4, 42, 3, 48, 35664,  true },
        {"SLH-DSA-SHA2-256s",   32, 64,  8,  8, 14, 22, 4, 47, 5, 64, 29792,  false},
        {"SLH-DSA-SHAKE-256s",  32, 64,  8,  8, 14, 22, 4, 47, 5, 64, 29792,  true },
        {"SLH-DSA-SHA2-256f",   32, 68, 17,  4,  9, 35, 4, 49, 5, 64, 49856,  false},
        {"SLH-DSA-SHAKE-256f",  32, 68, 17,  4,  9, 35, 4, 49, 5, 64, 49856,  true }
};

// Función get_params
const SLH_DSA_Params* get_params(SLH_DSA_ParamSet set) {
    auto index = static_cast<size_t>(set);
    if (index >= static_cast<size_t>(SLH_DSA_ParamSet::PARAM_COUNT))
        return nullptr;
    return &PARAMS[index];
}

// Declaramos las funciones auxiliares asociadas a las estructuras tanto ñla clave publica/privada como la firma

// Clave Publica :
ByteVector SLH_DSA_PublicKey::toBytes() const {
    // La clave pública consiste en PK.seed || PK.root
    ByteVector result;
    result.reserve(seed.size() + root.size());

    // Concatenar PK.seed
    result.insert(result.end(), seed.begin(), seed.end());

    // Concatenar PK.root
    result.insert(result.end(), root.begin(), root.end());

    return result;
}

SLH_DSA_PublicKey SLH_DSA_PublicKey::fromBytes(const ByteVector& data) {

    // Obtener los parámetros actuales del config manager
    const SLH_DSA_Params* params = FIPS205ConfigManager::getCurrentParams();
    if (!params) {
        throw std::runtime_error("SLH_DSA_Params not initialized. Call FIPS205ConfigManager::initialize() first.");
    }

    // Verificar que el tamaño sea correcto (2*n bytes)
    const size_t n = params->n;
    const size_t expected_size = 2 * n;  // PK.seed (n bytes) + PK.root (n bytes)

    if (data.size() != expected_size) {
        throw std::invalid_argument("Invalid public key size. Expected " +
                                    std::to_string(expected_size) + " bytes, got " +
                                    std::to_string(data.size()) + " bytes");
    }

    SLH_DSA_PublicKey pk;

    // Extraer PK.seed (primeros n bytes)
    pk.seed = ByteVector(data.begin(), data.begin() + n);

    // Extraer PK.root (siguientes n bytes)
    pk.root = ByteVector(data.begin() + n, data.begin() + 2 * n);

    return pk;
}

// Clave Privada

ByteVector SLH_DSA_PrivateKey::toBytes() const {
    // La clave privada consiste en SK.seed || SK.prf || PK.seed || PK.root
    ByteVector result;
    result.reserve(seed.size() + prf.size() + pkSeed.size() + pkRoot.size());

    // Concatenar SK.seed
    result.insert(result.end(), seed.begin(), seed.end());

    // Concatenar SK.prf
    result.insert(result.end(), prf.begin(), prf.end());

    // Concatenar PK.seed
    result.insert(result.end(), pkSeed.begin(), pkSeed.end());

    // Concatenar PK.root
    result.insert(result.end(), pkRoot.begin(), pkRoot.end());

    return result;
}

SLH_DSA_PrivateKey SLH_DSA_PrivateKey::fromBytes(const ByteVector& data) {

    // Obtener los parámetros actuales del config manager
    const SLH_DSA_Params* params = FIPS205ConfigManager::getCurrentParams();
    if (!params) {
        throw std::runtime_error("SLH_DSA_Params not initialized. Call FIPS205ConfigManager::initialize() first.");
    }

    // Verificar que el tamaño sea correcto (4*n bytes)
    const size_t n = params->n;
    const size_t expected_size = 4 * n;  // SK.seed + SK.prf + PK.seed + PK.root (cada uno n bytes)

    if (data.size() != expected_size) {
        throw std::invalid_argument("Invalid private key size. Expected " +
                                    std::to_string(expected_size) + " bytes, got " +
                                    std::to_string(data.size()) + " bytes");
    }

    SLH_DSA_PrivateKey sk;

    // Extraer SK.seed (primeros n bytes)
    sk.seed = ByteVector(data.begin(), data.begin() + n);

    // Extraer SK.prf (siguientes n bytes)
    sk.prf = ByteVector(data.begin() + n, data.begin() + 2 * n);

    // Extraer PK.seed (siguientes n bytes)
    sk.pkSeed = ByteVector(data.begin() + 2 * n, data.begin() + 3 * n);

    // Extraer PK.root (últimos n bytes)
    sk.pkRoot = ByteVector(data.begin() + 3 * n, data.begin() + 4 * n);

    return sk;
}

SLH_DSA_PublicKey SLH_DSA_PrivateKey::getPublicKey() const {
    SLH_DSA_PublicKey pk;
    pk.seed = pkSeed;  // PK.seed es una copia de la clave privada
    pk.root = pkRoot;  // PK.root es una copia de la clave privada

    return pk;
}

// Funciones auxiliares a la firma
ByteVector SLH_DSA_Signature::toBytes() const {
    // La firma consiste en R || SIG_FORS || SIG_HT
    ByteVector result;
    result.reserve(randomness.size() + forsSignature.size() + htSignature.size());

    // Concatenar R (randomness)
    result.insert(result.end(), randomness.begin(), randomness.end());

    // Concatenar SIG_FORS
    result.insert(result.end(), forsSignature.begin(), forsSignature.end());

    // Concatenar SIG_HT
    result.insert(result.end(), htSignature.begin(), htSignature.end());

    return result;
}

SLH_DSA_Signature SLH_DSA_Signature::fromBytes(const ByteVector& data) {

    // Obtener los parámetros actuales del config manager
    const SLH_DSA_Params* params = FIPS205ConfigManager::getCurrentParams();
    if (!params) {
        throw std::runtime_error("SLH_DSA_Params not initialized. Call FIPS205ConfigManager::initialize() first.");
    }

    // Obtener parámetros para calcular los tamaños esperados
    const size_t n = params->n;
    const uint32_t k = params->k;
    const uint32_t a = params->a;
    const uint32_t h = params->h;
    const uint32_t d = params->d;
    const uint32_t lg_w = params->lg_w;

    // Calcular len para WOTS+
    const size_t len1 = (8 * n + lg_w - 1) / lg_w;
    const size_t len2 = gen_len2(n, lg_w);
    const size_t len = len1 + len2;

    // Calcular tamaños esperados de cada componente
    const size_t r_size = n;                          // R tiene n bytes
    const size_t fors_size = k * (1 + a) * n;        // SIG_FORS tiene k(1+a)·n bytes
    const size_t ht_size = (h + d * len) * n;        // SIG_HT tiene (h+d·len)·n bytes
    const size_t expected_total = r_size + fors_size + ht_size;

    // Verificar que el tamaño sea correcto
    if (data.size() != expected_total) {
        throw std::invalid_argument("Invalid signature size. Expected " +
                                    std::to_string(expected_total) + " bytes, got " +
                                    std::to_string(data.size()) + " bytes");
    }

    SLH_DSA_Signature sig;

    // Extraer R (primeros n bytes)
    sig.randomness = ByteVector(data.begin(), data.begin() + r_size);

    // Extraer SIG_FORS (siguientes k(1+a)·n bytes)
    size_t fors_start = r_size;
    sig.forsSignature = ByteVector(data.begin() + fors_start,
                                   data.begin() + fors_start + fors_size);

    // Extraer SIG_HT (resto de bytes)
    size_t ht_start = fors_start + fors_size;
    sig.htSignature = ByteVector(data.begin() + ht_start, data.end());

    return sig;
}



// Función SHAKE256 para calcular el hash segun 11.1
bool computeShake256(const ByteVector& input, ByteVector& output, size_t outputLen) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (ctx == nullptr) {
        return false;
    }

    output.resize(outputLen);
    bool success = false;

    // Inicializar con SHAKE256 (El engine se define como nulo, seria interesante aplicar alguno de cara a optimizar la
    // implementación por hardware)
    if (!EVP_DigestInit_ex(ctx, EVP_shake256(), nullptr)) {
        EVP_MD_CTX_free(ctx);
        return false;
    }

    // Procesar los datos de entrada
    if (!EVP_DigestUpdate(ctx, input.data(), input.size())) {
        EVP_MD_CTX_free(ctx);
        return false;
    }

    // Finalizar la operación usando XOF con la longitud deseada
    if (!EVP_DigestFinalXOF(ctx, output.data(), outputLen)) {
        EVP_MD_CTX_free(ctx);
        return false;
    }

    success = true;
    EVP_MD_CTX_free(ctx);
    return success;
}

// Función para concatenar y hacer hash
bool concatenateAndHash(const std::vector<ByteVector>& inputs, ByteVector& output, size_t outputLen) {
    // Calcular tamaño total
    size_t totalSize = 0;
    for (const auto& input : inputs) {
        totalSize += input.size();
    }

    // Reservar espacio y concatenar
    ByteVector concatenated;
    concatenated.reserve(totalSize);

    for (const auto& input : inputs) {
        concatenated.insert(concatenated.end(), input.begin(), input.end());
    }

    // Calcular hash
    return computeShake256(concatenated, output, outputLen);
}


// Implementations of hash functions for SLH-DSA with proper parameters

bool H_msg(const ByteVector& R, const ByteVector& PKseed, const ByteVector& PKroot,
           const ByteVector& M, ByteVector& output) {
    // Obtener los parámetros actuales del config manager
    const SLH_DSA_Params* params = FIPS205ConfigManager::getCurrentParams();
    if (!params) {
        throw std::runtime_error("SLH_DSA_Params not initialized. Call FIPS205ConfigManager::initialize() first.");
    }

    // Get the correct output length (m value from params)
    size_t outputLen = params->m;
    return concatenateAndHash({R, PKseed, PKroot, M}, output, outputLen);
}

bool PRF(const ByteVector& PKseed, const ByteVector& SKseed, const ByteVector& ADRS,
         ByteVector& output) {
    // Obtener los parámetros actuales del config manager
    const SLH_DSA_Params* params = FIPS205ConfigManager::getCurrentParams();
    if (!params) {
        throw std::runtime_error("SLH_DSA_Params not initialized. Call FIPS205ConfigManager::initialize() first.");
    }

    // Output length is n from the parameters
    size_t outputLen = params->n;
    return concatenateAndHash({PKseed, ADRS, SKseed}, output, outputLen);
}

bool PRF_msg(const ByteVector& SKprf, const ByteVector& opt_rand, const ByteVector& M,
             ByteVector& output) {

    // Obtener los parámetros actuales del config manager
    const SLH_DSA_Params* params = FIPS205ConfigManager::getCurrentParams();
    if (!params) {
        throw std::runtime_error("SLH_DSA_Params not initialized. Call FIPS205ConfigManager::initialize() first.");
    }

    // Output length is n from the parameters
    size_t outputLen = params->n;
    return concatenateAndHash({SKprf, opt_rand, M}, output, outputLen);
}

bool F(const ByteVector& PKseed, const ByteVector& ADRS, const ByteVector& M1,
       ByteVector& output) {

    // Obtener los parámetros actuales del config manager
    const SLH_DSA_Params* params = FIPS205ConfigManager::getCurrentParams();
    if (!params) {
        throw std::runtime_error("SLH_DSA_Params not initialized. Call FIPS205ConfigManager::initialize() first.");
    }

    // Output length is n from the parameters
    size_t outputLen = params->n;
    return concatenateAndHash({PKseed, ADRS, M1}, output, outputLen);
}

bool H(const ByteVector& PKseed, const ByteVector& ADRS, const ByteVector& M2,
       ByteVector& output) {

    // Obtener los parámetros actuales del config manager
    const SLH_DSA_Params* params = FIPS205ConfigManager::getCurrentParams();
    if (!params) {
        throw std::runtime_error("SLH_DSA_Params not initialized. Call FIPS205ConfigManager::initialize() first.");
    }

    // Output length is n from the parameters
    size_t outputLen = params->n;
    return concatenateAndHash({PKseed, ADRS, M2}, output, outputLen);
}

bool T_l(const ByteVector& PKseed, const ByteVector& ADRS, std::vector<ByteVector> Ml,
         ByteVector& output) {

    // Obtener los parámetros actuales del config manager
    const SLH_DSA_Params* params = FIPS205ConfigManager::getCurrentParams();
    if (!params) {
        throw std::runtime_error("SLH_DSA_Params not initialized. Call FIPS205ConfigManager::initialize() first.");
    }

    // Comprobamos que Ml no esta vacio / es nulo
    if (Ml.empty()) return false ;

    // Primero concatenamos todos los ByteVector en Ml
    ByteVector concatenated_Ml;
    for (const auto& vec : Ml) {
        concatenated_Ml.insert(concatenated_Ml.end(), vec.begin(), vec.end());
    }

    // Output length is n from the parameters
    size_t outputLen = params->n;
    return concatenateAndHash({PKseed, ADRS, concatenated_Ml}, output, outputLen);
}


// Funciones de conversión
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
           (static_cast<uint32_t>(bytes[offset+3]));
}

// Implementación de ADRS

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

// Algoritmo 1: gen_len2
uint32_t gen_len2(uint64_t n, uint64_t lg_w) {
    uint64_t w = 1ULL << lg_w;  // w = 2^lg_w
    uint64_t len1 = (8 * n + lg_w - 1) / lg_w;
    uint64_t max_checksum = len1 * (w - 1);
    uint64_t len2 = 1;
    uint64_t capacity = w;

    while (capacity <= max_checksum) {
        len2 += 1;
        capacity *= w;
    }

    return len2;
}

// Algoritmo 2: toInt
uint32_t toInt(const ByteVector& X, uint64_t n) {
    if (X.size() < n) {
        throw std::invalid_argument("Input array is too short");
    }

    uint64_t total = 0;
    for (uint64_t i = 0; i < n; ++i) {
        total = 256 * total + static_cast<uint64_t>(X[i]);
    }
    return total;
}

// Algoritmo 3: toByte
// Devuelve el residuo (el byte menos significativo) y modifica el vector
uint8_t divmod256(ByteVector& num) {
    uint16_t carry = 0;
    for (size_t i = num.size(); i-- > 0;){
        uint16_t cur = (carry << 8) | num[i];
        num[i] = static_cast<uint8_t>(cur / 256);
        carry = cur % 256;
    }
    return static_cast<uint8_t>(carry);
}

ByteVector toByte(const ByteVector& X, uint64_t n) {
    ByteVector S(n, 0);
    ByteVector total = X; // copia de X

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

    int required_bytes = (out_len * b + 7) / 8;
    if (X.size() < required_bytes) {
        throw std::invalid_argument("Input byte array X is too short for requested output length");
    }

    std::vector<uint32_t> baseb(out_len);
    size_t in = 0;     // Input byte index
    int bits = 0;      // Bits currently in total
    uint32_t total = 0; // Accumulated bits

    for (int out = 0; out < out_len; out++) {
        // Accumulate bits until we have enough
        while (bits < b) {
            if (in >= X.size()) {
                break;  // End of input data
            }
            total = (total << 8) | X[in];
            in++;
            bits += 8;
        }

        // Extract the b most significant bits
        bits -= b;
        baseb[out] = (total >> bits) & ((1U << b) - 1);
        total &= (1U << bits) - 1; // Clear the used bits
    }

    return baseb;
}

// Algoritmo 5: chain(X, i, s, PK.seed, ADRS)
ByteVector chain(ByteVector X, uint32_t i, uint32_t s, const ByteVector& PKseed, ADRS adrs) {
    // If s is 0, return X
    if (s == 0) {
        return X;
    }

    // temp = X
    ByteVector temp = X;

    // For j from i to i+s-1
    for (uint32_t j = i; j < i + s; j++) {
        // Set hash address
        adrs.setHashAddress(j);

        // temp = F(PK.seed, ADRS, temp)
        ByteVector result;
        if (!F(PKseed, adrs.toVector(), temp, result)) {
            throw std::runtime_error("Error en F durante chain");
        }
        temp = result;
    }

    return temp;
}
// Algoritmo 6: wots_pkGen(SK.seed, PK.seed, ADRS) modificado
ByteVector wots_pkGen(const ByteVector& SKseed, const ByteVector& PKseed, ADRS adrs) {

    // Obtener los parámetros actuales del config manager
    const SLH_DSA_Params* params = FIPS205ConfigManager::getCurrentParams();
    if (!params) {
        throw std::runtime_error("SLH_DSA_Params not initialized. Call FIPS205ConfigManager::initialize() first.");
    }

    // Obtener todos los parámetros necesarios del objeto params global
    const size_t n = params->n;
    const uint32_t lg_w = params->lg_w;

    // Calcular len1 y len2 según las ecuaciones (5.2) y (5.3)
    const size_t len1 = (8 * n + lg_w - 1) / lg_w;  // ⌈8n / log2(w)⌉
    const size_t len2 = gen_len2(n, lg_w);
    const size_t len = len1 + len2;  // Ecuación (5.4)

    // Create a copy of ADRS for key generation
    ADRS skADRS = adrs;

    // Set type to WOTS_PRF
    skADRS.setTypeAndClear(WOTS_PRF);

    // Set key pair address
    skADRS.setKeyPairAddress(adrs.getKeyPairAddress());

    // Create temporary storage for public values
    std::vector<ByteVector> tmp(len);

    // For i from 0 to len-1
    for (size_t i = 0; i < len; i++) {
        // Set chain address
        skADRS.setChainAddress(i);

        // Generate secret value for chain i
        ByteVector sk;
        if (!PRF(PKseed, SKseed, skADRS.toVector(), sk)) {
            throw std::runtime_error("Error en PRF durante wots_pkGen");
        }

        // Set chain address in ADRS (for chain function)
        adrs.setChainAddress(i);

        // La w es 2^lg_w como se define en la ecuación (5.1)
        const uint32_t w = 1 << lg_w;
        tmp[i] = chain(sk, 0, w - 1, PKseed, adrs);
    }

    // Create WOTS+ public key address
    ADRS wotsADRS = adrs;
    wotsADRS.setTypeAndClear(WOTS_PK);
    wotsADRS.setKeyPairAddress(adrs.getKeyPairAddress());

    // El tamaño de la clave pública es n bytes
    ByteVector pk(n);
    if (!T_l(PKseed, wotsADRS.toVector(), tmp, pk)) {
        throw std::runtime_error("Error en T_l durante wots_pkGen");
    }

    return pk;
}

// Algoritmo 7: wots_sign(M, SK.seed, PK.seed, ADRS)
ByteVector wots_sign(const ByteVector& M, const ByteVector& SKseed, const ByteVector& PKseed, ADRS adrs) {

    // Obtener los parámetros actuales del config manager
    const SLH_DSA_Params* params = FIPS205ConfigManager::getCurrentParams();
    if (!params) {
        throw std::runtime_error("SLH_DSA_Params not initialized. Call FIPS205ConfigManager::initialize() first.");
    }

    // Obtener los parámetros necesarios del esquema configurado
    const size_t n = params->n;
    const uint32_t w = 1 << params->lg_w;  // w = 2^lg_w
    const uint32_t lg_w = params->lg_w;

    // Calcular len1 y len2 según algoritmos 1 y 2
    const size_t len1 = (8 * n + lg_w - 1) / lg_w;  // ⌈8n / log2(w)⌉
    const size_t len2 = gen_len2(n, lg_w);
    const size_t len = len1 + len2;

    // Inicializar checksum
    uint32_t csum = 0;

    // Convertir mensaje a base w
    std::vector<uint32_t> msg_base_w = base_2b(M, lg_w, static_cast<int>(len1));

    // Calcular checksum
    for (size_t i = 0; i < len1; i++) {
        csum += w - 1 - msg_base_w[i];
    }

    // Ajustar el checksum según el algoritmo (shift left)
    uint32_t shift_amount = (8 - ((len2 * lg_w) % 8)) % 8;
    csum = (csum << shift_amount) % (1 << (len2 * lg_w));

    // Convertir checksum a bytes
    ByteVector csum_bytes;
    size_t csum_byte_len = (len2 * lg_w + 7) / 8; // ⌈(len2 * lg_w) / 8⌉
    for (size_t i = csum_byte_len - 1; i >= 0; i--) {
        csum_bytes.insert(csum_bytes.begin(), static_cast<uint8_t>(csum & 0xFF));
        csum >>= 8;
    }

    // Convertir checksum a base w
    std::vector<uint32_t> csum_base_w = base_2b(csum_bytes, lg_w, len2);

    // Crear el mensaje completo (msg || csum)
    std::vector<uint32_t> msg_complete(len);
    for (size_t i = 0; i < len1; i++) {
        msg_complete[i] = msg_base_w[i];
    }
    for (size_t i = 0; i < len2; i++) {
        msg_complete[len1 + i] = csum_base_w[i];
    }

    // Crear una copia de ADRS para la generación de claves
    ADRS skADRS = adrs;

    // Establecer tipo a WOTS_PRF
    skADRS.setTypeAndClear(WOTS_PRF);

    // Establecer dirección del par de claves
    skADRS.setKeyPairAddress(adrs.getKeyPairAddress());

    // Inicializar la firma
    ByteVector sig(len * n);

    // Generar la firma
    for (size_t i = 0; i < len; i++) {
        // Establecer chain address
        skADRS.setChainAddress(i);

        // Calcular el valor secreto para la cadena i
        ByteVector sk;
        if (!PRF(PKseed, SKseed, skADRS.toVector(), sk)) {
            throw std::runtime_error("Error en PRF durante wots_sign");
        }

        // Establecer chain address en ADRS para la función chain
        adrs.setChainAddress(i);

        // Calcular el valor de firma para la cadena i usando msg_complete[i]
        ByteVector sig_part = chain(sk, 0, msg_complete[i], PKseed, adrs);

        // Copiar este valor a la posición correspondiente en sig
        std::copy(sig_part.begin(), sig_part.end(), sig.begin() + i * n);
    }

    return sig;
}
// Algoritmo 8: wots_pkFromSig(sig, M, PK.seed, ADRS)
ByteVector wots_pkFromSig(const ByteVector& sig, const ByteVector& M, const ByteVector& PKseed, ADRS adrs) {

    // Obtener los parámetros actuales del config manager
    const SLH_DSA_Params* params = FIPS205ConfigManager::getCurrentParams();
    if (!params) {
        throw std::runtime_error("SLH_DSA_Params not initialized. Call FIPS205ConfigManager::initialize() first.");
    }

    // Obtener los parámetros necesarios del esquema configurado
    const size_t n = params->n;
    const uint32_t w = 1 << params->lg_w;  // w = 2^lg_w
    const uint32_t lg_w = params->lg_w;

    // Calcular len1 y len2 según algoritmos 1 y 2
    const size_t len1 = (8 * n + lg_w - 1) / lg_w;  // ⌈8n / log2(w)⌉
    const size_t len2 = gen_len2(n, lg_w);
    const size_t len = len1 + len2;

    // Verificar tamaño de la firma
    if (sig.size() != len * n) {
        throw std::invalid_argument("Tamaño de firma incorrecto para wots_pkFromSig");
    }

    // Inicializar checksum
    uint32_t csum = 0;

    // Convertir mensaje a base w
    std::vector<uint32_t> msg_base_w = base_2b(M, lg_w, len1);

    // Calcular checksum
    for (size_t i = 0; i < len1; i++) {
        csum += w - 1 - msg_base_w[i];
    }

    // Ajustar el checksum según el algoritmo (shift left)
    uint32_t shift_amount = (8 - ((len2 * lg_w) % 8)) % 8;
    csum = (csum << shift_amount) % (1 << (len2 * lg_w));

    // Convertir checksum a bytes
    ByteVector csum_bytes;
    size_t csum_byte_len = (len2 * lg_w + 7) / 8; // ⌈(len2 * lg_w) / 8⌉
    for (int i = csum_byte_len - 1; i >= 0; i--) {
        csum_bytes.insert(csum_bytes.begin(), static_cast<uint8_t>(csum & 0xFF));
        csum >>= 8;
    }

    // Convertir checksum a base w
    std::vector<uint32_t> csum_base_w = base_2b(csum_bytes, lg_w, len2);

    // Crear el mensaje completo (msg || csum)
    std::vector<uint32_t> msg_complete(len);
    for (size_t i = 0; i < len1; i++) {
        msg_complete[i] = msg_base_w[i];
    }
    for (size_t i = 0; i < len2; i++) {
        msg_complete[len1 + i] = csum_base_w[i];
    }

    // Crear una copia de ADRS para la verificación
    ADRS pkADRS = adrs;

    // Vector temporal para almacenar las partes de la clave pública reconstruida
    std::vector<ByteVector> tmp(len);

    // Procesar cada parte de la firma
    for (size_t i = 0; i < len; i++) {
        // Extraer la parte i-ésima de la firma
        ByteVector sig_i(sig.begin() + i * n, sig.begin() + (i + 1) * n);

        // Establecer chain address en ADRS
        pkADRS.setChainAddress(i);

        // Calcular la parte correspondiente de la clave pública
        // tmp[i] <- chain(sig[i], msg[i], w-1-msg[i], PK.seed, ADRS)
        tmp[i] = chain(sig_i, msg_complete[i], w - 1 - msg_complete[i], PKseed, pkADRS);
    }

    // Crear dirección para la clave pública WOTS+
    ADRS wotsADRS = adrs;
    wotsADRS.setTypeAndClear(WOTS_PK);
    wotsADRS.setKeyPairAddress(adrs.getKeyPairAddress());

    // Comprimir los resultados para obtener la clave pública
    ByteVector pk(n);
    if (!T_l(PKseed, wotsADRS.toVector(), tmp, pk)) {
        throw std::runtime_error("Error en T_l durante wots_pkFromSig");
    }

    return pk;
}
// Algoritmo 9: xmss_node(SK.seed, i, z, PK.seed, ADRS) mejorado
ByteVector xmss_node(const ByteVector& SKseed, uint32_t i, uint32_t z, const ByteVector& PKseed, ADRS adrs) {
    // Inicializar nodo
    ByteVector node;

    // Si z = 0, calcular la clave pública WOTS+ directamente
    if (z == 0) {
        // Establecer dirección del par de claves sin modificar el tipo
        adrs.setKeyPairAddress(i);

        // Generar la clave pública WOTS+ pasando los parámetros desde la estructura global
        node = wots_pkGen(SKseed, PKseed, adrs);
    }
        // Si z > 0, calcular nodo interno del árbol
    else {
        // Calcular nodo izquierdo
        ByteVector lnode = xmss_node(SKseed, 2*i, z-1, PKseed, adrs);

        // Calcular nodo derecho
        ByteVector rnode = xmss_node(SKseed, 2*i+1, z-1, PKseed, adrs);

        // Configurar ADRS para nodo interno del árbol
        adrs.setTypeAndClear(WOTS_TREES);

        // Establecer altura del árbol
        adrs.setTreeHeight(z);

        // Establecer índice del árbol
        adrs.setTreeIndex(i);

        // Concatenar correctamente los nodos izquierdo y derecho
        ByteVector combined;
        combined.reserve(lnode.size() + rnode.size());
        combined.insert(combined.end(), lnode.begin(), lnode.end());
        combined.insert(combined.end(), rnode.begin(), rnode.end());

        // Aplicar la función hash H
        if (!H(PKseed, adrs.toVector(), combined, node)) {
            throw std::runtime_error("Error en H durante xmss_node");
        }
    }

    return node;
}
// Algoritmo 10: xmss_sign(M, SK.seed, idx, PK.seed, ADRS)
ByteVector xmss_sign(const ByteVector& M, const ByteVector& SKseed, uint32_t idx,
                     const ByteVector& PKseed, ADRS adrs) {

    // Obtener los parámetros actuales del config manager
    const SLH_DSA_Params* params = FIPS205ConfigManager::getCurrentParams();
    if (!params) {
        throw std::runtime_error("SLH_DSA_Params not initialized. Call FIPS205ConfigManager::initialize() first.");
    }

    // Obtener parámetros del esquema configurado
    const uint32_t h_prima = params->h_prima; // altura del árbol XMSS

    // Paso 1-4: Construir el camino de autenticación (AUTH)
    std::vector<ByteVector> AUTH(h_prima);
    for (uint32_t j = 0; j < h_prima; j++) {
        // Calcular k según la fórmula: k ← ⌊idx/2^j⌋ ⊕ 1
        uint32_t k = (idx >> j) ^ 1;

        // Obtener el nodo de autenticación usando xmss_node
        AUTH[j] = xmss_node(SKseed, k, j, PKseed, adrs);
    }

    // Paso 5-6: Preparar ADRS para la firma WOTS+
    adrs.setTypeAndClear(WOTS_HASH);
    adrs.setKeyPairAddress(idx);

    // Paso 7: Generar la firma WOTS+ del mensaje
    ByteVector sig = wots_sign(M, SKseed, PKseed, adrs);

    // Paso 8-9: Construir la firma XMSS completa (sig || AUTH)
    // Calcular el tamaño total de AUTH
    size_t auth_size = 0;
    for (const auto& auth_node : AUTH) {
        auth_size += auth_node.size();
    }

    // Reservar espacio para la firma completa
    ByteVector SIG_XMSS;
    SIG_XMSS.reserve(sig.size() + auth_size);

    // Agregar la firma WOTS+
    SIG_XMSS.insert(SIG_XMSS.end(), sig.begin(), sig.end());

    // Agregar el camino de autenticación
    for (const auto& auth_node : AUTH) {
        SIG_XMSS.insert(SIG_XMSS.end(), auth_node.begin(), auth_node.end());
    }

    return SIG_XMSS;
}
// Algoritmo 11: xmss_pkFromSig(idx, SIG_XMSS, M, PK.seed, ADRS)
ByteVector xmss_pkFromSig(uint32_t idx, const ByteVector& SIG_XMSS,
                          const ByteVector& M, const ByteVector& PKseed, ADRS adrs) {

    // Obtener los parámetros actuales del config manager
    const SLH_DSA_Params* params = FIPS205ConfigManager::getCurrentParams();
    if (!params) {
        throw std::runtime_error("SLH_DSA_Params not initialized. Call FIPS205ConfigManager::initialize() first.");
    }

    // Obtener parámetros del esquema configurado
    const size_t n = params->n;         // Tamaño en bytes del nivel de seguridad
    const uint32_t h_prima = params->h_prima; // Altura del árbol XMSS

    // Calcular la longitud de la firma WOTS+
    const uint32_t lg_w = params->lg_w;
    const size_t len1 = (8 * n + lg_w - 1) / lg_w;  // ⌈8n / log2(w)⌉
    const size_t len2 = gen_len2(n, lg_w);
    const size_t len = len1 + len2;  // Ecuación (5.4)

    // Calcular tamaño de la firma WOTS+
    const size_t wots_sig_size = len * n;

    // Paso 1-2: Preparar ADRS para obtener la clave pública WOTS+
    adrs.setTypeAndClear(WOTS_HASH);
    adrs.setKeyPairAddress(idx);

    // Paso 3-4: Extraer la firma WOTS+ y el camino de autenticación AUTH de SIG_XMSS
    // La firma WOTS+ es la primera parte de SIG_XMSS de tamaño len * n
    ByteVector sig(SIG_XMSS.begin(), SIG_XMSS.begin() + wots_sig_size);

    // El camino de autenticación AUTH está compuesto por h_prima nodos, cada uno de tamaño n
    std::vector<ByteVector> AUTH(h_prima);
    for (uint32_t i = 0; i < h_prima; i++) {
        size_t offset = wots_sig_size + i * n;
        AUTH[i] = ByteVector(SIG_XMSS.begin() + offset, SIG_XMSS.begin() + offset + n);
    }

    // Paso 5: Computar la clave pública WOTS+ a partir de la firma
    std::vector<ByteVector> node(2); // Necesitamos dos nodos para cálculos intermedios
    node[0] = wots_pkFromSig(sig, M, PKseed, adrs);

    // Paso 6-18: Calcular la raíz desde la clave pública WOTS+ y AUTH
    adrs.setTypeAndClear(WOTS_TREES);
    adrs.setTreeIndex(idx);

    for (uint32_t k = 0; k < h_prima; k++) {
        adrs.setTreeHeight(k + 1);

        if ((idx >> k) % 2 == 0) { // Si idx/2^k es par
            adrs.setTreeIndex(adrs.getTreeIndex() / 2);

            // Concatenar node[0] || AUTH[k]
            ByteVector concatenated;
            concatenated.reserve(node[0].size() + AUTH[k].size());
            concatenated.insert(concatenated.end(), node[0].begin(), node[0].end());
            concatenated.insert(concatenated.end(), AUTH[k].begin(), AUTH[k].end());

            // node[1] ← H(PK.seed, ADRS, node[0] || AUTH[k])
            if (!H(PKseed, adrs.toVector(), concatenated, node[1])) {
                throw std::runtime_error("Error en H durante xmss_pkFromSig");
            }
        } else { // Si idx/2^k es impar
            adrs.setTreeIndex((adrs.getTreeIndex() - 1) / 2);

            // Concatenar AUTH[k] || node[0]
            ByteVector concatenated;
            concatenated.reserve(AUTH[k].size() + node[0].size());
            concatenated.insert(concatenated.end(), AUTH[k].begin(), AUTH[k].end());
            concatenated.insert(concatenated.end(), node[0].begin(), node[0].end());

            // node[1] ← H(PK.seed, ADRS, AUTH[k] || node[0])
            if (!H(PKseed, adrs.toVector(), concatenated, node[1])) {
                throw std::runtime_error("Error en H durante xmss_pkFromSig");
            }
        }

        // node[0] ← node[1]
        node[0] = node[1];
    }

    // Paso 19: Devolver el nodo raíz
    return node[0];
}
// Algoritmo 12: ht_sign(M, SK.seed, PK.seed, idx_tree, idx_leaf)
ByteVector ht_sign(const ByteVector& M, const ByteVector& SKseed, const ByteVector& PKseed,
                   uint32_t idx_tree, uint32_t idx_leaf) {

    // Obtener los parámetros actuales del config manager
    const SLH_DSA_Params* params = FIPS205ConfigManager::getCurrentParams();
    if (!params) {
        throw std::runtime_error("SLH_DSA_Params not initialized. Call FIPS205ConfigManager::initialize() first.");
    }

    // Obtener parámetros relevantes del esquema configurado
    const uint32_t d = params->d;           // Número de capas en el árbol híper
    const uint32_t h_prima = params->h_prima; // Altura de cada árbol XMSS

    // Paso 1: Inicializar ADRS
    ADRS adrs;  // Por defecto se inicializa con ceros

    // Paso 2: Establecer la dirección del árbol
    adrs.setTreeAddress(reinterpret_cast<const uint8_t*>(&idx_tree));

    // Paso 3: Generar la firma XMSS para la capa 0
    ByteVector SIG_tmp = xmss_sign(M, SKseed, idx_leaf, PKseed, adrs);

    // Paso 4: Inicializar la firma HT con la firma XMSS de la capa 0
    ByteVector SIG_HT = SIG_tmp;

    // Paso 5: Calcular la raíz del árbol XMSS actual
    ByteVector root = xmss_pkFromSig(idx_leaf, SIG_tmp, M, PKseed, adrs);

    // Pasos 6-16: Procesar cada capa del árbol híper
    for (uint32_t j = 1; j < d; j++) {
        // Paso 7: Calcular el índice de hoja para esta capa
        uint32_t idx_leaf_j = idx_tree & ((1 << h_prima) - 1);  // idx_tree mod 2^h'

        // Paso 8: Actualizar el índice del árbol eliminando los bits usados
        idx_tree = idx_tree >> h_prima;  // Eliminar los h' bits menos significativos

        // Paso 9: Establecer la dirección de capa
        adrs.setLayerAddress(j);

        // Paso 10: Actualizar la dirección del árbol
        adrs.setTreeAddress(reinterpret_cast<const uint8_t*>(&idx_tree));

        // Paso 11: Generar la firma XMSS para la capa actual usando la raíz anterior como mensaje
        SIG_tmp = xmss_sign(root, SKseed, idx_leaf_j, PKseed, adrs);

        // Paso 12: Concatenar la firma XMSS actual a la firma HT
        SIG_HT.insert(SIG_HT.end(), SIG_tmp.begin(), SIG_tmp.end());

        // Pasos 13-15: Si no es la última capa, calcular la raíz para la siguiente iteración
        if (j < d - 1) {
            root = xmss_pkFromSig(idx_leaf_j, SIG_tmp, root, PKseed, adrs);
        }
    }

    // Paso 17: Devolver la firma HT completa
    return SIG_HT;
}

// Algoritmo 13: ht_verify(M, SIG_HT, PK.seed, idx_tree, idx_leaf, PK.root)
bool ht_verify(const ByteVector& M, const ByteVector& SIG_HT, const ByteVector& PKseed,
               uint32_t idx_tree, uint32_t idx_leaf, const ByteVector& PKroot) {

    // Obtener los parámetros actuales del config manager
    const SLH_DSA_Params* params = FIPS205ConfigManager::getCurrentParams();
    if (!params) {
        throw std::runtime_error("SLH_DSA_Params not initialized. Call FIPS205ConfigManager::initialize() first.");
    }

    // Obtener parámetros relevantes del esquema configurado
    const size_t n = params->n;         // Tamaño en bytes del nivel de seguridad
    const uint32_t d = params->d;       // Número de capas en el árbol híper
    const uint32_t h_prima = params->h_prima; // Altura de cada árbol XMSS

    // Paso 1: Inicializar ADRS
    ADRS adrs;  // Por defecto se inicializa con ceros (toByte(0, 32))

    // Paso 2: Establecer la dirección del árbol
    adrs.setTreeAddress(reinterpret_cast<const uint8_t*>(&idx_tree));

    // Calcular el tamaño de la firma XMSS (para extraerla de SIG_HT)
    const uint32_t lg_w = params->lg_w;
    const size_t len1 = (8 * n + lg_w - 1) / lg_w;
    const size_t len2 = gen_len2(n, lg_w);
    const size_t len = len1 + len2;
    const size_t wots_sig_size = len * n;
    const size_t xmss_sig_size = wots_sig_size + h_prima * n;  // firma WOTS+ + camino AUTH

    // Paso 3: Extraer la primera firma XMSS (de la capa 0)
    // SIG_tmp ← SIG_HT.getXMSSSignature(0)  [0 : (h' + len) · n]
    ByteVector SIG_tmp(SIG_HT.begin(), SIG_HT.begin() + xmss_sig_size);

    // Paso 4: Computar la raíz del árbol XMSS usando la firma y el mensaje
    ByteVector node = xmss_pkFromSig(idx_leaf, SIG_tmp, M, PKseed, adrs);

    // Pasos 5-12: Recorrer las capas restantes del árbol híper
    for (uint32_t j = 1; j < d; j++) {
        // Paso 6: Calcular el índice de hoja para esta capa
        // idx_leaf ← idx_tree mod 2^h'  [h' least significant bits of idx_tree]
        uint32_t idx_leaf_j = idx_tree & ((1 << h_prima) - 1);

        // Paso 7: Actualizar el índice del árbol eliminando los bits usados
        // idx_tree ← idx_tree >> h'  [remove least significant h' bits from idx_tree]
        idx_tree = idx_tree >> h_prima;

        // Paso 8: Establecer la dirección de capa
        adrs.setLayerAddress(j);

        // Paso 9: Actualizar la dirección del árbol
        adrs.setTreeAddress(reinterpret_cast<const uint8_t*>(&idx_tree));

        // Paso 10: Extraer la firma XMSS para la capa j
        // SIG_tmp ← SIG_HT.getXMSSSignature(j)  [SIG_HT[j · (h' + len) · n : (j + 1)(h' + len) · n]]
        size_t offset = j * xmss_sig_size;
        SIG_tmp = ByteVector(SIG_HT.begin() + offset,
                             SIG_HT.begin() + offset + xmss_sig_size);

        // Paso 11: Calcular la raíz usando node (raíz anterior) como mensaje
        node = xmss_pkFromSig(idx_leaf_j, SIG_tmp, node, PKseed, adrs);
    }

    // Paso 13-17: Verificar si la raíz calculada coincide con la raíz pública
    if (node == PKroot) {
        return true;
    } else {
        return false;
    }
}

// Algoritmo 14: fors_skGen(SK.seed, PK.seed, ADRS, idx)
ByteVector fors_skGen(const ByteVector& SKseed, const ByteVector& PKseed, ADRS adrs, uint32_t idx) {

    // Obtener los parámetros actuales del config manager
    const SLH_DSA_Params* params = FIPS205ConfigManager::getCurrentParams();
    if (!params) {
        throw std::runtime_error("SLH_DSA_Params not initialized. Call FIPS205ConfigManager::initialize() first.");
    }

    // Obtener el tamaño del valor secreto (n bytes) del esquema configurado
    const size_t n = params->n;

    // Paso 1: Copiar la dirección para crear la dirección de generación de claves
    ADRS skADRS = adrs;

    // Paso 2: Establecer el tipo FORS_PRF y limpiar los bytes restantes
    skADRS.setTypeAndClear(FORS_PRF);

    // Paso 3: Establecer la dirección del par de claves
    skADRS.setKeyPairAddress(adrs.getKeyPairAddress());

    // Paso 4: Establecer el índice del árbol
    skADRS.setTreeIndex(idx);

    // Paso 5: Generar y devolver el valor secreto usando PRF
    ByteVector sk(n);
    if (!PRF(PKseed, SKseed, skADRS.toVector(), sk)) {
        throw std::runtime_error("Error en PRF durante fors_skGen");
    }

    return sk;
}

// Algoritmo 15: fors_node(SK.seed, i, z, PK.seed, ADRS)
ByteVector fors_node(const ByteVector& SKseed, uint32_t i, uint32_t z,
                     const ByteVector& PKseed, ADRS adrs) {

    // Obtener los parámetros actuales del config manager
    const SLH_DSA_Params* params = FIPS205ConfigManager::getCurrentParams();
    if (!params) {
        throw std::runtime_error("SLH_DSA_Params not initialized. Call FIPS205ConfigManager::initialize() first.");
    }

    // Obtener el tamaño del valor secreto (n bytes) del esquema configurado
    const size_t n = params->n;

    // Inicializar el nodo a devolver
    ByteVector node;

    // Paso 1-5: Si estamos en un nodo hoja (z = 0)
    if (z == 0) {
        // Paso 2: Generar el valor secreto del FORS
        ByteVector sk = fors_skGen(SKseed, PKseed, adrs, i);

        // Paso 3: Establecer la altura del árbol en 0
        adrs.setTreeHeight(0);

        // Paso 4: Establecer el índice del árbol
        adrs.setTreeIndex(i);

        // Paso 5: Aplicar la función F para obtener el valor público
        if (!F(PKseed, adrs.toVector(), sk, node)) {
            throw std::runtime_error("Error en F durante fors_node");
        }
    }
        // Paso 6-11: Si estamos en un nodo interno (z > 0)
    else {
        // Paso 7: Calcular el nodo izquierdo de manera recursiva
        ByteVector lnode = fors_node(SKseed, 2*i, z-1, PKseed, adrs);

        // Paso 8: Calcular el nodo derecho de manera recursiva
        ByteVector rnode = fors_node(SKseed, 2*i+1, z-1, PKseed, adrs);

        // Paso 9: Establecer la altura del árbol
        adrs.setTreeHeight(z);

        // Paso 10: Establecer el índice del árbol
        adrs.setTreeIndex(i);

        // Paso 11: Concatenar los nodos izquierdo y derecho, y aplicar la función H
        ByteVector concatenated;
        concatenated.reserve(lnode.size() + rnode.size());
        concatenated.insert(concatenated.end(), lnode.begin(), lnode.end());
        concatenated.insert(concatenated.end(), rnode.begin(), rnode.end());

        if (!H(PKseed, adrs.toVector(), concatenated, node)) {
            throw std::runtime_error("Error en H durante fors_node");
        }
    }

    // Paso 13: Devolver el nodo calculado
    return node;
}
// Algoritmo 16: fors_sign(md, SK.seed, PK.seed, ADRS)
ByteVector fors_sign(const ByteVector& md, const ByteVector& SKseed,
                     const ByteVector& PKseed, ADRS adrs) {

    // Obtener los parámetros actuales del config manager
    const SLH_DSA_Params* params = FIPS205ConfigManager::getCurrentParams();
    if (!params) {
        throw std::runtime_error("SLH_DSA_Params not initialized. Call FIPS205ConfigManager::initialize() first.");
    }

    // Obtener parámetros relevantes del esquema configurado
    const size_t n = params->n;         // Tamaño en bytes del nivel de seguridad
    const uint32_t k = params->k;       // Número de árboles en el bosque FORS
    const uint32_t a = params->a;       // Altura de cada árbol FORS (log2 de t)
    const uint32_t t = 1 << a;          // Número de hojas en cada árbol FORS (t = 2^a)

    // Paso 1: Inicializar SIG_FORS como una cadena de bytes vacía
    ByteVector SIG_FORS;

    // Paso 2: Obtener los índices a partir del resumen del mensaje
    // indices ← base_2^b(md, a, k)
    std::vector<uint32_t> indices = base_2b(md, a, k);

    // Preparar estructura para almacenar el camino de autenticación completo
    std::vector<ByteVector> AUTH;

    // Paso 3-10: Calcular los elementos de la firma para cada uno de los k árboles
    for (uint32_t i = 0; i < k; i++) {
        // Paso 4: Obtener el valor secreto correspondiente a este índice
        // SIG_FORS ← SIG_FORS || fors_skGen(SK.seed, PK.seed, ADRS, i·2^a + indices[i])
        uint32_t leaf_index = i * t + indices[i];
        ByteVector sk = fors_skGen(SKseed, PKseed, adrs, leaf_index);

        // Añadir el valor secreto a la firma
        SIG_FORS.insert(SIG_FORS.end(), sk.begin(), sk.end());

        // Pasos 5-8: Calcular el camino de autenticación para este valor secreto
        for (uint32_t j = 0; j < a; j++) {
            // Paso 6: Calcular s, el índice del nodo hermano en este nivel
            // s ← ⌊indices[i]/2^j⌋ ⊕ 1
            uint32_t s = (indices[i] >> j) ^ 1;

            // Paso 7: Calcular el nodo de autenticación
            // AUTH[j] ← fors_node(SK.seed, i·2^(a-j) + s, j, PK.seed, ADRS)
            uint32_t node_index = i * (t >> j) + s;
            ByteVector auth_node = fors_node(SKseed, node_index, j, PKseed, adrs);

            // Añadir el nodo de autenticación al vector AUTH temporal
            AUTH.push_back(auth_node);
        }
    }

    // Paso 9: Añadir todos los nodos de autenticación a la firma
    for (const auto& auth_node : AUTH) {
        SIG_FORS.insert(SIG_FORS.end(), auth_node.begin(), auth_node.end());
    }

    // Paso 11: Devolver la firma FORS completa
    return SIG_FORS;
}

// Algoritmo 17: fors_pkFromSig(SIG_FORS, md, PK.seed, ADRS)
ByteVector fors_pkFromSig(const ByteVector& SIG_FORS, const ByteVector& md,
                          const ByteVector& PKseed, ADRS adrs) {

    // Obtener los parámetros actuales del config manager
    const SLH_DSA_Params* params = FIPS205ConfigManager::getCurrentParams();
    if (!params) {
        throw std::runtime_error("SLH_DSA_Params not initialized. Call FIPS205ConfigManager::initialize() first.");
    }

    // Obtener parámetros relevantes del esquema configurado
    const size_t n = params->n;         // Tamaño en bytes del nivel de seguridad
    const uint32_t k = params->k;       // Número de árboles en el bosque FORS
    const uint32_t a = params->a;       // Altura de cada árbol FORS (log2 de t)
    const uint32_t t = 1 << a;          // Número de hojas en cada árbol FORS (t = 2^a)

    // Paso 1: Obtener los índices a partir del resumen del mensaje
    // indices ← base_2^b(md, a, k)
    std::vector<uint32_t> indices = base_2b(md, a, k);

    // Vector para almacenar las raíces de los k árboles
    std::vector<ByteVector> roots(k);

    // Calcular el tamaño de cada componente de la firma
    size_t sk_size = n;                // Tamaño del valor secreto
    size_t auth_size = a * n;          // Tamaño del camino de autenticación por árbol
    size_t tree_sig_size = sk_size + auth_size; // Tamaño total de la firma por árbol

    // Paso 2-20: Procesar cada uno de los k árboles
    for (uint32_t i = 0; i < k; i++) {
        // Paso 3: Extraer el valor secreto de la firma
        // sk ← SIG_FORS.getSK(i)  [SIG_FORS[i · (a + 1) · n : (i · (a + 1) + 1) · n]]
        size_t sk_offset = i * tree_sig_size;
        ByteVector sk(SIG_FORS.begin() + sk_offset, SIG_FORS.begin() + sk_offset + n);

        // Paso 4-5: Configurar ADRS para calcular el nodo hoja
        adrs.setTreeHeight(0);
        adrs.setTreeIndex(i * t + indices[i]);

        // Paso 6: Calcular el nodo hoja aplicando F al valor secreto
        std::vector<ByteVector> node(2); // Para almacenar nodos intermedios (índices 0 y 1)
        if (!F(PKseed, adrs.toVector(), sk, node[0])) {
            throw std::runtime_error("Error en F durante fors_pkFromSig");
        }

        // Paso 7: Extraer el camino de autenticación de la firma
        // auth ← SIG_FORS.getAUTH(i)  [SIG_FORS[(i · (a + 1) + 1) · n : (i + 1) · (a + 1) · n]]
        std::vector<ByteVector> auth(a);
        for (uint32_t j = 0; j < a; j++) {
            size_t auth_offset = sk_offset + n + j * n;
            auth[j] = ByteVector(SIG_FORS.begin() + auth_offset,
                                 SIG_FORS.begin() + auth_offset + n);
        }

        // Pasos 8-18: Reconstruir la raíz a partir del nodo hoja y el camino de autenticación
        for (uint32_t j = 0; j < a; j++) {
            // Paso 9: Establecer la altura del árbol
            adrs.setTreeHeight(j + 1);

            // Pasos 10-16: Calcular el nodo padre según la paridad del índice
            if ((indices[i] >> j) % 2 == 0) { // Si el índice es par
                // Pasos 11-12: El nodo actual está a la izquierda
                adrs.setTreeIndex(adrs.getTreeIndex() / 2);

                // Concatenar node[0] || auth[j]
                ByteVector concatenated;
                concatenated.reserve(node[0].size() + auth[j].size());
                concatenated.insert(concatenated.end(), node[0].begin(), node[0].end());
                concatenated.insert(concatenated.end(), auth[j].begin(), auth[j].end());

                if (!H(PKseed, adrs.toVector(), concatenated, node[1])) {
                    throw std::runtime_error("Error en H durante fors_pkFromSig");
                }
            } else { // Si el índice es impar
                // Pasos 14-15: El nodo actual está a la derecha
                adrs.setTreeIndex((adrs.getTreeIndex() - 1) / 2);

                // Concatenar auth[j] || node[0]
                ByteVector concatenated;
                concatenated.reserve(auth[j].size() + node[0].size());
                concatenated.insert(concatenated.end(), auth[j].begin(), auth[j].end());
                concatenated.insert(concatenated.end(), node[0].begin(), node[0].end());

                if (!H(PKseed, adrs.toVector(), concatenated, node[1])) {
                    throw std::runtime_error("Error en H durante fors_pkFromSig");
                }
            }

            // Paso 17: Actualizar node[0] para la siguiente iteración
            node[0] = node[1];
        }

        // Paso 19: Guardar la raíz calculada
        roots[i] = node[0];
    }

    // Pasos 21-23: Preparar ADRS para calcular la clave pública FORS
    ADRS forspkADRS = adrs;
    forspkADRS.setTypeAndClear(FORS_ROOTS);
    forspkADRS.setKeyPairAddress(adrs.getKeyPairAddress());

    // Paso 24: Calcular la clave pública FORS usando T_l (función de compresión de árboles)
    ByteVector pk;
    if (!T_l(PKseed, forspkADRS.toVector(), roots, pk)) {
        throw std::runtime_error("Error en T_l durante fors_pkFromSig");
    }

    // Paso 25: Devolver la clave pública
    return pk;
}
// Algoritmo 18: slh_keygen_internal con separación de claves
std::pair<SLH_DSA_PrivateKey, SLH_DSA_PublicKey> slh_keygen_internal(
        const ByteVector& SKseed, const ByteVector& SKprf, const ByteVector& PKseed) {

    // Obtener los parámetros actuales del config manager
    const SLH_DSA_Params* params = FIPS205ConfigManager::getCurrentParams();
    if (!params) {
        throw std::runtime_error("SLH_DSA_Params not initialized. Call FIPS205ConfigManager::initialize() first.");
    }

    // Obtener parámetros relevantes del esquema configurado
    const uint32_t d = params->d;
    const uint32_t h_prima = params->h_prima;

    // Inicializar ADRS
    ADRS adrs;
    adrs.setLayerAddress(d - 1);

    // Generar la raíz de la clave pública para el árbol XMSS de nivel superior
    ByteVector PKroot = xmss_node(SKseed, 0, h_prima, PKseed, adrs);

    // Crear claves privada y pública por separado
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

// Algoritmo 19: slh_sign_internal con la estructura de clave privada separada
SLH_DSA_Signature slh_sign_internal(const ByteVector& M,
                                    const SLH_DSA_PrivateKey& privateKey,
                                    const ByteVector& addrnd) {

    // Obtener los parámetros actuales del config manager
    const SLH_DSA_Params* params = FIPS205ConfigManager::getCurrentParams();
    if (!params) {
        throw std::runtime_error("SLH_DSA_Params not initialized. Call FIPS205ConfigManager::initialize() first.");
    }
    // Obtener parámetros relevantes
    const size_t n = params->n;
    const uint32_t k = params->k;
    const uint32_t a = params->a;
    const uint32_t h = params->h;
    const uint32_t d = params->d;
    const uint32_t h_prima = params->h_prima;

    // Paso 1: Inicializar ADRS
    ADRS adrs;

    // Paso 2: Determinar el valor de opt_rand
    ByteVector opt_rand = addrnd.empty() ? privateKey.pkSeed : addrnd;

    // Paso 3-4: Generar el aleatorizador R
    ByteVector R;
    if (!PRF_msg(privateKey.prf, opt_rand, M, R)) {
        throw std::runtime_error("Error en PRF_msg");
    }

    // Paso 5: Calcular el digest del mensaje
    ByteVector digest;
    if (!H_msg(R, privateKey.pkSeed, privateKey.pkRoot, M, digest)) {
        throw std::runtime_error("Error en H_msg");
    }

    // Paso 6: Extraer md para FORS
    const size_t md_bits = k * a;
    const size_t md_bytes = (md_bits + 7) / 8;
    ByteVector md(digest.begin(), digest.begin() + md_bytes);

    // Pasos 7-10: Calcular índices para el árbol
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

    // Pasos 11-14: Generar firma FORS
    adrs.setTreeAddress(reinterpret_cast<const uint8_t*>(&idx_tree));
    adrs.setTypeAndClear(FORS_TREE);
    adrs.setKeyPairAddress(idx_leaf);
    ByteVector SIG_FORS = fors_sign(md, privateKey.seed, privateKey.pkSeed, adrs);

    // Paso 16: Calcular la clave pública FORS
    ByteVector PK_FORS = fors_pkFromSig(SIG_FORS, md, privateKey.pkSeed, adrs);

    // Paso 17-18: Generar la firma HT
    ByteVector SIG_HT = ht_sign(PK_FORS, privateKey.seed, privateKey.pkSeed, idx_tree, idx_leaf);

    // Crear y devolver la estructura de firma
    SLH_DSA_Signature signature;
    signature.randomness = R;
    signature.forsSignature = SIG_FORS;
    signature.htSignature = SIG_HT;

    return signature;
}
// Algoritmo 20: slh_verify_internal
bool slh_verify_internal(const ByteVector& M, const ByteVector& SIG, const SLH_DSA_PublicKey& PK) {

    const SLH_DSA_Params* params = FIPS205ConfigManager::getCurrentParams();

    // Obtener parámetros relevantes
    const size_t n = params->n;
    const uint32_t k = params->k;
    const uint32_t a = params->a;
    const uint32_t h = params->h;
    const uint32_t d = params->d;
    const uint32_t h_prima = params->h_prima;
    const uint32_t lg_w = params->lg_w;

    // Calcular len para el tamaño de la firma
    const size_t len1 = (8 * n + lg_w - 1) / lg_w;
    const size_t len2 = gen_len2(n, lg_w);
    const size_t len = len1 + len2;

    // Paso 1-3: Verificar que el tamaño de la firma sea correcto
    if (SIG.size() != (1 + k * (1 + a) + h + d * len) * n) {
        return false;
    }

    // Paso 4: Inicializar ADRS
    ADRS adrs;

    // Paso 5-7: Extraer componentes de la firma
    ByteVector R(SIG.begin(), SIG.begin() + n);  // R ← SIG.getR()

    // SIG_FORS ← SIG.getSIG_FORS()
    size_t fors_offset = n;
    size_t fors_size = k * (1 + a) * n;
    ByteVector SIG_FORS(SIG.begin() + fors_offset, SIG.begin() + fors_offset + fors_size);

    // SIG_HT ← SIG.getSIG_HT()
    size_t ht_offset = fors_offset + fors_size;
    ByteVector SIG_HT(SIG.begin() + ht_offset, SIG.end());

    // Paso 8: Calcular el digest del mensaje
    ByteVector digest;
    if (!H_msg(R, PK.seed, PK.root, M, digest)) {
        return false;  // Error en H_msg
    }

    // Paso 9: Extraer md para FORS
    const size_t md_bits = k * a;
    const size_t md_bytes = (md_bits + 7) / 8;
    ByteVector md(digest.begin(), digest.begin() + md_bytes);

    // Pasos 10-13: Extraer índices para el árbol
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

    // Pasos 14-16: Configurar ADRS para calcular la clave pública FORS
    adrs.setTreeAddress(reinterpret_cast<const uint8_t*>(&idx_tree));
    adrs.setTypeAndClear(FORS_TREE);
    adrs.setKeyPairAddress(idx_leaf);

    // Paso 17: Calcular la clave pública FORS a partir de la firma
    ByteVector PK_FORS = fors_pkFromSig(SIG_FORS, md, PK.seed, adrs);

    // Paso 18: Verificar la firma HT y devolver el resultado
    return ht_verify(PK_FORS, SIG_HT, PK.seed, idx_tree, idx_leaf, PK.root);
}

// Algoritmo 21: slh_keygen
std::pair<SLH_DSA_PrivateKey, SLH_DSA_PublicKey> slh_keygen() {
    // Obtener los parámetros actuales del esquema SLH-DSA
    const SLH_DSA_Params* params = FIPS205ConfigManager::getCurrentParams();
    // Obtener el tamaño en bytes para las semillas (n)
    const size_t n = params->n;

    // Crear vectores para almacenar los bytes aleatorios
    ByteVector SKseed(n);
    ByteVector SKprf(n);
    ByteVector PKseed(n);

    // Generar valores aleatorios para SK.seed, SK.prf y PK.seed usando OpenSSL
    if (RAND_bytes(SKseed.data(), n) != 1 ||
        RAND_bytes(SKprf.data(), n) != 1 ||
        RAND_bytes(PKseed.data(), n) != 1) {
        // Error en la generación de bytes aleatorios
        throw std::runtime_error("Error generating secure random bytes with OpenSSL");
    }

    // Llamar a slh_keygen_internal para generar el par de claves
    return slh_keygen_internal(SKseed, SKprf, PKseed);
}

// Algoritmo 22: slh_sign - Genera una firma SLH-DSA pura
ByteVector slh_sign(const ByteVector& M, const ByteVector& ctx, const SLH_DSA_PrivateKey& SK) {
    // Paso 1-3: Verificar que el tamaño del contexto no sea demasiado grande
    if (ctx.size() > 255) {
        // Devolver un error si el contexto es demasiado largo
        throw std::invalid_argument("Context string is too long (must be <= 255 bytes)");
    }

    // Paso 4-7: Para la variante determinista, omitimos la generación de addrnd
    ByteVector addrnd;

    // En la variante no determinista, descomentar estas líneas:
    /*
    addrnd.resize(params->n);
    if (RAND_bytes(addrnd.data(), params->n) != 1) {
        // Error en la generación de bytes aleatorios
        throw std::runtime_error("Error generating secure random bytes for addrnd");
    }
    */

    // Paso 8: Construir M' concatenando toByte(0,1) || toByte(|ctx|,1) || ctx || M
    ByteVector M_prime;

    // Agregar toByte(0,1) - un byte con valor 0 que indica "mensaje"
    M_prime.push_back(0);

    // Agregar toByte(|ctx|,1) - un byte con la longitud del contexto
    M_prime.push_back(static_cast<uint8_t>(ctx.size()));

    // Agregar ctx - el contexto
    M_prime.insert(M_prime.end(), ctx.begin(), ctx.end());

    // Agregar M - el mensaje
    M_prime.insert(M_prime.end(), M.begin(), M.end());

    // Paso 9: Llamar a slh_sign_internal con M', SK y addrnd
    SLH_DSA_Signature signature = slh_sign_internal(M_prime, SK, addrnd);

    // Paso 10: Convertir la estructura de firma a un vector de bytes y devolver
    return signature.toBytes();
}

// Algoritmo 23: slh_verify - Verifica una firma SLH-DSA con un preash (no implementado)

// Algoritmo 24: slh_verify - Verifica una firma SLH-DSA pura
bool slh_verify(const ByteVector& M, const ByteVector& SIG, const ByteVector& ctx, const SLH_DSA_PublicKey& PK) {
    // Paso 1-3: Verificar que el tamaño del contexto no sea demasiado grande
    if (ctx.size() > 255) {
        // Devolver false si el contexto es demasiado largo
        return false;
    }

    // Paso 4: Construir M' concatenando toByte(0,1) || toByte(|ctx|,1) || ctx || M
    ByteVector M_prime;

    // Agregar toByte(0,1) - un byte con valor 0 que indica "mensaje"
    M_prime.push_back(0);

    // Agregar toByte(|ctx|,1) - un byte con la longitud del contexto
    M_prime.push_back(static_cast<uint8_t>(ctx.size()));

    // Agregar ctx - el contexto
    M_prime.insert(M_prime.end(), ctx.begin(), ctx.end());

    // Agregar M - el mensaje
    M_prime.insert(M_prime.end(), M.begin(), M.end());

    // Paso 5: Llamar a slh_verify_internal con M', SIG y PK
    return slh_verify_internal(M_prime, SIG, PK);
}
