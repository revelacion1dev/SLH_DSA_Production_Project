#ifndef FIPS205_H
#define FIPS205_H

#include <vector>
#include <array>
#include <cstdint>
#include <stdexcept>
#include <algorithm>

// Tipo uniforme para datos binarios
using ByteVector = std::vector<uint8_t>;

// Funciones de conversión entre uint32_t y bytes
ByteVector uint32ToBytes(uint32_t value);
uint32_t bytesToUint32(const ByteVector& bytes, size_t offset = 0);

// Clase ADRS simplificada
class ADRS {
public:
    std::array<uint8_t, 32> addr;

    ADRS();

    // Acceso a datos
    uint8_t& operator[](size_t index);
    const uint8_t& operator[](size_t index) const;
    const uint8_t* data() const;
    static constexpr size_t size() { return 32; }

    // Convertir a ByteVector para interoperar con el resto del código
    ByteVector toVector() const;

    // Métodos para manipular direcciones
    void setLayerAddress(uint32_t layer);
    void setTreeAddress(const uint8_t tree[12]);
    void setTypeAndClear(uint32_t type);
    void setKeyPairAddress(uint32_t keyPair);
    void setChainAddress(uint32_t chain);
    void setTreeHeight(uint32_t height);
    void setHashAddress(uint32_t hash);
    void setTreeIndex(uint32_t index);

    // Métodos para obtener valores
    uint32_t getKeyPairAddress() const;
    uint32_t getTreeIndex() const;
};

// Algoritmos base
uint32_t gen_len2(uint64_t n, uint64_t lg_w);
uint32_t toInt(const ByteVector& X, uint64_t n);
ByteVector toByte(const ByteVector& X, uint64_t n);
uint8_t divmod256(ByteVector& num);
std::vector<uint32_t> base_2b(const ByteVector& X, int b, int out_len);

// Funciones de hash para SLH-DSA
bool computeShake256(const ByteVector& input, ByteVector& output, size_t outputLen);
bool concatenateAndHash(const std::vector<ByteVector>& inputs, ByteVector& output, size_t outputLen);

// Funciones primitivas SLH-DSA
bool H_msg(const ByteVector& R, const ByteVector& PKseed, const ByteVector& PKroot,
           const ByteVector& M, ByteVector& output);

bool PRF(const ByteVector& PKseed, const ByteVector& SKseed, const ByteVector& ADRS,
         ByteVector& output);

bool PRF_msg(const ByteVector& SKprf, const ByteVector& opt_rand, const ByteVector& M,
             ByteVector& output);

bool F(const ByteVector& PKseed, const ByteVector& ADRS, const ByteVector& M1,
       ByteVector& output);

bool H(const ByteVector& PKseed, const ByteVector& ADRS, const ByteVector& M2,
       ByteVector& output);

bool T_l(const ByteVector& PKseed, const ByteVector& ADRS, std::vector<ByteVector> Ml,
         ByteVector& output);

// Algoritmos WOTS+

// Algoritmo 5 : Encadenar usando WOTS+
ByteVector chain(ByteVector& X, uint32_t i, uint32_t s, const ByteVector& PKseed, ADRS& adrs, size_t n, size_t len);
// Algoritmo 6 : Generar la clave pública usando WOTS+
ByteVector wots_pkGen(const ByteVector& SKseed, const ByteVector& PKseed, ADRS& adrs, size_t n, size_t len);
ByteVector wots_sign(const ByteVector& M, const ByteVector& SKseed, const ByteVector& PKseed, ADRS& adrs, size_t n, size_t len);
ByteVector wots_pkFromSig(const ByteVector& sig, const ByteVector& M, const ByteVector& PKseed, ADRS& adrs, size_t n, size_t len);

// Algoritmos XMSS
ByteVector xmss_node(const ByteVector& SKseed, uint32_t i, uint32_t z, const ByteVector& PKseed, ADRS& adrs, size_t n, size_t wots_len);
ByteVector xmss_sign(const ByteVector& M, const ByteVector& SKseed, uint32_t idx, const ByteVector& PKseed, ADRS& adrs, size_t n, size_t wots_len, size_t h);
ByteVector xmss_pkFromSig(uint32_t idx, const ByteVector& SIGXMSS, const ByteVector& M, const ByteVector& PKseed, ADRS& adrs, size_t n, size_t wots_len, size_t h);

// Algoritmos HT (Hypertree)
ByteVector ht_sign(const ByteVector& M, const ByteVector& SKseed, const ByteVector& PKseed, uint64_t idxtree, uint32_t idxleaf, size_t n, size_t wots_len, size_t h, size_t d);
bool ht_verify(const ByteVector& M, const ByteVector& SIGHT, const ByteVector& PKseed, uint64_t idxtree, uint32_t idxleaf, const ByteVector& PKroot, size_t n, size_t wots_len, size_t h, size_t d);

// Algoritmos FORS
ByteVector fors_skGen(const ByteVector& SKseed, const ByteVector& PKseed, ADRS& adrs, uint32_t idx, size_t n);
ByteVector fors_node(const ByteVector& SKseed, uint32_t i, uint32_t z, const ByteVector& PKseed, ADRS& adrs, size_t n);
ByteVector fors_sign(const ByteVector& md, const ByteVector& SKseed, const ByteVector& PKseed, ADRS& adrs, size_t n, size_t k, size_t a);
ByteVector fors_pkFromSig(const ByteVector& SIGFORS, const ByteVector& md, const ByteVector& PKseed, ADRS& adrs, size_t n, size_t k, size_t a);

// Algoritmos SLH-DSA principales
struct SLHKeyPair {
    ByteVector publicKey;
    ByteVector privateKey;
};

SLHKeyPair slh_keygen_internal(const ByteVector& SK_seed, const ByteVector& SK_prf, const ByteVector& PK_seed, size_t n, size_t wots_len, size_t d, size_t h, size_t k, size_t a);
ByteVector slh_sign_internal(const ByteVector& M, const ByteVector& SK, const ByteVector& addrnd, size_t n, size_t wots_len, size_t d, size_t h, size_t k, size_t a);
bool slh_verify_internal(const ByteVector& M, const ByteVector& SIG, const ByteVector& PK, size_t n, size_t wots_len, size_t d, size_t h, size_t k, size_t a);

// Envoltorios contextuales
SLHKeyPair slh_keygen(size_t paramSet);
ByteVector slh_sign(const ByteVector& M, const ByteVector& ctx, const ByteVector& SK, size_t paramSet);
ByteVector hash_slh_sign(const ByteVector& M, const ByteVector& ctx, const ByteVector& PH, const ByteVector& SK, size_t paramSet);
bool slh_verify(const ByteVector& M, const ByteVector& SIG, const ByteVector& ctx, const ByteVector& PK, size_t paramSet);
bool hash_slh_verify(const ByteVector& M, const ByteVector& SIG, const ByteVector& ctx, const ByteVector& PH, const ByteVector& PK, size_t paramSet);

#endif // FIPS205_H