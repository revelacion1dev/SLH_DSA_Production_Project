#ifndef FIPS205_H
#define FIPS205_H

#include <vector>
#include <array>
#include <cstdint>
#include <stdexcept>
#include <algorithm>
#include <utility> // Para std::pair

// Tipo uniforme para datos binarios
using ByteVector = std::vector<uint8_t>;

// Definición de tipos para ADRS
constexpr uint32_t WOTS_HASH = 0x00;
constexpr uint32_t WOTS_PK = 0x01;
constexpr uint32_t WOTS_TREES = 0x02;
constexpr uint32_t FORS_TREE = 0x03;
constexpr uint32_t FORS_ROOTS = 0x04;
constexpr uint32_t WOTS_PRF = 0x05;
constexpr uint32_t FORS_PRF = 0x06;

// Enumeración para los parámetros de SLH-DSA
enum class SLH_DSA_ParamSet {
    SHA2_128S,
    SHAKE_128S,
    SHA2_128F,
    SHAKE_128F,
    SHA2_192S,
    SHAKE_192S,
    SHA2_192F,
    SHAKE_192F,
    SHA2_256S,
    SHAKE_256S,
    SHA2_256F,
    SHAKE_256F,
    PARAM_COUNT
};

// Configuración por defecto del esquema
struct SLH_DSA_Config {
    static constexpr SLH_DSA_ParamSet SCHEMA = SLH_DSA_ParamSet::SHAKE_256S;
};

// Estructura de parámetros para cada esquema
struct SLH_DSA_Params {
    const char* name;
    uint32_t n, h, d, h_prima, a, k, lg_w, m, security_category;
    uint32_t pk_bytes, sig_bytes;
    bool is_shake;
};

// Tabla de parámetros para cada variante de SLH-DSA
extern const SLH_DSA_Params PARAMS[static_cast<size_t>(SLH_DSA_ParamSet::PARAM_COUNT)];

// Función para obtener los parámetros de un esquema dado
const SLH_DSA_Params* get_params(SLH_DSA_ParamSet set);

// Variable global para acceder a los parámetros actuales
extern const SLH_DSA_Params* params;

// Estructura para la clave pública de SLH-DSA
struct SLH_DSA_PublicKey {
    ByteVector seed;  // PK.seed
    ByteVector root;  // PK.root

    // Métodos de serialización/deserialización
    ByteVector toBytes() const;
    static SLH_DSA_PublicKey fromBytes(const ByteVector& data);
};

// Estructura para la clave privada de SLH-DSA
struct SLH_DSA_PrivateKey {
    ByteVector seed;   // SK.seed
    ByteVector prf;    // SK.prf
    ByteVector pkSeed; // PK.seed (copia de la clave pública)
    ByteVector pkRoot; // PK.root (copia de la clave pública)

    // Métodos de serialización/deserialización
    ByteVector toBytes() const;
    static SLH_DSA_PrivateKey fromBytes(const ByteVector& data);

    // Método para obtener la clave pública correspondiente
    SLH_DSA_PublicKey getPublicKey() const;
};

// Estructura para la firma SLH-DSA
struct SLH_DSA_Signature {
    ByteVector randomness;    // R (n bytes)
    ByteVector forsSignature; // FORS signature (k(1+a)·n bytes)
    ByteVector htSignature;   // HT signature ((h+d·len)·n bytes)

    // Métodos de serialización/deserialización
    ByteVector toBytes() const;
    static SLH_DSA_Signature fromBytes(const ByteVector& data);
};

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

// Funciones de conversión entre uint32_t y bytes
ByteVector uint32ToBytes(uint32_t value);
uint32_t bytesToUint32(const ByteVector& bytes, size_t offset = 0);

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
ByteVector chain(ByteVector X, uint32_t i, uint32_t s, const ByteVector& PKseed, ADRS adrs, size_t n);
ByteVector wots_pkGen(const ByteVector& SKseed, const ByteVector& PKseed, ADRS adrs);
ByteVector wots_sign(const ByteVector& M, const ByteVector& SKseed, const ByteVector& PKseed, ADRS adrs);
ByteVector wots_pkFromSig(const ByteVector& sig, const ByteVector& M, const ByteVector& PKseed, ADRS adrs);

// Algoritmos XMSS
ByteVector xmss_node(const ByteVector& SKseed, uint32_t i, uint32_t z, const ByteVector& PKseed, ADRS adrs);
ByteVector xmss_sign(const ByteVector& M, const ByteVector& SKseed, uint32_t idx, const ByteVector& PKseed, ADRS adrs);
ByteVector xmss_pkFromSig(uint32_t idx, const ByteVector& SIG_XMSS, const ByteVector& M, const ByteVector& PKseed, ADRS adrs);

// Algoritmos HT (Hypertree)
ByteVector ht_sign(const ByteVector& M, const ByteVector& SKseed, const ByteVector& PKseed, uint32_t idx_tree, uint32_t idx_leaf);
bool ht_verify(const ByteVector& M, const ByteVector& SIG_HT, const ByteVector& PKseed, uint32_t idx_tree, uint32_t idx_leaf, const ByteVector& PKroot);

// Algoritmos FORS
ByteVector fors_skGen(const ByteVector& SKseed, const ByteVector& PKseed, ADRS adrs, uint32_t idx);
ByteVector fors_node(const ByteVector& SKseed, uint32_t i, uint32_t z, const ByteVector& PKseed, ADRS adrs);
ByteVector fors_sign(const ByteVector& md, const ByteVector& SKseed, const ByteVector& PKseed, ADRS adrs);
ByteVector fors_pkFromSig(const ByteVector& SIG_FORS, const ByteVector& md, const ByteVector& PKseed, ADRS adrs);

// Algoritmos SLH-DSA principales
std::pair<SLH_DSA_PrivateKey, SLH_DSA_PublicKey> slh_keygen_internal(const ByteVector& SKseed, const ByteVector& SKprf, const ByteVector& PKseed);
SLH_DSA_Signature slh_sign_internal(const ByteVector& M, const SLH_DSA_PrivateKey& privateKey, const ByteVector& addrnd = ByteVector());
bool slh_verify_internal(const ByteVector& M, const ByteVector& SIG, const SLH_DSA_PublicKey& PK);

// API pública
std::pair<SLH_DSA_PrivateKey, SLH_DSA_PublicKey> slh_keygen();
ByteVector slh_sign(const ByteVector& M, const ByteVector& ctx, const SLH_DSA_PrivateKey& SK);
bool slh_verify(const ByteVector& M, const ByteVector& SIG, const ByteVector& ctx, const SLH_DSA_PublicKey& PK);

#endif // FIPS205_H