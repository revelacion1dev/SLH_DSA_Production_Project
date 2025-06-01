#ifndef FIPS205_H
#define FIPS205_H

#include <vector>
#include <array>
#include <cstdint>
#include <stdexcept>
#include <algorithm>
#include <utility>
#include <mutex>

// Tipo uniforme para datos binarios
using ByteVector = std::vector<uint8_t>;

// Definición de tipos para ADRS
constexpr uint32_t WOTS_HASH = 0x00;
constexpr uint32_t WOTS_PK = 0x01;
constexpr uint32_t TREE = 0x02;
constexpr uint32_t FORS_TREE = 0x03;
constexpr uint32_t FORS_ROOTS = 0x04;
constexpr uint32_t WOTS_PRF = 0x05;
constexpr uint32_t FORS_PRF = 0x06;

// Enumeración para los parámetros de SLH-DSA (NOMBRES CORREGIDOS)
enum class SLH_DSA_ParamSet {
    SLH_DSA_SHA2_128s,      // Corregido de SHA2_128S
    SLH_DSA_SHAKE_128s,     // Corregido de SHAKE_128S
    SLH_DSA_SHA2_128f,
    SLH_DSA_SHAKE_128f,
    SLH_DSA_SHA2_192s,
    SLH_DSA_SHAKE_192s,
    SLH_DSA_SHA2_192f,
    SLH_DSA_SHAKE_192f,
    SLH_DSA_SHA2_256s,
    SLH_DSA_SHAKE_256s,
    SLH_DSA_SHA2_256f,
    SLH_DSA_SHAKE_256f,
    PARAM_COUNT
};

// Estructura de parámetros para cada esquema
struct SLH_DSA_Params {
    const char* name;
    uint32_t n, h, d, h_prima, a, k, lg_w, m, security_category;
    uint32_t pk_bytes, sig_bytes;
    bool is_shake;
};

// Declaración adelantada
const SLH_DSA_Params* get_params(SLH_DSA_ParamSet set);

// ConfigManager MEJORADO con thread-safety y validación
class FIPS205ConfigManager {
private:
    static SLH_DSA_ParamSet current_schema;
    static const SLH_DSA_Params* current_params;
    static std::mutex config_mutex; // Para thread-safety
    static bool is_initialized;

    // Validar que los parámetros sean consistentes
    static bool validateParams(const SLH_DSA_Params* params) {
        if (!params) return false;

        // Validaciones básicas de los parámetros
        if (params->n == 0 || params->h == 0 || params->d == 0) return false;
        if (params->h_prima == 0 || params->a == 0 || params->k == 0) return false;
        if (params->lg_w == 0 || params->lg_w > 8) return false;

        // Validar que h sea divisible por d
        if (params->h % params->d != 0) return false;

        // Validar que h_prima sea consistente
        if (params->h_prima != params->h / params->d) return false;

        return true;
    }

public:
    // Inicialización thread-safe
    static void initialize(SLH_DSA_ParamSet default_schema = SLH_DSA_ParamSet::SLH_DSA_SHAKE_128s) {
        std::lock_guard<std::mutex> lock(config_mutex);

        if (!is_initialized) {
            setSchemaUnsafe(default_schema);
            is_initialized = true;
        }
    }

    // Función para cambiar el esquema activo (thread-safe)
    static bool setSchema(SLH_DSA_ParamSet schema) {
        std::lock_guard<std::mutex> lock(config_mutex);
        return setSchemaUnsafe(schema);
    }

    // Función para obtener parámetros actuales (thread-safe)
    static const SLH_DSA_Params* getCurrentParams() {
        std::lock_guard<std::mutex> lock(config_mutex);

        if (!is_initialized) {
            // Auto-inicializar con parámetros por defecto
            setSchemaUnsafe(SLH_DSA_ParamSet::SLH_DSA_SHAKE_256s);
            is_initialized = true;
        }

        return current_params;
    }

    // Función para obtener el esquema actual
    static SLH_DSA_ParamSet getCurrentSchema() {
        std::lock_guard<std::mutex> lock(config_mutex);
        return current_schema;
    }

    // Función para testing con parámetros custom (MEJORADA)
    static bool setCustomParams(uint32_t n, uint32_t h, uint32_t d, uint32_t h_prima,
                                uint32_t a, uint32_t k, uint32_t lg_w) {
        std::lock_guard<std::mutex> lock(config_mutex);

        // Calcular m según la fórmula del estándar
        uint32_t len1 = (8 * n + lg_w - 1) / lg_w;
        uint32_t w = 1 << lg_w;
        uint32_t len2 = 1;
        uint64_t max_checksum = len1 * (w - 1);
        uint64_t capacity = w;
        while (capacity <= max_checksum) {
            len2++;
            capacity *= w;
        }
        uint32_t len = len1 + len2;

        uint32_t m = (k * a + h - h_prima + h_prima + 7) / 8;

        // Calcular sig_bytes según la fórmula del estándar
        uint32_t sig_bytes = (1 + k * (1 + a) + h + d * len) * n;

        static SLH_DSA_Params custom_params = {
                "CUSTOM", n, h, d, h_prima, a, k, lg_w, m,
                1, // security category
                2 * n, // pk_bytes
                sig_bytes,
                true // use_shake por defecto para testing
        };

        // Validar parámetros antes de aplicar
        if (!validateParams(&custom_params)) {
            return false;
        }

        current_params = &custom_params;
        current_schema = static_cast<SLH_DSA_ParamSet>(-1); // Marca como custom

        return true;
    }

    // Verificar si estamos usando parámetros custom
    static bool isUsingCustomParams() {
        std::lock_guard<std::mutex> lock(config_mutex);
        return current_schema == static_cast<SLH_DSA_ParamSet>(-1);
    }

    // Reset a parámetros estándar (en este caso de 128 ya que se toma la version movil)
    static bool resetToStandard(SLH_DSA_ParamSet schema = SLH_DSA_ParamSet::SLH_DSA_SHAKE_128s) {
        std::lock_guard<std::mutex> lock(config_mutex);
        return setSchemaUnsafe(schema);
    }

private:
    // Versión interna sin mutex (para uso interno)
    static bool setSchemaUnsafe(SLH_DSA_ParamSet schema) {
        const SLH_DSA_Params* new_params = get_params(schema);
        if (!new_params || !validateParams(new_params)) {
            return false;
        }

        current_schema = schema;
        current_params = new_params;
        return true;
    }
};

// Macro para acceso thread-safe a los parámetros actuales
#define CURRENT_PARAMS() FIPS205ConfigManager::getCurrentParams()

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

    // Méto do para obtener la clave pública correspondiente
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

// Clase ADRS
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
    void setTreeAddress(uint64_t treeAddress);
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
bool computeShake(const ByteVector& input, ByteVector& output, size_t outputLen);
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
ByteVector chain(ByteVector X, uint32_t i, uint32_t s, const ByteVector& PKseed, ADRS& adrs);
ByteVector wots_pkGen(const ByteVector& SKseed, const ByteVector& PKseed, ADRS& adrs);
ByteVector wots_sign(const ByteVector& M, const ByteVector& SKseed, const ByteVector& PKseed, ADRS adrs);
ByteVector wots_pkFromSig(const ByteVector& sig, const ByteVector& M, const ByteVector& PKseed, ADRS& adrs);

// Algoritmos XMSS
ByteVector xmss_node(const ByteVector& SKseed, uint32_t i, uint32_t z, const ByteVector& PKseed, ADRS& adrs);
ByteVector xmss_sign(const ByteVector& M, const ByteVector& SKseed, uint32_t idx, const ByteVector& PKseed, ADRS& adrs);
ByteVector xmss_pkFromSig(uint32_t idx, const ByteVector& SIG_XMSS, const ByteVector& M, const ByteVector& PKseed, ADRS& adrs);

// Algoritmos HT (Hypertree)
ByteVector ht_sign(const ByteVector& M, const ByteVector& SKseed, const ByteVector& PKseed, uint64_t idx_tree, uint32_t idx_leaf);
bool ht_verify(const ByteVector& M, const ByteVector& SIG_HT, const ByteVector& PKseed, uint64_t idx_tree, uint32_t idx_leaf, const ByteVector& PKroot);

// Algoritmos FORS
ByteVector fors_skGen(const ByteVector& SKseed, const ByteVector& PKseed, ADRS& adrs, uint32_t idx);
ByteVector fors_node(const ByteVector& SKseed, uint32_t i, uint32_t z, const ByteVector& PKseed, ADRS& adrs);
ByteVector fors_sign(const ByteVector& md, const ByteVector& SKseed, const ByteVector& PKseed, ADRS& adrs);
ByteVector fors_pkFromSig(const ByteVector& SIG_FORS, const ByteVector& md, const ByteVector& PKseed, ADRS& adrs);

// Algoritmos SLH-DSA principales
std::pair<SLH_DSA_PrivateKey, SLH_DSA_PublicKey> slh_keygen_internal(const ByteVector& SKseed, const ByteVector& SKprf, const ByteVector& PKseed);
SLH_DSA_Signature slh_sign_internal(const ByteVector& M, const SLH_DSA_PrivateKey& privateKey, const ByteVector& addrnd = ByteVector());
bool slh_verify_internal(const ByteVector& M, const ByteVector& SIG, const SLH_DSA_PublicKey& PK);

// API pública
std::pair<SLH_DSA_PrivateKey, SLH_DSA_PublicKey> slh_keygen();                                                                              // Genera una clave pública y privada de SLH-DSA
//std::pair<SLH_DSA_PrivateKey, SLH_DSA_PublicKey> slh_keygen(const ByteVector& SKseed, const ByteVector& SKprf, const ByteVector& PKseed); //Adopta la clave pública y privada de SLH-DSA a partir de semillas
ByteVector slh_sign(const ByteVector& M, const ByteVector& ctx, const SLH_DSA_PrivateKey& SK);
bool slh_verify(const ByteVector& M, const ByteVector& SIG, const ByteVector& ctx, const SLH_DSA_PublicKey& PK);

#endif // FIPS205_H