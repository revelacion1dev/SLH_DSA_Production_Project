// fips205.cpp
#include "fips205.h"


// ADRS operations implementations
namespace adrs_ops {

    // Incluimos la funcion necesaria para las funciones internas
    std::vector<uint8_t> toByte(const std::vector<uint8_t>& X, uint64_t n);

    const uint8_t* getAddressBytes(const ADRS& adrs) {
        return adrs.getAddress(); // Devuelve puntero a los 32 bytes
    }

    // Layer address - bytes 0-3
    void setLayerAddress(ADRS& adrs, uint32_t layer) {
        // Primero convertir uint32_t a vector<uint8_t>
        std::vector<uint8_t> layerVector;
        uint32_t temp = layer;

        // Agregar bytes en orden inverso (menos significativo primero)
        while (temp > 0 || layerVector.empty()) {
            layerVector.push_back(temp & 0xFF);
            temp >>= 8;
        }

        // Invertir para formato big-endian
        std::reverse(layerVector.begin(), layerVector.end());

        // Ahora usar toByte con el operador de ámbito global
        std::vector<uint8_t> layer_bytes = ::toByte(layerVector, 4);

        // Insertar los 4 bytes en la dirección
        for (int i = 0; i < 4; i++) {
            adrs[i] = layer_bytes[i];
        }
    }

    // Tree address - bytes 4-15 (contains 3 words)
    void setTreeAddress(ADRS& adrs, const uint8_t tree[12]) {
        // Convertimos el array a un vector para usar la implementación de toByte
        std::vector<uint8_t> tree_vec(tree, tree + 12);

        // Usamos toByte para asegurar el formato correcto
        std::vector<uint8_t> tree_bytes = ::toByte(tree_vec, 12);

        // Copiamos los bytes al ADRS
        for (int i = 0; i < 12; i++) {
            adrs[4 + i] = tree_bytes[i];
        }
    }
    // Type and clear - bytes 16-19
    void setTypeAndClear(ADRS& adrs, uint32_t type) {
        // Convertir type a vector<uint8_t>
        std::vector<uint8_t> typeVector;
        uint32_t temp = type;

        // Crear el vector de bytes
        while (temp > 0 || typeVector.empty()) {
            typeVector.push_back(temp & 0xFF);
            temp >>= 8;
        }

        // Invertir para formato big-endian
        std::reverse(typeVector.begin(), typeVector.end());

        // Usar el operador de ámbito global para llamar a toByte
        std::vector<uint8_t> typeBytes = ::toByte(typeVector, 4);

        // Colocarlos en adrs[16:20]
        for (int i = 0; i < 4; i++) {
            adrs[16 + i] = typeBytes[i];
        }

        // Clear all fields that follow (bytes 20-31)
        for (int i = 20; i < 32; i++) {
            adrs[i] = 0;
        }
    }

    // KeyPair address - bytes 20-23
    void setKeyPairAddress(ADRS& adrs, uint32_t keyPair) {
        // Convertir uint32_t a vector<uint8_t>
        std::vector<uint8_t> keyPairVector;
        uint32_t temp = keyPair;

        // Agregar bytes en orden inverso (comenzando por el menos significativo)
        while (temp > 0 || keyPairVector.empty()) {
            keyPairVector.push_back(temp & 0xFF);
            temp >>= 8;
        }

        // Invertir para tener formato big-endian
        std::reverse(keyPairVector.begin(), keyPairVector.end());

        // Usar la implementación de toByte
        std::vector<uint8_t> keyPairBytes = ::toByte(keyPairVector, 4);

        // Copiamos los bytes a las posiciones 20-23
        for (int i = 0; i < 4; i++) {
            adrs[20 + i] = keyPairBytes[i];
        }
    }

    // Chain address - bytes 24-27
    void setChainAddress(ADRS& adrs, uint32_t chain) {
        // Convertir chain a vector
        std::vector<uint8_t> chainVector;
        uint32_t temp = chain;

        // Crear vector de bytes a partir del entero
        while (temp > 0 || chainVector.empty()) {
            chainVector.push_back(temp & 0xFF);
            temp >>= 8;
        }

        // Invertir para tener formato big-endian
        std::reverse(chainVector.begin(), chainVector.end());

        // Convertir a formato de 4 bytes
        std::vector<uint8_t> chainBytes = ::toByte(chainVector, 4);

        // Colocar los bytes en ADRS[24:28]
        for (int i = 0; i < 4; i++) {
            adrs[24 + i] = chainBytes[i];
        }
    }

    // Tree Height - bytes 24-27 (misma posición que Chain)
    void setTreeHeight(ADRS& adrs, uint32_t height) {
        // Convertir height a vector
        std::vector<uint8_t> heightVector;
        uint32_t temp = height;

        // Crear vector de bytes a partir del entero
        while (temp > 0 || heightVector.empty()) {
            heightVector.push_back(temp & 0xFF);
            temp >>= 8;
        }

        // Invertir para tener formato big-endian
        std::reverse(heightVector.begin(), heightVector.end());

        // Convertir a formato de 4 bytes
        std::vector<uint8_t> heightBytes = ::toByte(heightVector, 4);

        // Colocar los bytes en ADRS[24:28]
        for (int i = 0; i < 4; i++) {
            adrs[24 + i] = heightBytes[i];
        }
    }

    // Hash address - bytes 28-31
    void setHashAddress(ADRS& adrs, uint32_t hash) {
        // Convertir hash a vector
        std::vector<uint8_t> hashVector;
        uint32_t temp = hash;

        // Crear vector de bytes a partir del entero
        while (temp > 0 || hashVector.empty()) {
            hashVector.push_back(temp & 0xFF);
            temp >>= 8;
        }

        // Invertir para tener formato big-endian
        std::reverse(hashVector.begin(), hashVector.end());

        // Convertir a formato de 4 bytes
        std::vector<uint8_t> hashBytes = ::toByte(hashVector, 4);

        // Colocar los bytes en ADRS[28:32]
        for (int i = 0; i < 4; i++) {
            adrs[28 + i] = hashBytes[i];
        }
    }

// Tree Index - bytes 28-31 (same position as Hash)
    void setTreeIndex(ADRS& adrs, uint32_t index) {
        // Convertir index a vector
        std::vector<uint8_t> indexVector;
        uint32_t temp = index;

        // Crear vector de bytes a partir del entero
        while (temp > 0 || indexVector.empty()) {
            indexVector.push_back(temp & 0xFF);
            temp >>= 8;
        }

        // Invertir para tener formato big-endian
        std::reverse(indexVector.begin(), indexVector.end());

        // Convertir a formato de 4 bytes
        std::vector<uint8_t> indexBytes = ::toByte(indexVector, 4);

        // Colocar los bytes en ADRS[28:32]
        for (int i = 0; i < 4; i++) {
            adrs[28 + i] = indexBytes[i];
        }
    }

    uint32_t getTreeIndex(const ADRS& adrs) {
        // Extract bytes 28-31 from the ADRS
        std::vector<uint8_t> bytes;
        for (int i = 28; i < 32; i++) {
            bytes.push_back(adrs[i]);
        }

        // Convert to integer using toInt
        return static_cast<uint32_t>(toInt(bytes, 4));
    }
    uint32_t getKeyPairAddress(const ADRS& adrs) {
        // Extract bytes 20-23 from the ADRS
        std::vector<uint8_t> bytes;
        for (int i = 20; i < 24; i++) {
            bytes.push_back(adrs[i]);
        }

        // Convert to integer using toInt
        return static_cast<uint32_t>(toInt(bytes, 4));
    }
}

// Algorithm 1: gen_len2
uint64_t gen_len2(uint64_t n, uint64_t lg_w) {
    uint64_t w = 1ULL << lg_w;  // w = 2^lg_w

    // len1 = ceil((8 * n + lg_w - 1) / lg_w)
    uint64_t len1 = (8 * n + lg_w - 1) / lg_w; // El resultado se trunca automaticamente

    uint64_t max_checksum = len1 * (w - 1);
    uint64_t len2 = 1;
    uint64_t capacity = w;

    while (capacity <= max_checksum) {
        len2 += 1;
        capacity *= w;
    }

    return len2;
}

// Algorithm 2: toInt
uint64_t toInt(const std::vector<uint8_t>& X, uint64_t n) {
    if (X.size() < n) {
        throw std::invalid_argument("Input array is too short");
    }

    uint64_t total = 0;
    for (uint64_t i = 0; i < n; ++i) {
        total = 256 * total + static_cast<uint64_t>(X[i]);
    }
    return total;
}

// Algorithm 3: toByte
// Devuelve el residuo (el byte menos significativo) y modifica el vector
uint8_t divmod256(std::vector<uint8_t>& num) {
    uint16_t carry = 0;
    for (int i = num.size() - 1; i >= 0; --i) {
        uint16_t cur = (carry << 8) | num[i];
        num[i] = cur / 256;
        carry = cur % 256;
    }
    return static_cast<uint8_t>(carry);
}

std::vector<uint8_t> toByte(const std::vector<uint8_t>& X, uint64_t n) {
    std::vector<uint8_t> S(n, 0);
    std::vector<uint8_t> total = X; // copia de X

    for (uint64_t i = 0; i < n; ++i) {
        S[n - 1 - i] = divmod256(total);
    }
    return S;
}

// Algorithm 4: base_2b
std::vector<uint32_t> base_2b(const std::vector<uint8_t>& X, int b, int out_len) {
    // Check for valid input parameters
    if (b <= 0 || b > 31) {
        throw std::invalid_argument("b must be between 1 and 31");
    }

    // Calculate required input length and check if X has enough bytes
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

/*
 *     WoTS+ algorithms
 */
