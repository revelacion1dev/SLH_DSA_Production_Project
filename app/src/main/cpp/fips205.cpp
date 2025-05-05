// fips205.cpp
#include "fips205.h"


// ADRS operations implementations

    ADRS::ADRS() {
        addr.fill(0);
    }

    // Método para obtener la dirección completa como puntero (borrar)
    const uint8_t* ADRS::getAddress() const {
        return addr.data(); // Devuelve un puntero a los bytes de la dirección
    }

    // Operador para acceder directamente a los bytes
    uint8_t& ADRS::operator[](size_t index) {
        return addr[index];
    }

    // Operador para acceder directamente a los bytes (versión const)
    const uint8_t& ADRS::operator[](size_t index) const {
        return addr[index];
    }

    // Tamaño de la dirección en bytes
    constexpr size_t ADRS::size() {
        return 32;
    }

    // Bytes 0-3 (big-endian)
    void ADRS::setLayerAddress(uint32_t layer) {
        // Crear representación big-endian
        std::vector<uint8_t> input = {
                static_cast<uint8_t>((layer >> 24) & 0xFF),  // Byte más significativo primero
                static_cast<uint8_t>((layer >> 16) & 0xFF),
                static_cast<uint8_t>((layer >> 8) & 0xFF),
                static_cast<uint8_t>(layer & 0xFF)           // Byte menos significativo al final
        };

        // Usar toByte para convertir a representación de 4 bytes
        std::vector<uint8_t> layer_bytes = ::toByte(input, 4);

        // Copiar al ADRS
        for (int i = 0; i < 4; i++) {
            addr[i] = layer_bytes[i];
        }
    }

    // Tree address - bytes 4-15 (contains 3 words)
    void ADRS::setTreeAddress(const uint8_t tree[12]) {

        // En principio ya vienen en bytes luego no es necesaria la conversión.
        // Simplemente copiar los bytes directamente sin procesar
        for (int i = 0; i < 12; i++) {
            addr[4 + i] = tree[i];
        }
    }

    // Type and clear - bytes 16-19
    void ADRS::setTypeAndClear(uint32_t type) {
        // Convertir type a array de 4 bytes en formato big-endian
        uint8_t type_arr[4] = {
                static_cast<uint8_t>((type >> 24) & 0xFF),
                static_cast<uint8_t>((type >> 16) & 0xFF),
                static_cast<uint8_t>((type >> 8) & 0xFF),
                static_cast<uint8_t>(type & 0xFF)
        };

        // Convertir el array a vector para toByte
        std::vector<uint8_t> type_vec(type_arr, type_arr + 4);

        // Usar toByte para asegurar el formato correcto
        std::vector<uint8_t> type_bytes = ::toByte(type_vec, 4);

        // Copiar los bytes al ADRS en la posición 16
        for (int i = 0; i < 4; i++) {
            addr[16 + i] = type_bytes[i];
        }

        // Limpiar todos los campos que siguen (bytes 20-31)
        for (int i = 20; i < 32; i++) {
            addr[i] = 0;
        }
    }

    // KeyPair address - bytes 20-23 (little-endian)
    void ADRS::setKeyPairAddress(uint32_t keyPair) {
        // Convertir keyPair a array de 4 bytes en formato big-endian
        uint8_t keyPair_arr[4] = {
                static_cast<uint8_t>((keyPair >> 24) & 0xFF),
                static_cast<uint8_t>((keyPair >> 16) & 0xFF),
                static_cast<uint8_t>((keyPair >> 8) & 0xFF),
                static_cast<uint8_t>(keyPair & 0xFF)
        };

        // Convertir el array a vector para toByte
        std::vector<uint8_t> keyPair_vec(keyPair_arr, keyPair_arr + 4);

        // Usar toByte para asegurar el formato correcto
        std::vector<uint8_t> keyPair_bytes = ::toByte(keyPair_vec, 4);

        // Copiar los bytes al ADRS en la posición 20
        for (int i = 0; i < 4; i++) {
            addr[20 + i] = keyPair_bytes[i];
        }
    }

    // Chain address - bytes 24-27
    void ADRS::setChainAddress(uint32_t chain) {
        // Crear representación big-endian del valor uint32_t
        std::vector<uint8_t> input = {
                static_cast<uint8_t>((chain >> 24) & 0xFF),  // Byte más significativo primero
                static_cast<uint8_t>((chain >> 16) & 0xFF),
                static_cast<uint8_t>((chain >> 8) & 0xFF),
                static_cast<uint8_t>(chain & 0xFF)          // Byte menos significativo al final
        };

        // Convertir a formato de longitud fija usando toByte
        std::vector<uint8_t> chain_bytes = ::toByte(input, 4);

        // Copiar a la posición apropiada en la dirección
        for (int i = 0; i < 4; i++) {
            addr[24 + i] = chain_bytes[i];
        }
    }

    // Tree Height - bytes 24-27 (misma posición que Chain)
    void ADRS::setTreeHeight(uint32_t height) {
        // Crear representación big-endian del valor uint32_t
        std::vector<uint8_t> input = {
                static_cast<uint8_t>((height >> 24) & 0xFF),  // Byte más significativo primero
                static_cast<uint8_t>((height >> 16) & 0xFF),
                static_cast<uint8_t>((height >> 8) & 0xFF),
                static_cast<uint8_t>(height & 0xFF)          // Byte menos significativo al final
        };

        // Convertir a formato de longitud fija usando toByte
        std::vector<uint8_t> height_bytes = ::toByte(input, 4);

        // Copiar a la posición apropiada en la dirección
        for (int i = 0; i < 4; i++) {
            addr[24 + i] = height_bytes[i];
        }
    }

    // Hash address - bytes 28-31
    void ADRS::setHashAddress(uint32_t hash) {
        // Crear array de bytes en formato big-endian
        uint8_t hash_arr[4] = {
                static_cast<uint8_t>((hash >> 24) & 0xFF),  // Byte más significativo primero
                static_cast<uint8_t>((hash >> 16) & 0xFF),
                static_cast<uint8_t>((hash >> 8) & 0xFF),
                static_cast<uint8_t>(hash & 0xFF)           // Byte menos significativo al final
        };

        // Convertir el array a vector para usar toByte
        std::vector<uint8_t> hash_vec(hash_arr, hash_arr + 4);

        // Usar toByte para asegurar el formato correcto
        std::vector<uint8_t> hash_bytes = ::toByte(hash_vec, 4);

        // Copiar los bytes al ADRS en la posición 28
        for (int i = 0; i < 4; i++) {
            addr[28 + i] = hash_bytes[i];
        }
    }

    // Tree Index - bytes 28-31 (same position as Hash)
    void ADRS::setTreeIndex(uint32_t index) {
        // Crear array de bytes en formato big-endian
        uint8_t index_arr[4] = {
                static_cast<uint8_t>((index >> 24) & 0xFF),  // Byte más significativo primero
                static_cast<uint8_t>((index >> 16) & 0xFF),
                static_cast<uint8_t>((index >> 8) & 0xFF),
                static_cast<uint8_t>(index & 0xFF)           // Byte menos significativo al final
        };

        // Convertir el array a vector para usar toByte
        std::vector<uint8_t> index_vec(index_arr, index_arr + 4);

        // Usar toByte para asegurar el formato correcto
        std::vector<uint8_t> indexBytes = ::toByte(index_vec, 4);

        // Colocar los bytes en ADRS[28:32]
        for (int i = 0; i < 4; i++) {
            addr[28 + i] = indexBytes[i];
        }
    }

    // Get KeyPair address from ADRS (little-endian)
    uint32_t ADRS::getKeyPairAddress() const {
        // Extraer bytes 20-23 del ADRS
        std::vector<uint8_t> bytes;
        for (int i = 20; i < 24; i++) {
            bytes.push_back(addr[i]);
        }

        // Convertir de little-endian a entero
        return static_cast<uint32_t>(
                (static_cast<uint32_t>(bytes[3]) << 24) |
                (static_cast<uint32_t>(bytes[2]) << 16) |
                (static_cast<uint32_t>(bytes[1]) << 8) |
                (static_cast<uint32_t>(bytes[0]))
        );
    }

    // Get Tree Index - bytes 28-31
    uint32_t ADRS::getTreeIndex() const {
        // Extraer bytes 28-31 del ADRS
        std::vector<uint8_t> bytes;
        for (int i = 28; i < 32; i++) {
            bytes.push_back(addr[i]);
        }

        // Convertir de little-endian a entero (igual que getKeyPairAddress)
        return static_cast<uint32_t>(
                (static_cast<uint32_t>(bytes[3]) << 24) |
                (static_cast<uint32_t>(bytes[2]) << 16) |
                (static_cast<uint32_t>(bytes[1]) << 8)  |
                (static_cast<uint32_t>(bytes[0]))
        );
    }



// Algorithm 1: gen_len2
uint32_t gen_len2(uint64_t n, uint64_t lg_w) {
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
uint32_t toInt(const std::vector<uint8_t>& X, uint64_t n) {
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
