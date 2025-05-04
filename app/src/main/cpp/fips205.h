#ifndef FIPS205_H
#define FIPS205_H

#include <vector>
#include <cstdint>
#include <stdexcept>
/*
 *    ADRS structure
 */

struct ADRS {
    // La estructura ADRS es de 32 bytes (256 bits)
    std::array<uint8_t, 32> addr;

    // Constructor
    ADRS() {
        addr.fill(0);
    }

    // Método para obtener la dirección completa
    const uint8_t* getAddress() const {
        return addr.data(); // Devuelve un puntero a los bytes de la dirección de addr
    }

    // Operador para acceder directamente a los bytes
    uint8_t& operator[](size_t index) {
        return addr[index];
    }

    // Operador para acceder directamente a los bytes (versión const)
    const uint8_t& operator[](size_t index) const {
        return addr[index];
    }

    // Tamaño de la dirección en bytes
    static constexpr size_t size() {
        return 32;
    }
};



// ADRS operations namespace
namespace adrs_ops {
    // Layer address functions - first 4 bytes (big-endian)
    void setLayerAddress(ADRS& adrs, uint32_t layer);        // 4 bytes for layer address

    // Tree address functions - bytes 4-15 (big-endian)
    void setTreeAddress(ADRS& adrs, const uint8_t tree[12]); // 12 bytes for tree address

    // Type and clear - bytes 16-19 (big-endian)
    // Clears all fields below the type when setting type
    void setTypeAndClear(ADRS& adrs, uint32_t type);

    // KeyPair address - bytes 20-23 (big-endian)
    void setKeyPairAddress(ADRS& adrs, uint32_t keyPair);
    uint32_t getKeyPairAddress(const ADRS& adrs);

    // Chain/Tree Height address - bytes 24-27 (big-endian)
    void setChainAddress(ADRS& adrs, uint32_t chain);
    void setTreeHeight(ADRS& adrs, uint32_t height);

    // Hash/Tree Index address - bytes 28-31 (big-endian)
    void setHashAddress(ADRS& adrs, uint32_t hash);
    void setTreeIndex(ADRS& adrs, uint32_t index);
    uint32_t getTreeIndex(const ADRS& adrs);
}

// Algorithm 1: gen_len2
// Computes len2 given security parameter n and bits per hash chain lg_w
uint64_t gen_len2(uint64_t n, uint64_t lg_w);

// Algorithm 2: toInt
// Converts a byte array to an integer (big-endian)
uint64_t toInt(const std::vector<uint8_t>& X, uint64_t n);

// Algorithm 3: toByte
// Converts an integer to a byte array (big-endian)
std::vector<uint8_t> toByte(const std::vector<uint8_t>& X, uint64_t n);

// Algorithm 4: base_2b
// Computes the base 2^b representation of X
std::vector<uint32_t> base_2b(const std::vector<uint8_t>& X, int b, int out_len);

// Algorithm 5: chain
// Chaining function used in WOTS+

#endif // FIPS205_H