#ifndef FIPS205_H
#define FIPS205_H

#include <vector>
#include <cstdint>
#include <stdexcept>


class ADRS {
    private:
        // La estructura ADRS es de 32 bytes (256 bits)


    public:

        // Puesta aqui para que sea publica de cara a testing (visualizar all el contenido)
        std::array<uint8_t, 32> addr;
        ADRS();


        const uint8_t* getAddress() const;


        uint8_t& operator[](size_t index);

        const uint8_t& operator[](size_t index) const;

        static constexpr size_t size();

        void setLayerAddress(uint32_t layer);

        void setTreeAddress(const uint8_t tree[12]);

        void setTypeAndClear(uint32_t type);

        void setKeyPairAddress(uint32_t keyPair);

        void setChainAddress(uint32_t chain);

        void setTreeHeight(uint32_t height);

        void setHashAddress(uint32_t hash);

        void setTreeIndex(uint32_t index);

        uint32_t getKeyPairAddress() const;

        uint32_t getTreeIndex() const;
    };

// Algorithm 1: gen_len2
// Computes len2 given security parameter n and bits per hash chain lg_w
uint32_t gen_len2(uint64_t n, uint64_t lg_w);

// Algorithm 2: toInt
// Converts a byte array to an integer (big-endian)
uint32_t toInt(const std::vector<uint8_t>& X, uint64_t n);

// Algorithm 3: toByte
// Converts an integer to a byte array (big-endian)
std::vector<uint8_t> toByte(const std::vector<uint8_t>& X, uint64_t n);

// Algorithm 4: base_2b
// Computes the base 2^b representation of X
std::vector<uint32_t> base_2b(const std::vector<uint8_t>& X, int b, int out_len);

// Algorithm 5: chain
// Chaining function used in WOTS+

#endif // FIPS205_H