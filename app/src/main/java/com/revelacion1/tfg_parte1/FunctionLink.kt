package com.revelacion1.tfg_parte1

class FunctionLink {
    // Native method declarations
    external fun genLen2(n: Long, lg_w: Long): Long
    external fun toInt(x: ByteArray, n: Int): Long
    external fun toByte(x: Long, n: Int): ByteArray
    external fun base2b(x: ByteArray, b: Int, out_len: Int ): IntArray

    // Nuevos métodos nativos para ADRS
    external fun createADRS(): Long  // Devuelve un puntero/handle a la instancia de ADRS
    external fun disposeADRS(adrsPtr: Long)  // Libera la memoria de la instancia de ADRS
    external fun getAddressBytes(adrsPtr: Long) : ByteArray // Obtiene los 32 bytes de la dirección
    external fun setLayerAddress(adrsPtr: Long, layer: Int)
    external fun setTreeAddress(adrsPtr: Long, tree: ByteArray)
    external fun setTypeAndClear(adrsPtr: Long, type: Int)
    external fun setKeyPairAddress(adrsPtr: Long, keyPair: Int)
    external fun setChainAddress(adrsPtr: Long, chain: Int)
    external fun setTreeHeight(adrsPtr: Long, height: Int)
    external fun setHashAddress(adrsPtr: Long, hash: Int)
    external fun setTreeIndex(adrsPtr: Long, index: Int)
    external fun getKeyPairAddress(adrsPtr: Long): Long
    external fun getTreeIndex(adrsPtr: Long): Long

    // Helper method for testing
    fun formatBase2bResult(result: IntArray): String {
        return result.joinToString(", ", prefix = "[", postfix = "]")
    }


    // Helper para formatear bytes en hexadecimal
    fun bytesToHex(bytes: ByteArray): String {
        return bytes.joinToString("") { String.format("%02X", it) }
    }
}