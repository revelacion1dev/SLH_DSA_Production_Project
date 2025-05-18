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

    // Metodo para verificar que la importacion de shake es correcta
    external fun computeHash(byteArray: ByteArray, version: Int): ByteArray

    // Algoritmos WOTS+
    external fun chain(X: ByteArray, i: Int, s: Int, PKseed: ByteArray, adrsPtr: Long, n: Int): ByteArray
    external fun wotsPkGen(SKseed: ByteArray, PKseed: ByteArray, adrsPtr: Long, n: Int, len: Int): ByteArray
    external fun wotsSign(M: ByteArray, SKseed: ByteArray, PKseed: ByteArray, adrsPtr: Long): ByteArray
    external fun wotsPkFromSig(sig: ByteArray, M: ByteArray, PKseed: ByteArray, adrsPtr: Long): ByteArray

    // Algoritmos XMSS
    external fun xmssNode(SKseed: ByteArray, i: Int, z: Int, PKseed: ByteArray, adrsPtr: Long, n: Int, wots_len: Int): ByteArray
    external fun xmssSign(M: ByteArray, SKseed: ByteArray, idx: Int, PKseed: ByteArray, adrsPtr: Long, n: Int, wots_len: Int, h: Int): ByteArray
    external fun xmssPkFromSig(idx: Int, SIGXMSS: ByteArray, M: ByteArray, PKseed: ByteArray, adrsPtr: Long, n: Int, wots_len: Int, h: Int): ByteArray

    // Algoritmos HT (Hypertree)
    external fun htSign(M: ByteArray, SKseed: ByteArray, PKseed: ByteArray, idxtree: Long, idxleaf: Int, n: Int, wots_len: Int, h: Int, d: Int): ByteArray
    external fun htVerify(M: ByteArray, SIGHT: ByteArray, PKseed: ByteArray, idxtree: Long, idxleaf: Int, PKroot: ByteArray, n: Int, wots_len: Int, h: Int, d: Int): Boolean

    // Algoritmos FORS
    external fun forsSkGen(SKseed: ByteArray, PKseed: ByteArray, adrsPtr: Long, idx: Int, n: Int): ByteArray
    external fun forsNode(SKseed: ByteArray, i: Int, z: Int, PKseed: ByteArray, adrsPtr: Long, n: Int): ByteArray
    external fun forsSign(md: ByteArray, SKseed: ByteArray, PKseed: ByteArray, adrsPtr: Long, n: Int, k: Int, a: Int): ByteArray
    external fun forsPkFromSig(SIGFORS: ByteArray, md: ByteArray, PKseed: ByteArray, adrsPtr: Long, n: Int, k: Int, a: Int): ByteArray

    // Algoritmos SLH-DSA principales
    external fun slhKeyGen(paramSet: Int): Array<ByteArray> // Retorna [publicKey, privateKey]
    external fun slhSign(M: ByteArray, ctx: ByteArray, SK: ByteArray, paramSet: Int): ByteArray
    external fun hashSlhSign(M: ByteArray, ctx: ByteArray, PH: ByteArray, SK: ByteArray, paramSet: Int): ByteArray
    external fun slhVerify(M: ByteArray, SIG: ByteArray, ctx: ByteArray, PK: ByteArray, paramSet: Int): Boolean
    external fun hashSlhVerify(M: ByteArray, SIG: ByteArray, ctx: ByteArray, PH: ByteArray, PK: ByteArray, paramSet: Int): Boolean



    // Helper method for testing
    fun formatBase2bResult(result: IntArray): String {
        return result.joinToString(", ", prefix = "[", postfix = "]")
    }


    // Helper para formatear bytes en hexadecimal
    fun bytesToHex(bytes: ByteArray): String {
        return bytes.joinToString("") { String.format("%02X", it) }
    }
}