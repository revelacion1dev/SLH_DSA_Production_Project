package com.revelacion1.tfg_parte1

import android.util.Log

/**
 * Interface JNI corregida para FIPS205 con ConfigManager integrado
 *
 * CAMBIOS PRINCIPALES:
 * - Eliminados parámetros redundantes (n, len, h, d, k, a, wots_len)
 * - Agregadas funciones de gestión del ConfigManager
 * - Funciones simplificadas que usan parámetros automáticamente
 * - Nuevas capacidades de debugging y validación
 */
class FunctionLink {

    companion object {
        init {
            System.loadLibrary("TFG_PARTE1")
        }
    }

    // CONFIGURATION MANAGER

    external fun initializeConfig(defaultScheme: Int): Boolean
    external fun setParameterScheme(scheme: Int): Boolean
    external fun getCurrentParameters(): Array<Any>
    external fun getCurrentSchemaName(): String
    external fun isUsingCustomParameters(): Boolean
    external fun setCustomParameters(n: Int, h: Int, d: Int, h_prima: Int, a: Int, k: Int, lg_w: Int): Boolean
    external fun resetToStandard(scheme: Int): Boolean

    // Debugging parametros auxiliares
    external fun printCurrentConfig()
    external fun calculateDerivedParams(): IntArray
    external fun getAllSchemaParameters(schemeIndex: Int): IntArray

    // Basic Functions
    external fun genLen2(n : Int , lg_w: Int): Long
    external fun toInt(x: ByteArray, n: Int): Long
    external fun toByte(x: Long, n: Int): ByteArray
    external fun base2b(x: ByteArray, b: Int, out_len: Int): IntArray

    // ADRS Principal

    external fun createADRS(): Long
    external fun disposeADRS(adrsPtr: Long)
    external fun getAddressBytes(adrsPtr: Long): ByteArray
    external fun setLayerAddress(adrsPtr: Long, layer: Int)
    external fun setTreeAddress(adrsPtr: Long, treeIndex : Long)
    external fun setTypeAndClear(adrsPtr: Long, type: Int)
    external fun setKeyPairAddress(adrsPtr: Long, keyPair: Int)
    external fun setChainAddress(adrsPtr: Long, chain: Int)
    external fun setTreeHeight(adrsPtr: Long, height: Int)
    external fun setHashAddress(adrsPtr: Long, hash: Int)
    external fun setTreeIndex(adrsPtr: Long, index: Int)
    external fun getKeyPairAddress(adrsPtr: Long): Long
    external fun getTreeIndex(adrsPtr: Long): Long


    // ALGORITMOS  Para computo de Hash
    external fun computeHash(byteArray: ByteArray, outputLength: Int): ByteArray

    // ALGORITMOS WOTS+
    external fun chain(X: ByteArray, i: Int, s: Int, PKseed: ByteArray, adrsPtr: Long): ByteArray
    external fun wotsPkGen(SKseed: ByteArray, PKseed: ByteArray, adrsPtr: Long): ByteArray
    external fun wotsSign(M: ByteArray, SKseed: ByteArray, PKseed: ByteArray, adrsPtr: Long): ByteArray
    external fun wotsPkFromSig(sig: ByteArray, M: ByteArray, PKseed: ByteArray, adrsPtr: Long): ByteArray

    // ALGORITMOS XMSS

    external fun xmssNode(SKseed: ByteArray, i: Int, z: Int, PKseed: ByteArray, adrsPtr: Long): ByteArray
    external fun xmssSign(M: ByteArray, SKseed: ByteArray, idx: Int, PKseed: ByteArray, adrsPtr: Long): ByteArray
    external fun xmssPkFromSig(idx: Int, SIGXMSS: ByteArray, M: ByteArray, PKseed: ByteArray, adrsPtr: Long): ByteArray


    // ALGORITMOS HT

    external fun htSign(M: ByteArray, SKseed: ByteArray, PKseed: ByteArray, idxtree: Long, idxleaf: Int): ByteArray
    external fun htVerify(M: ByteArray, SIGHT: ByteArray, PKseed: ByteArray, idxtree: Long, idxleaf: Int, PKroot: ByteArray): Boolean

    // ALGORITMOS FORS

    external fun forsSkGen(SKseed: ByteArray, PKseed: ByteArray, adrsPtr: Long, idx: Int): ByteArray
    external fun forsNode(SKseed: ByteArray, i: Int, z: Int, PKseed: ByteArray, adrsPtr: Long): ByteArray
    external fun forsSign(md: ByteArray, SKseed: ByteArray, PKseed: ByteArray, adrsPtr: Long): ByteArray
    external fun forsPkFromSig(SIGFORS: ByteArray, md: ByteArray, PKseed: ByteArray, adrsPtr: Long): ByteArray


    //Interfaces internas (se introduce un addrnd generado)
    external fun slhInternalSign(M: ByteArray, SKSeed: ByteArray,addrnd: ByteArray): ByteArray
    external fun slhInternalVerify(M: ByteArray, SIG: ByteArray, PK: ByteArray): Boolean

    //Interfaces externas (para uso directo en la app
    external fun slhKeyGen(): Array<ByteArray>
    external fun slhSign(M: ByteArray, ctx: ByteArray, SK: ByteArray): ByteArray
    external fun slhVerify(M: ByteArray, SIG: ByteArray, ctx: ByteArray, PK: ByteArray): Boolean

    // Todo : Implementar la version del algoritmo con preHashing
    external fun hashSlhSign(M: ByteArray, ctx: ByteArray, PH: ByteArray, SK: ByteArray): ByteArray
    external fun hashSlhVerify(M: ByteArray, SIG: ByteArray, ctx: ByteArray, PH: ByteArray, PK: ByteArray): Boolean

    // Clase auxiliar para tipar la informacion del esquema
    // HELPER: Función para extraer parámetros fácilmente
    fun getCurrentSchemaInfo(): SchemaInfo? {
        return try {
            val array = getCurrentParameters()

            val name = array[0] as String
            val intParams = array[1] as IntArray
            val isShake = array[2] as Boolean

            SchemaInfo(
                name = name,
                n = intParams[0],
                h = intParams[1],
                d = intParams[2],
                h_prima = intParams[3],
                a = intParams[4],
                k = intParams[5],
                lg_w = intParams[6],
                m = intParams[7],
                security_category = intParams[8],
                pk_bytes = intParams[9],
                sig_bytes = intParams[10],
                is_shake = isShake
            )
        } catch (e: Exception) {
            Log.e("FunctionLink", "Error parsing schema info: ${e.message}")
            null
        }
    }

    /**
     * Clase de datos para información del esquema
     */
    data class SchemaInfo(
        val name: String,
        val n: Int,
        val h: Int,
        val d: Int,
        val h_prima: Int,
        val a: Int,
        val k: Int,
        val lg_w: Int,
        val m: Int,
        val security_category: Int,
        val pk_bytes: Int,
        val sig_bytes: Int,
        val is_shake: Boolean
    )
}
