package com.revelacion1.tfg_parte1

class ADRSWrapper {
    // Carga la biblioteca nativa
    companion object {
        init {
            System.loadLibrary("TFG_PARTE1")
        }
    }
    // Puntero al objeto ADRS en C++ y referencia a FunctionLink
    private var nativePtr: Long = 0
    private val functionLink = FunctionLink()

    // Constructor que crea una nueva instancia de ADRS en C++
    init {
        nativePtr = functionLink.createADRS() // Usar createADRS de FunctionLink
        if (nativePtr == 0L) {
            throw RuntimeException("No se pudo crear la instancia nativa de ADRS")
        }
    }

    // Método para liberar los recursos nativos
    fun dispose() {
        if (nativePtr != 0L) {
            functionLink.disposeADRS(nativePtr)
            nativePtr = 0L
        }
    }

    // Métodos que envuelven las funciones de FunctionLink
    fun setLayerAddress(layer: Int) {
        functionLink.setLayerAddress(nativePtr, layer)
    }

    fun setTreeAddress(tree: ByteArray) {
        if (tree.size != 12) {
            throw IllegalArgumentException("El array 'tree' debe tener 12 bytes")
        }
        functionLink.setTreeAddress(nativePtr, tree)
    }

    fun setTypeAndClear(type: Int) {
        functionLink.setTypeAndClear(nativePtr, type)
    }

    fun setKeyPairAddress(keyPair: Int) {
        functionLink.setKeyPairAddress(nativePtr, keyPair)
    }

    fun setChainAddress(chain: Int) {
        functionLink.setChainAddress(nativePtr, chain)
    }

    fun setTreeHeight(height: Int) {
        functionLink.setTreeHeight(nativePtr, height)
    }

    fun setHashAddress(hash: Int) {
        functionLink.setHashAddress(nativePtr, hash)
    }

    fun setTreeIndex(index: Int) {
        functionLink.setTreeIndex(nativePtr, index)
    }

    fun getKeyPairAddress(): Int {
        return functionLink.getKeyPairAddress(nativePtr).toInt()
    }

    fun getTreeIndex(): Int {
        return functionLink.getTreeIndex(nativePtr).toInt()
    }

    fun getAddressBytes(): ByteArray {
        return functionLink.getAddressBytes(nativePtr)
    }
}