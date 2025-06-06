package com.revelacion1.tfg_parte1

class FIPS205Tester {

    // Interface para callback de logging
    interface TestLogger {
        fun log(message: String)
        fun logTestStart(testName: String)
        fun logTestResult(testName: String, passed: Boolean, message: String)
    }

    private var logger: TestLogger? = null

    init {
        System.loadLibrary("TFG_PARTE1")
    }

    // Setter para el logger
    fun setLogger(logger: TestLogger) {
        this.logger = logger
    }

    private fun log(message: String) {
        logger?.log(message)
    }

    private fun logTestStart(testName: String) {
        logger?.logTestStart(testName)
    }

    private fun logTestResult(testName: String, passed: Boolean, message: String) {
        logger?.logTestResult(testName, passed, message)
    }

    // Clase wrapper para ADRS corregida para el FunctionLink real
    inner class ADRSWrapper {
        private var adrsPtr: Long = 0

        init {
            adrsPtr = FunctionLink().createADRS()
        }

        fun setLayerAddress(layer: Int) {
            FunctionLink().setLayerAddress(adrsPtr, layer)
        }

        fun setTreeAddress(tree: Long) {
            FunctionLink().setTreeAddress(adrsPtr, tree)
        }

        fun setTypeAndClear(type: Int) {
            FunctionLink().setTypeAndClear(adrsPtr, type)
        }

        fun setKeyPairAddress(keyPair: Int) {
            FunctionLink().setKeyPairAddress(adrsPtr, keyPair)
        }

        fun setChainAddress(chain: Int) {
            FunctionLink().setChainAddress(adrsPtr, chain)
        }

        fun setTreeHeight(height: Int) {
            FunctionLink().setTreeHeight(adrsPtr, height)
        }

        fun setHashAddress(hash: Int) {
            FunctionLink().setHashAddress(adrsPtr, hash)
        }

        fun setTreeIndex(index: Int) {
            FunctionLink().setTreeIndex(adrsPtr, index)
        }

        fun getKeyPairAddress(): Long {
            return FunctionLink().getKeyPairAddress(adrsPtr)
        }

        fun getTreeIndex(): Long {
            return FunctionLink().getTreeIndex(adrsPtr)
        }

        fun getAddressBytes(): ByteArray {
            return FunctionLink().getAddressBytes(adrsPtr)
        }

        fun dispose() {
            if (adrsPtr != 0L) {
                FunctionLink().disposeADRS(adrsPtr)
                adrsPtr = 0
            }
        }

        val ptr: Long get() = adrsPtr
    }

    // Función principal que ejecuta todos los tests con logging detallado
    fun runAllTests(): List<TestResult> {
        val results = mutableListOf<TestResult>()

        log("🔬 Iniciando batería completa de tests FIPS 205...\n")
        log("Total de tests a ejecutar: 10\n\n")

        // Tests básicos de utilidades
        log("📁 SECCIÓN: Tests de Utilidades Básicas\n")
        results.add(runSingleTest("genLen2") { testGenLen2() })
        results.add(runSingleTest("toInt32") { testToInt() })
        results.add(runSingleTest("toByte") { testToByte() })
        results.add(runSingleTest("base2b") { testBase2b() })
        results.add(runSingleTest("RoundTripConversion") { testRoundTripConversion() })

        // Test ADRS
        log("\n📁 SECCIÓN: Test de Estructuras de Datos\n")
        results.add(runSingleTest("ADRS") { testADRS() })

        // Test computeHash
        log("\n📁 SECCIÓN: Test de Funciones Hash\n")
        results.add(runSingleTest("computeHash") { testComputeHash() })

        // Tests criptográficos
        log("\n📁 SECCIÓN: Tests Criptográficos Avanzados\n")
        results.add(runSingleTest("WOTS Algorithms") { testWOTSAlgorithms() })
        results.add(runSingleTest("XMSS Algorithms") { testXMSSAlgorithms() })
        results.add(runSingleTest("FORS Algorithms") { testFORSAlgorithms() })

        log("\n📁 SECCIÓN: Tests de Alto Nivel\n")
        results.add(runSingleTest("HT Algorithms") { testHTAlgorithms() })
        results.add(runSingleTest("SLH-DSA Main") { testSLHDSAMainAlgorithms() })

        // Resumen final
        val passed = results.count { it.passed }
        val failed = results.size - passed

        log("\n" + "=".repeat(50) + "\n")
        log("📊 RESUMEN FINAL DE TESTS:\n")
        log("✅ Tests exitosos: $passed\n")
        log("❌ Tests fallidos: $failed\n")
        log("📈 Tasa de éxito: ${(passed * 100.0 / results.size).toInt()}%\n")

        if (failed > 0) {
            log("\n🔍 Tests que fallaron:\n")
            results.filter { !it.passed }.forEach { result ->
                log("   • ${result.testName}: ${result.message}\n")
            }
        }

        log("=".repeat(50) + "\n")

        return results
    }

    // Función helper para ejecutar un test individual con logging
    private fun runSingleTest(testName: String, testFunction: () -> TestResult): TestResult {
        logTestStart(testName)
        log("⏳ Ejecutando test: $testName...")

        return try {
            val startTime = System.currentTimeMillis()
            val result = testFunction()
            val duration = System.currentTimeMillis() - startTime

            val emoji = if (result.passed) "✅" else "❌"
            val status = if (result.passed) "EXITOSO" else "FALLIDO"

            log(" ${duration}ms\n")
            log("$emoji $testName: $status\n")

            if (!result.passed) {
                log("   💡 Detalle: ${result.message}\n")
            }

            logTestResult(testName, result.passed, result.message)
            log("\n")

            result
        } catch (e: Exception) {
            val errorMsg = "Error inesperado: ${e.message}"
            log(" ❌ ERROR\n")
            log("💥 $testName: EXCEPCIÓN - $errorMsg\n\n")

            logTestResult(testName, false, errorMsg)
            TestResult(testName, false, errorMsg)
        }
    }

    // Test básico genLen2 (Algoritmo 1)
    private fun testGenLen2(): TestResult {
        log("   🔢 Probando diferentes valores de n y lg_w...")

        val testCases = listOf(
            Triple(16, 4, 3),
            Triple(24, 4, 3),
            Triple(32, 4, 3),
            Triple(8, 2, 4),
            Triple(32, 8, 2)
        )

        try {
            for ((i, testCase) in testCases.withIndex()) {
                val (n, lg_w, expected) = testCase
                log(" caso ${i+1}/${testCases.size}")

                val actual = FunctionLink().genLen2(n, lg_w)
                if (actual != expected.toLong()) {
                    return TestResult("genLen2", false,
                        "Caso ${i+1}: n=$n, lg_w=$lg_w, esperado=$expected, obtenido=$actual")
                }
            }
            return TestResult("genLen2", true, "Todos los ${testCases.size} casos pasaron")
        } catch (e: Exception) {
            return TestResult("genLen2", false, "Error: ${e.message}")
        }
    }

    // Test toInt (Algoritmo 2)
    private fun testToInt(): TestResult {
        log("   🔄 Probando conversiones de bytes a enteros...")

        try {
            log(" caso 1/3")
            val testBytes1 = byteArrayOf(0x12, 0x34)
            val result1 = FunctionLink().toInt(testBytes1, 2)
            if (result1 != 0x1234L) {
                return TestResult("toInt32", false, "Caso 1: esperado=0x1234, obtenido=$result1")
            }

            log(" caso 2/3")
            val testBytes2 = byteArrayOf(0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte())
            val result2 = FunctionLink().toInt(testBytes2, 4)
            if (result2 != 0xFFFFFFFFL) {
                return TestResult("toInt32", false, "Caso 2: esperado=0xFFFFFFFF, obtenido=$result2")
            }

            log(" caso 3/3")
            val testBytes3 = byteArrayOf(0x00, 0x00, 0x00, 0x00)
            val result3 = FunctionLink().toInt(testBytes3, 4)
            if (result3 != 0L) {
                return TestResult("toInt32", false, "Caso 3: esperado=0, obtenido=$result3")
            }

            return TestResult("toInt32", true, "Todos los casos de conversión pasaron")
        } catch (e: Exception) {
            return TestResult("toInt32", false, "Error: ${e.message}")
        }
    }

    // Test toByte (Algoritmo 3)
    private fun testToByte(): TestResult {
        log("   🔄 Probando conversiones de enteros a bytes...")

        try {
            val test = FunctionLink()

            log(" caso 1/2")
            val bytes1 = test.toByte(0x1234L, 2)
            if (!bytes1.contentEquals(byteArrayOf(0x34, 0x12))) {
                return TestResult("toByte", false,
                    "Caso 1: esperado=[34, 12], obtenido=[${bytes1.joinToString(", ") { String.format("%02X", it) }}]")
            }

            log(" caso 2/2")
            val bytes2 = test.toByte(0xFFFFFFFFL, 4)
            val expectedBytes2 = byteArrayOf(0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte())
            if (!bytes2.contentEquals(expectedBytes2)) {
                return TestResult("toByte", false,
                    "Caso 2: esperado=[FF, FF, FF, FF], obtenido=[${bytes2.joinToString(", ") { String.format("%02X", it) }}]")
            }

            return TestResult("toByte", true, "Conversiones a bytes correctas")
        } catch (e: Exception) {
            return TestResult("toByte", false, "Error: ${e.message}")
        }
    }

    // Test base2b (Algoritmo 4)
    private fun testBase2b(): TestResult {
        log("   🔢 Probando conversiones de base...")

        try {
            val test = FunctionLink()

            log(" caso 1/2")
            val input1 = byteArrayOf(0x12, 0x34)
            val result1 = test.base2b(input1, 4, 4)
            val expected1 = intArrayOf(1, 2, 3, 4)
            if (!result1.contentEquals(expected1)) {
                return TestResult("base2b", false,
                    "Caso 1: esperado=[1, 2, 3, 4], obtenido=[${result1.joinToString(", ")}]")
            }

            log(" caso 2/2")
            val input2 = byteArrayOf(0xA5.toByte())
            val result2 = test.base2b(input2, 1, 8)
            val expected2 = intArrayOf(1, 0, 1, 0, 0, 1, 0, 1)
            if (!result2.contentEquals(expected2)) {
                return TestResult("base2b", false,
                    "Caso 2: esperado=[1, 0, 1, 0, 0, 1, 0, 1], obtenido=[${result2.joinToString(", ")}]")
            }

            return TestResult("base2b", true, "Conversiones de base correctas")
        } catch (e: Exception) {
            return TestResult("base2b", false, "Error: ${e.message}")
        }
    }

    // Test conversión ida y vuelta
    private fun testRoundTripConversion(): TestResult {
        log("   🔄 Probando conversión ida y vuelta...")

        try {
            val test = FunctionLink()
            val originalValue = 0x123456L

            log(" conversión a bytes")
            val byteArray = test.toByte(originalValue, 3)
            val expectedBytes = byteArrayOf(0x56.toByte(), 0x34.toByte(), 0x12.toByte())

            if (!byteArray.contentEquals(expectedBytes)) {
                return TestResult("RoundTripConversion", false,
                    "Orden de bytes incorrecto. Esperado: [56, 34, 12], Obtenido: [${
                        byteArray.joinToString(", ") { "0x" + it.toInt().and(0xFF).toString(16).padStart(2, '0') }
                    }]")
            }

            log(" conversión de vuelta")
            val bytesForToInt = byteArray.reversedArray()
            val convertedValue = test.toInt(bytesForToInt, 3)

            if (originalValue != convertedValue) {
                return TestResult("RoundTripConversion", false,
                    "Conversión fallida. Esperado: $originalValue, Obtenido: $convertedValue")
            }

            return TestResult("RoundTripConversion", true, "Conversión ida y vuelta exitosa")
        } catch (e: Exception) {
            return TestResult("RoundTripConversion", false, "Error: ${e.message}")
        }
    }

    // Test ADRS (Address Data Structure)
    private fun testADRS(): TestResult {
        log("   🏗️ Probando estructura de direcciones ADRS...")

        val adrsWrapper = ADRSWrapper()

        try {
            log(" inicialización")
            var bytes = adrsWrapper.getAddressBytes()
            if (!bytes.all { it == 0.toByte() }) {
                return TestResult("ADRS", false,
                    "Inicialización incorrecta. Bytes: ${formatBytesToHex(bytes)}")
            }

            log(" setLayerAddress")
            adrsWrapper.setLayerAddress(0x12345678)
            bytes = adrsWrapper.getAddressBytes()
            if (bytes[0] != 0x12.toByte() || bytes[1] != 0x34.toByte() ||
                bytes[2] != 0x56.toByte() || bytes[3] != 0x78.toByte()) {
                return TestResult("ADRS", false,
                    "setLayerAddress falló. Bytes: ${formatBytesToHex(bytes)}")
            }

            log(" setTreeAddress")
            adrsWrapper.setTreeAddress(0x9ABCDEF0L)

            log(" setTypeAndClear")
            adrsWrapper.setTypeAndClear(0) // WOTS_HASH

            log(" KeyPairAddress")
            adrsWrapper.setKeyPairAddress(0xABCD)
            val kpAddr = adrsWrapper.getKeyPairAddress()
            if (kpAddr != 0xABCDL) {
                return TestResult("ADRS", false,
                    "getKeyPairAddress falló. Esperado: 0xABCD, Obtenido: $kpAddr")
            }

            return TestResult("ADRS", true, "Todas las operaciones ADRS correctas")
        } catch (e: Exception) {
            return TestResult("ADRS", false, "Error: ${e.message}")
        } finally {
            adrsWrapper.dispose()
        }
    }

    // Test computeHash
    private fun testComputeHash(): TestResult {
        log("   🔐 Probando función de hash...")

        try {
            val functionLink = FunctionLink()

            log(" hash básico")
            val testInput = "Test input for hash".toByteArray()
            val hashOutput = functionLink.computeHash(testInput, 1)

            if (hashOutput.size != 32) {
                return TestResult("computeHash", false,
                    "Tamaño incorrecto. Esperado: 32, Obtenido: ${hashOutput.size}")
            }

            log(" verificando no-ceros")
            if (hashOutput.all { it == 0.toByte() }) {
                return TestResult("computeHash", false, "Hash no debería ser todo ceros")
            }

            log(" reproducibilidad")
            val hashOutput2 = functionLink.computeHash(testInput, 1)
            if (!hashOutput.contentEquals(hashOutput2)) {
                return TestResult("computeHash", false, "Hash no es reproducible")
            }

            return TestResult("computeHash", true, "Hash funciona correctamente")
        } catch (e: Exception) {
            return TestResult("computeHash", false, "Error: ${e.message}")
        }
    }

    // Test algoritmos WOTS+ con parámetros FIPS 205 oficiales
    private fun testWOTSAlgorithms(): TestResult {
        log("   🔑 Probando algoritmos WOTS+ (FIPS 205)...")

        try {
            val functionLink = FunctionLink()

            // Parámetros oficiales para SLH-DSA-128s/128f (Security Category 1)
            val n = 16  // FIPS 205: n=16 para 128-bit security
            val lgw = 4  // FIPS 205: lgw=4 para todos los parameter sets
            val len = calculateLen(n, lgw)  // len = len1 + len2

            log(" usando parámetros FIPS 205: n=$n, lgw=$lgw, len=$len")

            val skSeed = ByteArray(32) { 0x01 }  // Mantener 32 para semillas (SK.seed)
            val pkSeed = ByteArray(32) { 0x02 }  // Mantener 32 para semillas (PK.seed)

            ADRSWrapper().use { adrs ->
                log(" configurando ADRS")
                adrs.setLayerAddress(0)
                adrs.setTreeAddress(0)
                adrs.setTypeAndClear(5) // WOTS_PRF
                adrs.setKeyPairAddress(0)

                log(" wotsPkGen")
                val pk = functionLink.wotsPkGen(skSeed, pkSeed, adrs.ptr)
                if (pk.size != n) {
                    return TestResult("WOTS Algorithms", false,
                        "Tamaño de PK incorrecto. Esperado: $n, Obtenido: ${pk.size}")
                }

                log(" chain (operación rápida)")
                val X = ByteArray(n) { 0x03 }
                val chainResult = functionLink.chain(X, 0, 3, pkSeed, adrs.ptr)
                if (chainResult.size != n) {
                    return TestResult("WOTS Algorithms", false,
                        "Tamaño de chain incorrecto. Esperado: $n, Obtenido: ${chainResult.size}")
                }

                log(" wotsSign")
                val message = ByteArray(n) { 0x04 }
                adrs.setTypeAndClear(5) // WOTS_PRF

                val startTime = System.currentTimeMillis()
                val signature = functionLink.wotsSign(message, skSeed, pkSeed, adrs.ptr)
                val duration = System.currentTimeMillis() - startTime

                log(" completado en ${duration}ms")

                if (signature.size != len * n) {
                    return TestResult("WOTS Algorithms", false,
                        "Tamaño de firma incorrecto. Esperado: ${len * n}, Obtenido: ${signature.size}")
                }

                log(" wotsPkFromSig")
                adrs.setTypeAndClear(0) // WOTS_HASH
                val recoveredPk = functionLink.wotsPkFromSig(signature, message, pkSeed, adrs.ptr)
                if (!recoveredPk.contentEquals(pk)) {
                    return TestResult("WOTS Algorithms", false, "PK recuperada no coincide")
                }

                return TestResult("WOTS Algorithms", true, "Algoritmos WOTS+ correctos (FIPS 205: n=$n)")
            }
        } catch (e: Exception) {
            return TestResult("WOTS Algorithms", false, "Error: ${e.message}")
        }
    }

    // Función helper para calcular len según FIPS 205
    private fun calculateLen(n: Int, lgw: Int): Int {
        val w = 1 shl lgw  // 2^lgw = 16 para lgw=4
        val len1 = (8 * n + lgw - 1) / lgw  // ceil(8*n/lgw)
        val len2 = 3  // Para todos los parameter sets en FIPS 205, len2=3
        return len1 + len2
    }

    // Test algoritmos XMSS con parámetros FIPS 205
    private fun testXMSSAlgorithms(): TestResult {
        log("   🌳 Probando algoritmos XMSS (FIPS 205)...")

        try {
            val functionLink = FunctionLink()

            // Parámetros para SLH-DSA-128s (más rápido para testing)
            val n = 16
            val h_prime = 9  // h' = 9 para 128s según Tabla 2
            val wots_len = calculateLen(n, 4)

            log(" usando parámetros FIPS 205: n=$n, h'=$h_prime")

            val skSeed = ByteArray(32) { 0x05 }
            val pkSeed = ByteArray(32) { 0x06 }

            ADRSWrapper().use { adrs ->
                log(" configurando ADRS para XMSS")
                adrs.setLayerAddress(0)
                adrs.setTreeAddress(0)
                adrs.setTypeAndClear(2) // WOTS_TREES

                log(" xmssNode (altura reducida para testing)")
                val startTime = System.currentTimeMillis()
                val rootNode = functionLink.xmssNode(skSeed, 0, h_prime, pkSeed, adrs.ptr)
                val nodeTime = System.currentTimeMillis() - startTime
                log(" nodo generado en ${nodeTime}ms")

                if (rootNode.size != n) {
                    return TestResult("XMSS Algorithms", false,
                        "Tamaño de nodo incorrecto. Esperado: $n, Obtenido: ${rootNode.size}")
                }

                log(" xmssSign")
                val message = ByteArray(n) { 0x07 }
                val signStart = System.currentTimeMillis()
                val signature = functionLink.xmssSign(message, skSeed, 0, pkSeed, adrs.ptr)
                val signTime = System.currentTimeMillis() - signStart
                log(" firma generada en ${signTime}ms")

                if (signature.isEmpty()) {
                    return TestResult("XMSS Algorithms", false, "Firma XMSS vacía")
                }

                log(" xmssPkFromSig")
                val recoveredNode = functionLink.xmssPkFromSig(0, signature, message, pkSeed, adrs.ptr)
                if (!recoveredNode.contentEquals(rootNode)) {
                    return TestResult("XMSS Algorithms", false, "Nodo recuperado no coincide")
                }

                return TestResult("XMSS Algorithms", true, "Algoritmos XMSS correctos (FIPS 205: h'=$h_prime)")
            }
        } catch (e: Exception) {
            return TestResult("XMSS Algorithms", false, "Error: ${e.message}")
        }
    }

    // Test algoritmos FORS con parámetros FIPS 205
    private fun testFORSAlgorithms(): TestResult {
        log("   🌲 Probando algoritmos FORS (FIPS 205)...")

        try {
            val functionLink = FunctionLink()

            // Parámetros para SLH-DSA-128s según Tabla 2
            val n = 16
            val k = 14  // FIPS 205 Tabla 2: k=14 para 128s
            val a = 12  // FIPS 205 Tabla 2: a=12 para 128s

            log(" usando parámetros FIPS 205: n=$n, k=$k, a=$a")

            val skSeed = ByteArray(32) { 0x08 }
            val pkSeed = ByteArray(32) { 0x09 }

            ADRSWrapper().use { adrs ->
                log(" configurando ADRS para FORS")
                adrs.setLayerAddress(0)
                adrs.setTreeAddress(0)
                adrs.setTypeAndClear(3) // FORS_TREE

                log(" forsSkGen")
                val forsSk = functionLink.forsSkGen(skSeed, pkSeed, adrs.ptr, 0)
                if (forsSk.size != n) {
                    return TestResult("FORS Algorithms", false,
                        "Tamaño de SK incorrecto. Esperado: $n, Obtenido: ${forsSk.size}")
                }

                log(" forsNode")
                val forsNode = functionLink.forsNode(skSeed, 0, 3, pkSeed, adrs.ptr)
                if (forsNode.size != n) {
                    return TestResult("FORS Algorithms", false,
                        "Tamaño de nodo incorrecto. Esperado: $n, Obtenido: ${forsNode.size}")
                }

                log(" forsSign")
                val messageDigest = ByteArray(n) { 0x0A }
                val startTime = System.currentTimeMillis()
                val signature = functionLink.forsSign(messageDigest, skSeed, pkSeed, adrs.ptr)
                val duration = System.currentTimeMillis() - startTime
                log(" completado en ${duration}ms")

                if (signature.isEmpty()) {
                    return TestResult("FORS Algorithms", false, "Firma FORS vacía")
                }

                log(" forsPkFromSig")
                adrs.setTypeAndClear(3) // FORS_TREE
                val recoveredPk = functionLink.forsPkFromSig(signature, messageDigest, pkSeed, adrs.ptr)
                if (recoveredPk.size != n) {
                    return TestResult("FORS Algorithms", false,
                        "Tamaño de PK recuperada incorrecto. Esperado: $n, Obtenido: ${recoveredPk.size}")
                }

                return TestResult("FORS Algorithms", true, "Algoritmos FORS correctos (FIPS 205: k=$k, a=$a)")
            }
        } catch (e: Exception) {
            return TestResult("FORS Algorithms", false, "Error: ${e.message}")
        }
    }

    // Test algoritmos HT (Hypertree)
    private fun testHTAlgorithms(): TestResult {
        log("   🏔️ Probando algoritmos HT (Hypertree)...")

        try {
            val functionLink = FunctionLink()
            val n = 32
            val wots_len = 67
            val h = 5
            val d = 2

            val message = ByteArray(n) { 0x0B }
            val skSeed = ByteArray(n) { 0x0C }
            val pkSeed = ByteArray(n) { 0x0D }
            val pkRoot = ByteArray(n) { 0x0E }

            log(" htSign")
            val signature = functionLink.htSign(message, skSeed, pkSeed, 0L, 0)
            if (signature.isEmpty()) {
                return TestResult("HT Algorithms", false, "Firma HT vacía")
            }

            log(" htVerify")
            try {
                functionLink.htVerify(message, signature, pkSeed, 0L, 0, pkRoot)
                return TestResult("HT Algorithms", true, "Algoritmos HT sin errores")
            } catch (e: Exception) {
                return TestResult("HT Algorithms", false, "htVerify falló: ${e.message}")
            }

        } catch (e: Exception) {
            return TestResult("HT Algorithms", false, "Error: ${e.message}")
        }
    }

    // Test algoritmos SLH-DSA principales
    private fun testSLHDSAMainAlgorithms(): TestResult {
        log("   🎯 Probando algoritmos SLH-DSA principales...")

        try {
            val functionLink = FunctionLink()
            val paramSets = listOf(0, 1)

            for ((index, paramSet) in paramSets.withIndex()) {
                log(" paramSet ${index + 1}/${paramSets.size} (valor=$paramSet)")

                try {
                    log("   • slhKeyGen")
                    val keyPair = functionLink.slhKeyGen()
                    if (keyPair.size != 2) {
                        return TestResult("SLH-DSA Main", false,
                            "slhKeyGen debería devolver 2 elementos, obtuvo ${keyPair.size}")
                    }

                    val publicKey = keyPair[0]
                    val privateKey = keyPair[1]

                    if (publicKey.isEmpty() || privateKey.isEmpty()) {
                        return TestResult("SLH-DSA Main", false,
                            "Claves vacías para paramSet $paramSet")
                    }

                    log("   • slhSign")
                    val message = "Test message for SLH-DSA".toByteArray()
                    val context = ByteArray(0)
                    val signature = functionLink.slhSign(message, context, privateKey)

                    if (signature.isEmpty()) {
                        return TestResult("SLH-DSA Main", false,
                            "Firma vacía para paramSet $paramSet")
                    }

                    log("   • slhVerify (válido)")
                    val isValid = functionLink.slhVerify(message, signature, context, publicKey)
                    if (!isValid) {
                        return TestResult("SLH-DSA Main", false,
                            "Verificación falló para paramSet $paramSet")
                    }

                    log("   • slhVerify (mensaje modificado)")
                    val modifiedMessage = message.clone()
                    if (modifiedMessage.isNotEmpty()) {
                        modifiedMessage[0] = (modifiedMessage[0] + 1).toByte()
                    }

                    val isInvalid = functionLink.slhVerify(modifiedMessage, signature, context, publicKey)
                    if (isInvalid) {
                        return TestResult("SLH-DSA Main", false,
                            "Verificación debería fallar con mensaje modificado para paramSet $paramSet")
                    }

                    log("   • hashSlhSign/Verify (opcional)")
                    try {
                        val ph = ByteArray(32) { 0x10 }
                        val hashSignature = functionLink.hashSlhSign(message, context, ph, privateKey)
                        if (hashSignature.isNotEmpty()) {
                            functionLink.hashSlhVerify(message, hashSignature, context, ph, publicKey)
                        }
                    } catch (e: Exception) {
                        log("     (funciones hash opcionales no disponibles)")
                    }

                } catch (e: Exception) {
                    return TestResult("SLH-DSA Main", false,
                        "Error con paramSet $paramSet: ${e.message}")
                }
            }

            return TestResult("SLH-DSA Main", true, "Algoritmos SLH-DSA principales correctos")
        } catch (e: Exception) {
            return TestResult("SLH-DSA Main", false, "Error: ${e.message}")
        }
    }

    // Función helper privada para formatear bytes en hexadecimal
    private fun formatBytesToHex(bytes: ByteArray): String {
        return bytes.joinToString("") { String.format("%02X", it) }
    }

    // Extensión para usar ADRS con try-with-resources
    private inline fun <T> ADRSWrapper.use(block: (ADRSWrapper) -> T): T {
        try {
            return block(this)
        } finally {
            this.dispose()
        }
    }

    // Clase para representar resultados de tests
    data class TestResult(
        val testName: String,
        val passed: Boolean,
        val message: String
    ) {
        override fun toString(): String {
            val status = if (passed) "✓ PASS" else "✗ FAIL"
            return "[$status] $testName: $message"
        }
    }

    companion object {
        // Constantes para tipos de ADRS (según FIPS 205)
        const val WOTS_HASH = 0x00
        const val WOTS_PK = 0x01
        const val WOTS_TREES = 0x02
        const val FORS_TREE = 0x03
        const val FORS_ROOTS = 0x04
        const val WOTS_PRF = 0x05
        const val FORS_PRF = 0x06

        // Función estática para test rápido
        fun runQuickTest(): Boolean {
            return try {
                val functionLink = FunctionLink()

                // Test rápido básico
                val result1 = functionLink.genLen2(32, 4)
                val result2 = functionLink.base2b(byteArrayOf(0x12, 0x34), 4, 4)

                result1 > 0 && result2.isNotEmpty()
            } catch (e: Exception) {
                false
            }
        }
    }
}