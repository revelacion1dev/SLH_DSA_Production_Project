package com.revelacion1.tfg_parte1

class FIPS205Tester {
    init {
        System.loadLibrary("TFG_PARTE1") // Asegúrate de usar el nombre exacto de tu biblioteca
    }

    // Adaptación de tus métodos de prueba
    fun runAllTests(): List<TestResult> {
        val results = mutableListOf<TestResult>()

        // Test genLen2 (Al. 1)
        results.add(testGenLen2())

        // Test toInt (Al. 2)
        results.add(testToInt())

        // Test toByte (Al. 3)
        results.add(testToByte())

        // Test base2b (Al. 4)
        results.add(testBase2b())

        // Test roundTrip
        results.add(testRoundTripConversion())

        // Test ADRS (Data structure)
        results.add(testADRS())

        // Tests específicos con SHAKE256
        results.add(testWOTSWithSHAKE256())
        results.add(testFORSWithSHAKE256())
        results.add(testXMSSWithSHAKE256())
        results.add(testVectorsWithSHAKE256())

        return results
    }

    // Implementación de los métodos de test
    private fun testGenLen2(): TestResult {
        val testCases = listOf(
            Triple(16, 4, 3),
            Triple(24, 4, 3),
            Triple(32, 4, 3),
            Triple(8, 2, 4),
            Triple(32, 8, 2)
        )

        try {
            for ((n, lg_w, expected) in testCases) {
                val actual = FunctionLink().genLen2(n.toLong(), lg_w.toLong())
                if (actual != expected.toLong()) {
                    return TestResult("genLen2", false,
                        "Para n=$n, lg_w=$lg_w, se esperaba $expected pero se obtuvo $actual")
                }
            }
            return TestResult("genLen2", true, "Todos los casos de prueba pasaron")
        } catch (e: Exception) {
            return TestResult("genLen2", false, "Error: ${e.message}")
        }
    }

    private fun testToInt(): TestResult {
        try {
            // Test case 1: Simple value
            val testBytes1 = byteArrayOf(0x12, 0x34)
            val result1 = FunctionLink().toInt(testBytes1, 2)
            if (result1 != 0x1234L) {
                return TestResult("toInt", false, "Simple 2-byte value falló. Esperado: 0x1234, Obtenido: $result1")
            }

            // Test case 2: Maximum value for 4 bytes
            val testBytes2 = byteArrayOf(
                0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte()
            )
            val result2 = FunctionLink().toInt(testBytes2, 4)
            if (result2 != 0xFFFFFFFFL) {
                return TestResult("toInt", false, "Max 4-byte value falló. Esperado: 0xFFFFFFFF, Obtenido: $result2")
            }

            // Test case 3: Zero value
            val testBytes3 = byteArrayOf(0x00, 0x00, 0x00, 0x00)
            val result3 = FunctionLink().toInt(testBytes3, 4)
            if (result3 != 0L) {
                return TestResult("toInt", false, "Zero value falló. Esperado: 0, Obtenido: $result3")
            }

            return TestResult("toInt", true, "Todos los casos de prueba pasaron")
        } catch (e: Exception) {
            return TestResult("toInt", false, "Error: ${e.message}")
        }
    }

    private fun testToByte(): TestResult {
        try {
            val test = FunctionLink()

            // Test case 1: Simple value
            val bytes1 = test.toByte(0x1234L, 2)
            if (!bytes1.contentEquals(byteArrayOf(0x34, 0x12))) {  // Se invierte la posicion del contenido en memoria
                return TestResult("toByte", false,
                    "Simple 2-byte value falló. Esperado: [34, 12], Obtenido: ${bytes1.joinToString(", ") { String.format("%02X", it) }}")
            }

            // Test case 2: Large value
            val bytes2 = test.toByte(0xFFFFFFFFL, 4)
            val expectedBytes2 = byteArrayOf(0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte())
            if (!bytes2.contentEquals(expectedBytes2)) {
                return TestResult("toByte", false,
                    "Large 4-byte value falló. Esperado: [FF, FF, FF, FF], Obtenido: ${bytes2.joinToString(", ") { String.format("%02X", it) }}")
            }

            // Test case 3: Zero value
            val bytes3 = test.toByte(0L, 2)
            if (!bytes3.contentEquals(byteArrayOf(0x00, 0x00))) {
                return TestResult("toByte", false,
                    "Zero value falló. Esperado: [00, 00], Obtenido: ${bytes3.joinToString(", ") { String.format("%02X", it) }}")
            }

            // Test case 4: Odd number
            val bytes4 = test.toByte(0x123L, 2)
            if (!bytes4.contentEquals(byteArrayOf(0x23, 0x01))) {
                return TestResult("toByte", false,
                    "Odd number falló. Esperado: [23, 01], Obtenido: ${bytes4.joinToString(", ") { String.format("%02X", it) }}")
            }

            // Test case 5: Value with leading zeros requested
            val bytes5 = test.toByte(0x1L, 4)  // Pedir 4 bytes para un valor pequeño
            if (!bytes5.contentEquals(byteArrayOf(0x00, 0x00, 0x00, 0x01))) {
                return TestResult("toByte", false,
                    "Value with leading zeros falló. Esperado: [00, 00, 00, 01], Obtenido: ${bytes5.joinToString(", ") { String.format("%02X", it) }}")
            }

            return TestResult("toByte", true, "Todos los casos de prueba pasaron")
        } catch (e: Exception) {
            return TestResult("toByte", false, "Error: ${e.message}")
        }
    }

    // Test for algorithm 4 base2.
    private fun testBase2b(): TestResult {
        try {
            val test = FunctionLink()

            // Test case 1: Simple value with b=4
            // Entrada: [0x12, 0x34] con b=4, out_len=4
            // Siguiendo el algoritmo, debería producir [1, 2, 3, 4]
            val input1 = byteArrayOf(0x12, 0x34)
            val result1 = test.base2b(input1, 4, 4)
            val expected1 = intArrayOf(1, 2, 3, 4)
            if (!result1.contentEquals(expected1)) {
                return TestResult("base2b", false,
                    "Simple value con b=4 falló. Esperado: [1, 2, 3, 4], Obtenido: ${result1.joinToString(", ")}")
            }

            // Test case 2: Binary representation (b=1)
            // Entrada: [0xA5] (10100101 en binario) con b=1, out_len=8
            // Debería dar [1, 0, 1, 0, 0, 1, 0, 1]
            val input2 = byteArrayOf(0xA5.toByte())
            val result2 = test.base2b(input2, 1, 8)
            val expected2 = intArrayOf(1, 0, 1, 0, 0, 1, 0, 1)
            if (!result2.contentEquals(expected2)) {
                return TestResult("base2b", false,
                    "Binary representation falló. Esperado: [1, 0, 1, 0, 0, 1, 0, 1], Obtenido: ${result2.joinToString(", ")}")
            }

            // Test case 3: Large value with b=16
            // Entrada: [0x12, 0x34, 0x56, 0x78] con b=16, out_len=2
            // Siguiendo el algoritmo: [0x1234, 0x5678]
            val input4 = byteArrayOf(0x12, 0x34, 0x56, 0x78)
            val result4 = test.base2b(input4, 16, 2)
            val expected4 = intArrayOf(0x1234, 0x5678)
            if (!result4.contentEquals(expected4)) {
                return TestResult("base2b", false,
                    "Large value con b=16 falló. Esperado: [4660, 22136], Obtenido: ${result4.joinToString(", ")}")
            }

            // Test case 5: Zero bytes
            // Entrada: [0x00, 0x00] con b=8, out_len=2
            // Esto debería producir [0, 0]
            val input5 = byteArrayOf(0x00, 0x00)
            val result5 = test.base2b(input5, 8, 2)
            val expected5 = intArrayOf(0, 0)
            if (!result5.contentEquals(expected5)) {
                return TestResult("base2b", false,
                    "Zero bytes falló. Esperado: [0, 0], Obtenido: ${result5.joinToString(", ")}")
            }

            return TestResult("base2b", true, "Todos los casos de prueba pasaron")
        } catch (e: Exception) {
            return TestResult("base2b", false, "Error: ${e.message}")
        }
    }

    private fun testRoundTripConversion(): TestResult {
        try {
            val test = FunctionLink()
            // Valor de prueba: 0x123456
            val originalValue = 0x123456L

            // Convertir a bytes usando toByte
            val byteArray = test.toByte(originalValue, 3)

            // Para little-endian, el orden esperado sería [0x56, 0x34, 0x12]
            val expectedBytes = byteArrayOf(0x56.toByte(), 0x34.toByte(), 0x12.toByte())

            // Verificar que los bytes están en el orden esperado (little-endian)
            if (!byteArray.contentEquals(expectedBytes)) {
                return TestResult("RoundTripConversion", false,
                    "Orden de bytes incorrecto. Esperado: [56, 34, 12], Obtenido: ${
                        byteArray.joinToString(", ") { "0x" + it.toInt().and(0xFF).toString(16).padStart(2, '0') }
                    }")
            }

            // Ahora, para que la conversión ida y vuelta funcione correctamente
            // tenemos que asegurarnos de que toInt también interprete los bytes como little-endian
            // o invertir el array antes de llamar a toInt
            val bytesForToInt = byteArray.reversedArray() // Invertir para adaptarse a toInt (si espera big-endian)
            val convertedValue = test.toInt(bytesForToInt, 3)

            // Verificar que el valor resultante es igual al original
            if (originalValue != convertedValue) {
                return TestResult("RoundTripConversion", false,
                    "Conversión de ida y vuelta falló. Esperado: $originalValue (0x${originalValue.toString(16)}), " +
                            "Obtenido: $convertedValue (0x${convertedValue.toString(16)})")
            }

            return TestResult("RoundTripConversion", true, "Conversión de ida y vuelta exitosa")
        } catch (e: Exception) {
            return TestResult("RoundTripConversion", false, "Error: ${e.message}")
        }
    }

    private fun testADRS(): TestResult {
        val adrsWrapper = ADRSWrapper()

        try {
            // Verificar que la inicialización es correcta (todos ceros)
            var bytes = adrsWrapper.getAddressBytes()
            if (!bytes.all { it == 0.toByte() }) {
                return TestResult("ADRS", false,
                    "La inicialización de ADRS no es correcta. Bytes: ${bytesToHex(bytes)}")
            }

            // Probar setLayerAddress
            adrsWrapper.setLayerAddress(0x12345678)
            bytes = adrsWrapper.getAddressBytes()
            // Verificar orden big-endian (bytes más significativos primero)
            if (bytes[0] != 0x12.toByte() || bytes[1] != 0x34.toByte() ||
                bytes[2] != 0x56.toByte() || bytes[3] != 0x78.toByte()) {
                return TestResult("ADRS", false,
                    "setLayerAddress no funcionó correctamente. Bytes: ${bytesToHex(bytes)}")
            }

            // Convertir un valor a bytes para setTreeAddress (12bytes)
            val treeValue = 0x123456789ABCL
            val treeBytes = ByteArray(12)
            // Llenar en orden big-endian
            for (i in 0 until 6) {
                treeBytes[i] = ((treeValue shr (8 * (5 - i))) and 0xFF).toByte()
            }
            // Rellenar el resto con ceros
            for (i in 6 until 12) {
                treeBytes[i] = 0
            }
            adrsWrapper.setTreeAddress(treeBytes)
            bytes = adrsWrapper.getAddressBytes()

            // Verificar los bytes en orden big-endian
            if (bytes[4] != 0x12.toByte() || bytes[5] != 0x34.toByte() ||
                bytes[6] != 0x56.toByte() || bytes[7] != 0x78.toByte() ||
                bytes[8] != 0x9A.toByte() || bytes[9] != 0xBC.toByte()) {
                return TestResult("ADRS", false,
                    "setTreeAddress no funcionó correctamente. Bytes: ${bytesToHex(bytes)}")
            }

            // Probar setTypeAndClear (tipo 2)
            adrsWrapper.setTypeAndClear(2)
            bytes = adrsWrapper.getAddressBytes()
            // En big-endian, el valor 2 sería 00 00 00 02
            if (bytes[16] != 0x00.toByte() || bytes[17] != 0x00.toByte() ||
                bytes[18] != 0x00.toByte() || bytes[19] != 0x02.toByte()) {
                return TestResult("ADRS", false,
                    "setTypeAndClear no estableció el tipo correctamente. Bytes: ${bytesToHex(bytes)}")
            }

            // Verificar que los bytes 20-31 están a cero
            for (i in 20..31) {
                if (bytes[i] != 0.toByte()) {
                    return TestResult("ADRS", false,
                        "setTypeAndClear no puso a cero los bytes 20-31. Bytes: ${bytesToHex(bytes)}")
                }
            }

            // Probar setKeyPairAddress con un entero (Int)
            val keyPairValue: Int = 0xABCD  // Valor entero explícito (Int en Kotlin)
            adrsWrapper.setKeyPairAddress(keyPairValue)
            bytes = adrsWrapper.getAddressBytes()

            // Verificamos que los bytes se almacenen correctamente en big-endian
            // 0xABCD en big-endian debería ser 00 00 AB CD
            if (bytes[20] != 0x00.toByte() || bytes[21] != 0x00.toByte() ||
                bytes[22] != 0xAB.toByte() || bytes[23] != 0xCD.toByte()) {
                return TestResult("ADRS", false,
                    "setKeyPairAddress no funcionó correctamente. Bytes: ${bytesToHex(bytes)}")
            }

            // Obtener y verificar el KeyPairAddress
            val kpAddr = adrsWrapper.getKeyPairAddress()
            if (kpAddr != 0xABCD) {
                return TestResult("ADRS", false,
                    "getKeyPairAddress debería devolver 0xABCD, pero devolvió $kpAddr")
            }

            // Probar setChainAddress
            adrsWrapper.setChainAddress(0x1234)
            bytes = adrsWrapper.getAddressBytes()
            // En big-endian sería 00 00 12 34
            if (bytes[24] != 0x00.toByte() || bytes[25] != 0x00.toByte() ||
                bytes[26] != 0x12.toByte() || bytes[27] != 0x34.toByte()) {
                return TestResult("ADRS", false,
                    "setChainAddress no funcionó correctamente. Bytes: ${bytesToHex(bytes)}")
            }

            // Probar setHashAddress
            adrsWrapper.setHashAddress(0x5678)
            bytes = adrsWrapper.getAddressBytes()
            // En big-endian sería 00 00 56 78
            if (bytes[28] != 0x00.toByte() || bytes[29] != 0x00.toByte() ||
                bytes[30] != 0x56.toByte() || bytes[31] != 0x78.toByte()) {
                return TestResult("ADRS", false,
                    "setHashAddress no funcionó correctamente. Bytes: ${bytesToHex(bytes)}")
            }

            // Probar setTreeHeight (modifica los mismos bytes que setChainAddress)
            adrsWrapper.setTreeHeight(0x9ABC)
            bytes = adrsWrapper.getAddressBytes()
            // En big-endian sería 00 00 9A BC
            if (bytes[24] != 0x00.toByte() || bytes[25] != 0x00.toByte() ||
                bytes[26] != 0x9A.toByte() || bytes[27] != 0xBC.toByte()) {
                return TestResult("ADRS", false,
                    "setTreeHeight no funcionó correctamente. Bytes: ${bytesToHex(bytes)}")
            }

            // Probar setTreeIndex (modifica los mismos bytes que setHashAddress)
            adrsWrapper.setTreeIndex(0xDEF0)
            bytes = adrsWrapper.getAddressBytes()
            // En big-endian sería 00 00 DE F0
            if (bytes[28] != 0x00.toByte() || bytes[29] != 0x00.toByte() ||
                bytes[30] != 0xDE.toByte() || bytes[31] != 0xF0.toByte()) {
                return TestResult("ADRS", false,
                    "setTreeIndex no funcionó correctamente. Bytes: ${bytesToHex(bytes)}")
            }

            // Obtener y verificar el TreeIndex
            val treeIdx = adrsWrapper.getTreeIndex()
            if (treeIdx != 0xDEF0) {
                return TestResult("ADRS", false,
                    "getTreeIndex debería devolver 0xDEF0, pero devolvió $treeIdx")
            }

            return TestResult("ADRS", true, "Todas las pruebas de ADRS han pasado correctamente")
        } catch (e: Exception) {
            return TestResult("ADRS", false, "Error: ${e.message}")
        } finally {
            // Liberar recursos
            adrsWrapper.dispose()
        }
    }

    private fun testWOTSWithSHAKE256(): TestResult {
        try {
            // Parámetros WOTS+ con SHAKE256
            val n = 32 // Tamaño de salida del hash en bytes (256 bits)
            val lg_w = 4 // log2(w) = 4 para w=16

            // Calcular len1 y len2 según FIPS 205
            val len1 = (8 * n + lg_w - 1) / lg_w // ⌈8n/lg_w⌉
            val len2 = FunctionLink().genLen2(n.toLong(), lg_w.toLong()).toInt()
            val len = len1 + len2

            // Vector de prueba para SHAKE256
            // (Estos son valores de ejemplo, en un caso real usarías vectores oficiales)
            val skSeed = ByteArray(n) { 0x12 } // Semilla secreta constante
            val pkSeed = ByteArray(n) { 0x34 } // Semilla pública constante

            // Crear y configurar ADRS
            val adrs = ADRSWrapper()
            adrs.setLayerAddress(0)
            adrs.setTreeAddress(ByteArray(12) { 0 })
            adrs.setTypeAndClear(0) // WOTS_PRF
            adrs.setKeyPairAddress(0)

            // Generar clave pública WOTS+
            val pk = FunctionLink().wots_pkGen(skSeed, pkSeed, adrs.getAddressBytes())

            // Verificar el tamaño de la clave pública
            if (pk.size != n) {
                return TestResult("WOTS+ (SHAKE256)", false,
                    "Tamaño de clave pública incorrecto. Esperado: $n, Obtenido: ${pk.size}")
            }

            // Mensaje para firmar (usando un valor determinista para reproducibilidad)
            val message = ByteArray(n) { 0x56 }

            // Establecer ADRS para firma
            adrs.setTypeAndClear(0) // WOTS_PRF para firma

            // Generar firma WOTS+
            val signature = FunctionLink().wots_sign(message, skSeed, pkSeed, adrs.getAddressBytes())

            // Verificar tamaño de firma
            val expectedSigSize = len * n
            if (signature.size != expectedSigSize) {
                return TestResult("WOTS+ (SHAKE256)", false,
                    "Tamaño de firma incorrecto. Esperado: $expectedSigSize, Obtenido: ${signature.size}")
            }

            // Configurar ADRS para verificación
            adrs.setTypeAndClear(1) // WOTS_HASH para verificación

            // Verificar firma reconstruyendo la clave pública
            val reconstructedPk = FunctionLink().wots_pkFromSig(signature, message, pkSeed, adrs.getAddressBytes())

            // Comparar la clave reconstruida con la original
            if (!reconstructedPk.contentEquals(pk)) {
                return TestResult("WOTS+ (SHAKE256)", false,
                    "La clave pública reconstruida no coincide con la original")
            }

            // Prueba con mensaje modificado
            val modifiedMessage = message.clone()
            modifiedMessage[0] = (modifiedMessage[0] + 1).toByte()

            val reconstructedPkForModified = FunctionLink().wots_pkFromSig(
                signature, modifiedMessage, pkSeed, adrs.getAddressBytes())

            if (reconstructedPkForModified.contentEquals(pk)) {
                return TestResult("WOTS+ (SHAKE256)", false,
                    "La firma debería fallar con mensaje modificado, pero fue válida")
            }

            // Imprimir resultados exitosos con valores específicos para referencia
            val pkHex = pk.joinToString("") { String.format("%02x", it) }
            val sigHex = signature.take(32).toByteArray().joinToString("") { String.format("%02x", it) }

            return TestResult("WOTS+ (SHAKE256)", true,
                "Prueba exitosa. PK: ${pkHex.take(16)}..., SIG: ${sigHex.take(16)}...")
        } catch (e: Exception) {
            return TestResult("WOTS+ (SHAKE256)", false, "Error: ${e.message}")
        }
    }

    // Helper para formatear bytes en hexadecimal
    private fun bytesToHex(bytes: ByteArray): String {
        return bytes.joinToString("") { String.format("%02X", it) }
    }

    // Clase para representar resultados de tests
    data class TestResult(
        val testName: String,
        val passed: Boolean,
        val message: String
    )
}