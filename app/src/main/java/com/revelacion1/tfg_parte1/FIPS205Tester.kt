package com.revelacion1.tfg_parte1

class FIPS205Tester {
    init {
        System.loadLibrary("TFG_PARTE1") // Asegúrate de usar el nombre exacto de tu biblioteca
    }

    // Adaptación de tus métodos de prueba
    fun runAllTests(): List<TestResult> {
        val results = mutableListOf<TestResult>()

        // Test genLen2
        results.add(testGenLen2())

        // Test toInt
        results.add(testToInt())

        // Test toByte
        results.add(testToByte())

        // Test roundTrip
        results.add(testRoundTripConversion())

        // Test ADRS
        results.add(testADRS())

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
            if (!bytes1.contentEquals(byteArrayOf(0x34, 0x12))) {
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
        val test = FunctionLink()
        var adrsPtr: Long = 0

        try {
            // Crear una instancia de ADRS
            adrsPtr = test.createADRS()
            if (adrsPtr == 0L) {
                return TestResult("ADRS", false, "No se pudo crear la instancia de ADRS")
            }

            // Verificar que la inicialización es correcta (todos ceros)
            var bytes = test.getAddressBytes(adrsPtr)
            if (!bytes.all { it == 0.toByte() }) {
                return TestResult("ADRS", false,
                    "La inicialización de ADRS no es correcta. Bytes: ${test.bytesToHex(bytes)}")
            }

            // Probar setLayerAddress
            test.setLayerAddress(adrsPtr, 0x12345678)
            bytes = test.getAddressBytes(adrsPtr)
            // Verificar orden little-endian (bytes menos significativos primero)
            if (bytes[0] != 0x78.toByte() || bytes[1] != 0x56.toByte() ||
                bytes[2] != 0x34.toByte() || bytes[3] != 0x12.toByte()) {
                return TestResult("ADRS", false,
                    "setLayerAddress no funcionó correctamente. Bytes: ${test.bytesToHex(bytes)}")
            }

            // Convertir un valor a bytes para setTreeAddress (12bytes)
            val treeValue = 0x123456789ABCL
            val treeBytes = ByteArray(12)
            // Llenar en orden little-endian
            for (i in 0 until 6) {
                treeBytes[i] = ((treeValue shr (8 * i)) and 0xFF).toByte()
            }
            test.setTreeAddress(adrsPtr, treeBytes)
            bytes = test.getAddressBytes(adrsPtr)

            // Verificar los 6 bytes en orden little-endian
            if (bytes[4] != 0xBC.toByte() || bytes[5] != 0x9A.toByte() ||
                bytes[6] != 0x78.toByte() || bytes[7] != 0x56.toByte() ||
                bytes[8] != 0x34.toByte() || bytes[9] != 0x12.toByte()) {
                return TestResult("ADRS", false,
                    "setTreeAddress no funcionó correctamente. Bytes: ${test.bytesToHex(bytes)}")
            }

            // Probar setTypeAndClear (tipo 2)
            test.setTypeAndClear(adrsPtr, 2)
            bytes = test.getAddressBytes(adrsPtr)
            // En little-endian, el valor 2 sería 02 00 00 00
            if (bytes[16] != 0x02.toByte() || bytes[17] != 0x00.toByte() ||
                bytes[18] != 0x00.toByte() || bytes[19] != 0x00.toByte()) {
                return TestResult("ADRS", false,
                    "setTypeAndClear no estableció el tipo correctamente. Bytes: ${test.bytesToHex(bytes)}")
            }

            // Verificar que los bytes 20-31 están a cero
            for (i in 20..31) {
                if (bytes[i] != 0.toByte()) {
                    return TestResult("ADRS", false,
                        "setTypeAndClear no puso a cero los bytes 20-31. Bytes: ${test.bytesToHex(bytes)}")
                }
            }

            // Probar setKeyPairAddress
            test.setKeyPairAddress(adrsPtr, 0xABCD)
            bytes = test.getAddressBytes(adrsPtr)
            // En little-endian sería CD AB 00 00
            if (bytes[20] != 0xCD.toByte() || bytes[21] != 0xAB.toByte() ||
                bytes[22] != 0x00.toByte() || bytes[23] != 0x00.toByte()) {
                return TestResult("ADRS", false,
                    "setKeyPairAddress no funcionó correctamente. Bytes: ${test.bytesToHex(bytes)}")
            }

            // Obtener y verificar el KeyPairAddress
            val kpAddr = test.getKeyPairAddress(adrsPtr)
            if (kpAddr != 0xABCD) {
                return TestResult("ADRS", false,
                    "getKeyPairAddress debería devolver 0xABCD, pero devolvió $kpAddr")
            }

            // Probar setChainAddress
            test.setChainAddress(adrsPtr, 0x1234)
            bytes = test.getAddressBytes(adrsPtr)
            // En little-endian sería 34 12 00 00
            if (bytes[24] != 0x34.toByte() || bytes[25] != 0x12.toByte() ||
                bytes[26] != 0x00.toByte() || bytes[27] != 0x00.toByte()) {
                return TestResult("ADRS", false,
                    "setChainAddress no funcionó correctamente. Bytes: ${test.bytesToHex(bytes)}")
            }

            // Probar setHashAddress
            test.setHashAddress(adrsPtr, 0x5678)
            bytes = test.getAddressBytes(adrsPtr)
            // En little-endian sería 78 56 00 00
            if (bytes[28] != 0x78.toByte() || bytes[29] != 0x56.toByte() ||
                bytes[30] != 0x00.toByte() || bytes[31] != 0x00.toByte()) {
                return TestResult("ADRS", false,
                    "setHashAddress no funcionó correctamente. Bytes: ${test.bytesToHex(bytes)}")
            }

            // Probar setTreeHeight (modifica los mismos bytes que setChainAddress)
            test.setTreeHeight(adrsPtr, 0x9ABC)
            bytes = test.getAddressBytes(adrsPtr)
            // En little-endian sería BC 9A 00 00
            if (bytes[24] != 0xBC.toByte() || bytes[25] != 0x9A.toByte() ||
                bytes[26] != 0x00.toByte() || bytes[27] != 0x00.toByte()) {
                return TestResult("ADRS", false,
                    "setTreeHeight no funcionó correctamente. Bytes: ${test.bytesToHex(bytes)}")
            }

            // Probar setTreeIndex (modifica los mismos bytes que setHashAddress)
            test.setTreeIndex(adrsPtr, 0xDEF0)
            bytes = test.getAddressBytes(adrsPtr)
            // En little-endian sería F0 DE 00 00
            if (bytes[28] != 0xF0.toByte() || bytes[29] != 0xDE.toByte() ||
                bytes[30] != 0x00.toByte() || bytes[31] != 0x00.toByte()) {
                return TestResult("ADRS", false,
                    "setTreeIndex no funcionó correctamente. Bytes: ${test.bytesToHex(bytes)}")
            }

            // Obtener y verificar el TreeIndex
            val treeIdx = test.getTreeIndex(adrsPtr)
            if (treeIdx != 0xDEF0) {
                return TestResult("ADRS", false,
                    "getTreeIndex debería devolver 0xDEF0, pero devolvió $treeIdx")
            }

            return TestResult("ADRS", true, "Todas las pruebas de ADRS han pasado correctamente")
        } catch (e: Exception) {
            return TestResult("ADRS", false, "Error: ${e.message}")
        } finally {
            // Liberar recursos
            if (adrsPtr != 0L) {
                test.disposeADRS(adrsPtr)
            }
        }
    }
    // Clase para representar resultados de tests
    data class TestResult(
        val testName: String,
        val passed: Boolean,
        val message: String
    )
}