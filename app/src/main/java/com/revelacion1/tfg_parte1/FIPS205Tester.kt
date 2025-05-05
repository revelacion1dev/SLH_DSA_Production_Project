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

        // Test base2b
        results.add(testBase2b())

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

    // Test for algorithm 5 2b.
    private fun testBase2b(): TestResult {
        try {
            val test = FunctionLink()

            // Test case 1: Simple value with b=4
            // Entrada: [0x12, 0x34] con b=4, out_len=4
            // Esto debería producir [1, 2, 3, 4] (cada dígito hexadecimal como un elemento)
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

            // Test case 3: Base 8 (octal)
            // Entrada: [0x12, 0x34] (00010010 00110100 en binario) con b=3, out_len=5
            // En octal: 001 001 000 110 100 -> [1, 1, 0, 6, 4]
            val input3 = byteArrayOf(0x12, 0x34)
            val result3 = test.base2b(input3, 3, 5)
            val expected3 = intArrayOf(1, 1, 0, 6, 4)
            if (!result3.contentEquals(expected3)) {
                return TestResult("base2b", false,
                    "Base 8 (octal) falló. Esperado: [1, 1, 0, 6, 4], Obtenido: ${result3.joinToString(", ")}")
            }

            // Test case 4: Large value with b=16
            // Entrada: [0x12, 0x34, 0x56, 0x78] con b=16, out_len=2
            // Esto debería producir [0x1234, 0x5678]
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
            // Verificar orden little-endian (bytes menos significativos primero)
            if (bytes[0] != 0x78.toByte() || bytes[1] != 0x56.toByte() ||
                bytes[2] != 0x34.toByte() || bytes[3] != 0x12.toByte()) {
                return TestResult("ADRS", false,
                    "setLayerAddress no funcionó correctamente. Bytes: ${bytesToHex(bytes)}")
            }

            // Convertir un valor a bytes para setTreeAddress (12bytes)
            val treeValue = 0x123456789ABC
            val treeBytes = ByteArray(12)
            // Llenar en orden little-endian
            for (i in 0 until 6) {
                treeBytes[i] = ((treeValue shr (8 * i)) and 0xFF).toByte()
            }
            adrsWrapper.setTreeAddress(treeBytes)
            bytes = adrsWrapper.getAddressBytes()

            // Verificar los 6 bytes en orden little-endian
            if (bytes[4] != 0xBC.toByte() || bytes[5] != 0x9A.toByte() ||
                bytes[6] != 0x78.toByte() || bytes[7] != 0x56.toByte() ||
                bytes[8] != 0x34.toByte() || bytes[9] != 0x12.toByte()) {
                return TestResult("ADRS", false,
                    "setTreeAddress no funcionó correctamente. Bytes: ${bytesToHex(bytes)}")
            }

            // Probar setTypeAndClear (tipo 2)
            adrsWrapper.setTypeAndClear(2)
            bytes = adrsWrapper.getAddressBytes()
            // En little-endian, el valor 2 sería 02 00 00 00
            if (bytes[16] != 0x02.toByte() || bytes[17] != 0x00.toByte() ||
                bytes[18] != 0x00.toByte() || bytes[19] != 0x00.toByte()) {
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

            // Verificamos que los bytes se almacenen correctamente en little-endian
            // 0xABCD en little-endian debería ser CD AB 00 00
            if (bytes[20] != 0xCD.toByte() || bytes[21] != 0xAB.toByte() ||
                bytes[22] != 0x00.toByte() || bytes[23] != 0x00.toByte()) {
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
            // En little-endian sería 34 12 00 00
            if (bytes[24] != 0x34.toByte() || bytes[25] != 0x12.toByte() ||
                bytes[26] != 0x00.toByte() || bytes[27] != 0x00.toByte()) {
                return TestResult("ADRS", false,
                    "setChainAddress no funcionó correctamente. Bytes: ${bytesToHex(bytes)}")
            }

            // Probar setHashAddress
            adrsWrapper.setHashAddress(0x5678)
            bytes = adrsWrapper.getAddressBytes()
            // En little-endian sería 78 56 00 00
            if (bytes[28] != 0x78.toByte() || bytes[29] != 0x56.toByte() ||
                bytes[30] != 0x00.toByte() || bytes[31] != 0x00.toByte()) {
                return TestResult("ADRS", false,
                    "setHashAddress no funcionó correctamente. Bytes: ${bytesToHex(bytes)}")
            }

            // Probar setTreeHeight (modifica los mismos bytes que setChainAddress)
            adrsWrapper.setTreeHeight(0x9ABC)
            bytes = adrsWrapper.getAddressBytes()
            // En little-endian sería BC 9A 00 00
            if (bytes[24] != 0xBC.toByte() || bytes[25] != 0x9A.toByte() ||
                bytes[26] != 0x00.toByte() || bytes[27] != 0x00.toByte()) {
                return TestResult("ADRS", false,
                    "setTreeHeight no funcionó correctamente. Bytes: ${bytesToHex(bytes)}")
            }

            // Probar setTreeIndex (modifica los mismos bytes que setHashAddress)
            adrsWrapper.setTreeIndex(0xDEF0)
            bytes = adrsWrapper.getAddressBytes()
            // En little-endian sería F0 DE 00 00
            if (bytes[28] != 0xF0.toByte() || bytes[29] != 0xDE.toByte() ||
                bytes[30] != 0x00.toByte() || bytes[31] != 0x00.toByte()) {
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