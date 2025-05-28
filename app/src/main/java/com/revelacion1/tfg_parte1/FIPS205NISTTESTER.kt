package com.revelacion1.tfg_parte1

import android.util.Log
import org.json.JSONObject
import org.json.JSONArray

/**
 * Utilidades para manipulación de datos hexadecimales
 */
object NISTVectorUtils {
    fun isValidHex(hex: String): Boolean {
        return hex.matches(Regex("^[0-9A-Fa-f]*$")) && hex.length % 2 == 0
    }

    fun hexToByteArray(hex: String): ByteArray {
        if (!isValidHex(hex)) throw IllegalArgumentException("Invalid hex string: $hex")
        val result = ByteArray(hex.length / 2)
        for (i in hex.indices step 2) {
            val byte = hex.substring(i, i + 2).toInt(16).toByte()
            result[i / 2] = byte
        }
        return result
    }

    fun toHexString(bytes: ByteArray): String {
        return bytes.joinToString("") { String.format("%02X", it) }
    }
}

/**
 * Procesador de vectores de prueba NIST para SLH-DSA
 * Especializado en configuraciones SHAKE-128 y SHAKE-256
 */
class NISTVectorTester(private val context: android.content.Context) {

    private val functionLink = FunctionLink()
    private var logger: FIPS205Tester.TestLogger? = null

    fun setLogger(logger: FIPS205Tester.TestLogger) {
        this.logger = logger
    }

    private fun log(message: String) {
        logger?.log(message) ?: println(message)

        // Para mensajes con saltos de línea, dividir y loggear por separado
        if (message.contains("\n")) {
            val lines = message.split("\n")
            lines.forEach { line ->
                if (line.trim().isNotEmpty()) {
                    Log.d("NIST_VECTOR_TESTER", line.trim())
                }
            }
        } else {
            Log.d("NIST_VECTOR_TESTER", message)
        }
    }
    /**
     * Estructuras de datos para vectores NIST
     */
    data class SigGenTestCase(
        val tcId: Int,
        val sk: String,
        val message: String,
        val context: String = ""
    )

    data class SigVerTestCase(
        val tcId: Int,
        val pk: String,
        val message: String,
        val signature: String,
        val context: String = ""
    )

    data class TestResult(
        val tcId: Int,
        val passed: Boolean,
        val message: String,
        val duration: Long,
        val details: String? = null
    )

    data class TestResults(
        val algorithm: String,
        val mode: String,
        val totalTests: Int,
        val passedTests: Int,
        val results: List<TestResult>,
        val errorMessage: String? = null
    )

    /**
     * TEST DE GENERACIÓN DE FIRMAS
     * Lee prompt.json, genera firmas con slhSign y compara con expectedResults.json
     */
    fun testSignatureGeneration(): TestResults {
        log("🔧 INICIANDO TEST DE GENERACIÓN DE FIRMAS NIST\n")
        log("📂 Leyendo archivos: firmaGen_json_tests/\n")

        return try {
            // Leer archivos JSON
            val promptJson = readAssetFile("firmaGen_json_tests/prompt.json")
            val expectedJson = readAssetFile("firmaGen_json_tests/expectedResults.json")

            if (promptJson == null || expectedJson == null) {
                return TestResults("ERROR", "sigGen", 0, 0, emptyList(),
                    "No se pudieron leer los archivos JSON de generación")
            }

            val promptObject = JSONObject(promptJson)
            val expectedObject = JSONObject(expectedJson)

            val algorithm = promptObject.getString("algorithm")
            log("🎯 Algoritmo: $algorithm\n")

            val testGroups = promptObject.getJSONArray("testGroups")
            val expectedGroups = expectedObject.getJSONArray("testGroups")

            val allResults = mutableListOf<TestResult>()
            var totalPassed = 0

            // Procesar cada grupo de tests
            for (i in 0 until testGroups.length()) {
                val testGroup = testGroups.getJSONObject(i)
                val expectedGroup = expectedGroups.getJSONObject(i)

                val parameterSet = testGroup.getString("parameterSet")

                // Filtrar solo configuraciones SHAKE soportadas
                if (!isSupportedParameterSet(parameterSet)) {
                    log("🚫 Saltando parameter set no soportado: $parameterSet\n")
                    continue
                }

                log("📋 Procesando grupo: $parameterSet\n")

                // Configurar biblioteca
                val config = mapParameterSetToConfig(parameterSet)
                if (config == -1) {
                    log("❌ Error mapeando parameter set: $parameterSet\n")
                    continue
                }

                functionLink.initializeConfig(config)

                val tests = testGroup.getJSONArray("tests")
                val expectedTests = expectedGroup.getJSONArray("tests")

                // Procesar cada test case
                for (j in 0 until tests.length()) {
                    val test = tests.getJSONObject(j)
                    val expectedTest = expectedTests.getJSONObject(j)

                    val testCase = SigGenTestCase(
                        tcId = test.getInt("tcId"),
                        sk = test.getString("sk"),
                        message = test.getString("message"),
                        context = test.optString("context", "")
                    )

                    val expectedSignature = expectedTest.getString("signature")

                    val result = executeSignatureGeneration(testCase, expectedSignature)
                    allResults.add(result)
                    if (result.passed) totalPassed++
                }
            }

            log("📊 GENERACIÓN COMPLETADA: $totalPassed/${allResults.size} exitosos\n")
            TestResults(algorithm, "sigGen", allResults.size, totalPassed, allResults)

        } catch (e: Exception) {
            log("💥 ERROR en test de generación: ${e.message}\n")
            TestResults("ERROR", "sigGen", 0, 0, emptyList(), e.message)
        }
    }

    /**
     * TEST DE VERIFICACIÓN DE FIRMAS
     * Lee prompt.json, verifica firmas con slhVerify y compara con expectedResults.json
     */
    fun testSignatureVerification(): TestResults {
        log("🔍 INICIANDO TEST DE VERIFICACIÓN DE FIRMAS NIST\n")
        log("📂 Leyendo archivos: firmaVer_json_tests/\n")

        return try {
            // Leer archivos JSON
            val promptJson = readAssetFile("firmaVer_json_tests/prompt.json")
            val expectedJson = readAssetFile("firmaVer_json_tests/expectedResults.json")

            if (promptJson == null || expectedJson == null) {
                return TestResults("ERROR", "sigVer", 0, 0, emptyList(),
                    "No se pudieron leer los archivos JSON de verificación")
            }

            val promptObject = JSONObject(promptJson)
            val expectedObject = JSONObject(expectedJson)

            val algorithm = promptObject.getString("algorithm")
            log("🎯 Algoritmo: $algorithm\n")

            val testGroups = promptObject.getJSONArray("testGroups")
            val expectedGroups = expectedObject.getJSONArray("testGroups")

            val allResults = mutableListOf<TestResult>()
            var totalPassed = 0

            // Procesar cada grupo de tests
            for (i in 0 until testGroups.length()) {
                val testGroup = testGroups.getJSONObject(i)
                val expectedGroup = expectedGroups.getJSONObject(i)

                val parameterSet = testGroup.getString("parameterSet")

                // Filtrar solo configuraciones SHAKE soportadas
                if (!isSupportedParameterSet(parameterSet)) {
                    log("🚫 Saltando parameter set no soportado: $parameterSet\n")
                    continue
                }

                log("📋 Verificando grupo: $parameterSet\n")

                // Configurar biblioteca
                val config = mapParameterSetToConfig(parameterSet)
                if (config == -1) {
                    log("❌ Error mapeando parameter set: $parameterSet\n")
                    continue
                }

                functionLink.initializeConfig(config)

                val tests = testGroup.getJSONArray("tests")
                val expectedTests = expectedGroup.getJSONArray("tests")

                // Procesar cada test case
                for (j in 0 until tests.length()) {
                    val test = tests.getJSONObject(j)
                    val expectedTest = expectedTests.getJSONObject(j)

                    val testCase = SigVerTestCase(
                        tcId = test.getInt("tcId"),
                        pk = test.getString("pk"),
                        message = test.getString("message"),
                        signature = test.getString("signature"),
                        context = test.optString("context", "")
                    )

                    val expectedResult = expectedTest.getBoolean("testPassed")

                    val result = executeSignatureVerification(testCase, expectedResult, parameterSet)
                    allResults.add(result)
                    if (result.passed) totalPassed++
                }
            }

            log("📊 VERIFICACIÓN COMPLETADA: $totalPassed/${allResults.size} exitosos\n")
            TestResults(algorithm, "sigVer", allResults.size, totalPassed, allResults)

        } catch (e: Exception) {
            log("💥 ERROR en test de verificación: ${e.message}\n")
            TestResults("ERROR", "sigVer", 0, 0, emptyList(), e.message)
        }
    }

    /**
     * Ejecuta test de generación de firma individual
     */
    @OptIn(ExperimentalStdlibApi::class)
    private fun executeSignatureGeneration(
        testCase: SigGenTestCase,
        expectedSignature: String
    ): TestResult {
        return try {
            log("  🔄 TC${testCase.tcId}: Generando firma...\n")

            val startTime = System.currentTimeMillis()

            // Convertir datos de entrada
            val privateKey = NISTVectorUtils.hexToByteArray(testCase.sk)
            val messageBytes = NISTVectorUtils.hexToByteArray(testCase.message)
            val contextBytes = NISTVectorUtils.hexToByteArray(testCase.context)

            // Generar firma usando slhSign
            val generatedSignature = functionLink.slhSign(messageBytes, contextBytes, privateKey)
            val duration = System.currentTimeMillis() - startTime

            // Convertir firma generada a hex para comparación
            val generatedSignatureHex = NISTVectorUtils.toHexString(generatedSignature)

            // Comparar con resultado esperado
            val matches = generatedSignatureHex.equals(expectedSignature, ignoreCase = true)

            val message = if (matches) {
                "Firma coincide con NIST (${generatedSignature.size} bytes)\n" +
                        "Expected: ${expectedSignature}...\n" +
                        "Generated: ${generatedSignatureHex}...\n" +
                        "Match: $matches"
            } else {
                "Firma NO coincide con NIST\n" +
                        "Expected: ${expectedSignature}...\n" +
                        "Generated: ${generatedSignatureHex}...\n" +
                        "Match: $matches"
            }


            log("    ${if (matches) "✅" else "❌"} TC${testCase.tcId}: $message (${duration}ms)\n")

            TestResult(
                tcId = testCase.tcId,
                passed = matches,
                message = message,
                duration = duration,
                details = null
            )

        } catch (e: Exception) {
            log("    💥 TC${testCase.tcId}: Error - ${e.message}\n")
            TestResult(testCase.tcId, false, "Error: ${e.message}", 0)
        }
    }

    /**
     * Ejecuta test de verificación de firma individual
     */
    private fun executeSignatureVerification(
        testCase: SigVerTestCase,
        expectedResult: Boolean,
        parameterSet: String
    ): TestResult {
        return try {
            log("  🔍 TC${testCase.tcId}: Verificando firma...\n")

            val startTime = System.currentTimeMillis()

            // Convertir datos de entrada
            val publicKey = NISTVectorUtils.hexToByteArray(testCase.pk)
            val messageBytes = NISTVectorUtils.hexToByteArray(testCase.message)
            val signatureBytes = NISTVectorUtils.hexToByteArray(testCase.signature)
            val contextBytes = NISTVectorUtils.hexToByteArray(testCase.context)

            // Verificar firma usando slhVerify
            val verificationResult = functionLink.slhVerify(
                messageBytes,
                signatureBytes,
                contextBytes,
                publicKey
            )

            val duration = System.currentTimeMillis() - startTime

            // Comparar con resultado esperado
            val matches = verificationResult == expectedResult

            val message = if (matches) {
                "Verificación correcta: ${if (verificationResult) "VÁLIDA" else "INVÁLIDA"}"
            } else {
                "Error: Esperado $expectedResult, obtenido $verificationResult"
            }

            val details = "Expected: $expectedResult, Got: $verificationResult"

            log("    ${if (matches) "✅" else "❌"} TC${testCase.tcId}: $message (${duration}ms)\n")

            TestResult(
                tcId = testCase.tcId,
                passed = matches,
                message = message,
                duration = duration,
                details = details
            )

        } catch (e: Exception) {
            log("    💥 TC${testCase.tcId}: Error - ${e.message}\n")
            TestResult(testCase.tcId, false, "Error: ${e.message}", 0)
        }
    }

    /**
     * Mapea parameter sets a configuraciones - SOLO SHAKE 128 y 256
     */
    private fun mapParameterSetToConfig(parameterSet: String): Int {
        return when (parameterSet) {
            "SLH-DSA-SHAKE-128s" -> 1
            "SLH-DSA-SHAKE-128f" -> 3
            "SLH-DSA-SHAKE-256s" -> 9
            "SLH-DSA-SHAKE-256f" -> 11
            else -> {
                log("⚠️ Parameter set no soportado (solo SHAKE-128/256): $parameterSet\n")
                -1
            }
        }
    }

    /**
     * Valida si el parameter set es soportado
     */
    private fun isSupportedParameterSet(parameterSet: String): Boolean {
        return parameterSet.startsWith("SLH-DSA-SHAKE-") &&
                (parameterSet.contains("128") || parameterSet.contains("256"))
    }

    /**
     * Lee un archivo de assets como String
     */
    private fun readAssetFile(fileName: String): String? {
        return try {
            context.assets.open(fileName).bufferedReader().use { it.readText() }
        } catch (e: Exception) {
            log("💥 Error leyendo archivo $fileName: ${e.message}\n")
            null
        }
    }

    /**
     * Función combinada para ejecutar ambos tests
     */
    fun testOnlySHAKE(): TestResults {
        log("🔧 EJECUTANDO TESTS COMPLETOS NIST SHAKE\n")
        log("📌 Generación + Verificación de firmas\n")
        log("=".repeat(50) + "\n")

        val startTime = System.currentTimeMillis()

        // Ejecutar test de generación
        log("1️⃣ FASE: Generación de firmas\n")
        val generationResults = testSignatureGeneration()

        // Ejecutar test de verificación
        log("\n2️⃣ FASE: Verificación de firmas\n")
        val verificationResults = testSignatureVerification()

        val totalTime = System.currentTimeMillis() - startTime

        // Combinar resultados
        val combinedResults = generationResults.results + verificationResults.results
        val totalTests = generationResults.totalTests + verificationResults.totalTests
        val totalPassed = generationResults.passedTests + verificationResults.passedTests
        val successRate = if (totalTests > 0) (totalPassed * 100.0 / totalTests) else 0.0

        log("\n🏁 TESTS SHAKE COMPLETADOS\n")
        log("⏱️ Tiempo total: ${totalTime}ms\n")
        log("📊 Generación: ${generationResults.passedTests}/${generationResults.totalTests}\n")
        log("📊 Verificación: ${verificationResults.passedTests}/${verificationResults.totalTests}\n")
        log("📈 Total: $totalPassed/$totalTests (${successRate.toInt()}%)\n")

        return TestResults(
            algorithm = "SHAKE-Combined",
            mode = "sigGen+sigVer",
            totalTests = totalTests,
            passedTests = totalPassed,
            results = combinedResults,
            errorMessage = if (generationResults.errorMessage != null || verificationResults.errorMessage != null) {
                "Gen: ${generationResults.errorMessage ?: "OK"} | Ver: ${verificationResults.errorMessage ?: "OK"}"
            } else null
        )
    }
}