package com.revelacion1.tfg_parte1

import android.graphics.Color
import android.os.Bundle
import android.view.View
import android.widget.*
import androidx.appcompat.app.AppCompatActivity
import java.text.SimpleDateFormat
import java.util.*
import java.util.concurrent.atomic.AtomicBoolean

class MainActivity : AppCompatActivity() {

    // Views
    private lateinit var statusText: TextView
    private lateinit var spinnerAlgorithm: Spinner
    private lateinit var etMessage: EditText
    private lateinit var layoutKeyInfo: LinearLayout
    private lateinit var tvKeyInfo: TextView
    private lateinit var tvResults: TextView
    private lateinit var btnSign: Button
    private lateinit var btnNistTest: Button  // Solo un botón para vectores NIST

    // Estado
    private var currentKeys: Array<ByteArray>? = null
    private var currentAlgorithm = 0
    private lateinit var fipsTester: FIPS205Tester
    private lateinit var nistVectorTester: NISTVectorTester  // Tester NIST

    // Thread safety
    private val isTestRunning = AtomicBoolean(false)

    // Algoritmos disponibles
    private val algorithms = arrayOf(
        "SHA2-128s", "SHAKE-128s", "SHA2-128f", "SHAKE-128f",
        "SHA2-192s", "SHAKE-192s", "SHA2-192f", "SHAKE-192f",
        "SHA2-256s", "SHAKE-256s", "SHA2-256f", "SHAKE-256f"
    )

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        // Inicializar testers con logger thread-safe
        fipsTester = FIPS205Tester()
        nistVectorTester = NISTVectorTester(this)  // Pasar contexto

        setupFipsTesterLogger()
        setupNISTVectorTesterLogger()

        initViews()
        initFipsLibrary()
        setupListeners()
        checkLibraryStatus()
    }

    private fun initFipsLibrary(){
        // Inicializar la biblioteca FIPS205
        Thread {
            try {
                val functionLink = FunctionLink()
                val isInitialized = functionLink.initializeConfig(1) // SHAKE-128s por defecto
                runOnUiThread {
                    if (isInitialized) {
                        log("✅ Biblioteca FIPS205 inicializada correctamente\n")
                    } else {
                        log("❌ Error al inicializar la biblioteca FIPS205\n")
                    }
                }
            } catch (e: Exception) {
                runOnUiThread {
                    log("💥 Error crítico al inicializar la biblioteca: ${e.message}\n")
                }
            }
        }.start()
    }

    private fun setupFipsTesterLogger() {
        // Logger thread-safe con forzado de actualización
        fipsTester.setLogger(object : FIPS205Tester.TestLogger {
            override fun log(message: String) {
                runOnUiThread {
                    forceUpdateUI(message)
                }
            }

            override fun logTestStart(testName: String) {
                runOnUiThread {
                    forceUpdateUI("🚀 INICIANDO: $testName\n")
                    forceUpdateUI("=".repeat(40) + "\n")
                }
            }

            override fun logTestResult(testName: String, passed: Boolean, message: String) {
                runOnUiThread {
                    val emoji = if (passed) "✅" else "❌"
                    val status = if (passed) "ÉXITO" else "FALLO"
                    forceUpdateUI("$emoji RESULTADO: $testName = $status\n")

                    if (!passed) {
                        forceUpdateUI("💡 DETALLE: $message\n")
                    }
                    forceUpdateUI("-".repeat(40) + "\n")
                }
            }
        })
    }

    private fun setupNISTVectorTesterLogger() {
        // Logger para el tester de vectores NIST
        nistVectorTester.setLogger(object : FIPS205Tester.TestLogger {
            override fun log(message: String) {
                runOnUiThread {
                    forceUpdateUI(message)
                }
            }

            override fun logTestStart(testName: String) {
                runOnUiThread {
                    forceUpdateUI("🔬 VECTOR NIST: $testName\n")
                    forceUpdateUI("*".repeat(40) + "\n")
                }
            }

            override fun logTestResult(testName: String, passed: Boolean, message: String) {
                runOnUiThread {
                    val emoji = if (passed) "✅" else "❌"
                    val status = if (passed) "EXITOSO" else "FALLO"
                    forceUpdateUI("$emoji VECTOR: $testName = $status\n")

                    if (!passed) {
                        forceUpdateUI("🔍 DETALLE: $message\n")
                    }
                    forceUpdateUI("*".repeat(40) + "\n")
                }
            }
        })
    }

    // Función para forzar actualización de UI
    private fun forceUpdateUI(message: String) {
        try {
            val current = tvResults.text.toString()
            val newText = current + message
            tvResults.text = newText

            // Forzar scroll inmediato
            tvResults.post {
                val scrollView = tvResults.parent as? ScrollView
                scrollView?.fullScroll(View.FOCUS_DOWN)
            }

            // Forzar invalidación de la vista
            tvResults.invalidate()

        } catch (e: Exception) {
            // Log silencioso del error
            println("Error updating UI: ${e.message}")
        }
    }

    private fun initViews() {
        statusText = findViewById(R.id.statusText)
        spinnerAlgorithm = findViewById(R.id.spinnerAlgorithm)
        etMessage = findViewById(R.id.etMessage)
        layoutKeyInfo = findViewById(R.id.layoutKeyInfo)
        tvKeyInfo = findViewById(R.id.tvKeyInfo)
        tvResults = findViewById(R.id.tvResults)
        btnSign = findViewById(R.id.btnSign)
        btnNistTest = findViewById(R.id.btnNistTest)  // Solo un botón

        // Configurar spinner
        val adapter = ArrayAdapter(this, android.R.layout.simple_spinner_item, algorithms)
        adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)
        spinnerAlgorithm.adapter = adapter
        spinnerAlgorithm.setSelection(1) // SHAKE-128s por defecto
    }

    private fun setupListeners() {
        findViewById<Button>(R.id.btnQuickTest).setOnClickListener {
            if (!isTestRunning.get()) runQuickTest()
        }
        findViewById<Button>(R.id.btnFullTest).setOnClickListener {
            if (!isTestRunning.get()) runFullTestWithDebug()
        }
        findViewById<Button>(R.id.btnGenerateKeys).setOnClickListener { generateKeys() }
        findViewById<Button>(R.id.btnSign).setOnClickListener { signMessage() }
        findViewById<Button>(R.id.btnClear).setOnClickListener { clearResults() }

        // Solo un listener para vectores NIST
        btnNistTest.setOnClickListener {
            if (!isTestRunning.get()) runNISTVectorTest()
        }

        spinnerAlgorithm.onItemSelectedListener = object : AdapterView.OnItemSelectedListener {
            override fun onItemSelected(parent: AdapterView<*>?, view: View?, position: Int, id: Long) {
                currentAlgorithm = position
                currentKeys = null
                updateKeyInfo()
                btnSign.isEnabled = false
            }
            override fun onNothingSelected(parent: AdapterView<*>?) {}
        }
    }

    /**
     * TEST DE VECTORES NIST - Procesamiento completo de archivos JSON
     * Ejecuta ambas funciones: generación y verificación de firmas
     */
    private fun runNISTVectorTest() {
        if (!isTestRunning.compareAndSet(false, true)) {
            log("⚠️ Ya hay un test ejecutándose, espera a que termine\n")
            return
        }

        btnNistTest.isEnabled = false
        btnNistTest.text = "Ejecutando Vectores NIST..."

        log("🔬 PROCESADOR DE VECTORES NIST - SOLO SHAKE\n")
        log("📌 Configuraciones soportadas: SHAKE-128s/f, SHAKE-256s/f\n")
        log("🎯 Procesando archivos JSON reales de NIST\n")
        log("=".repeat(60) + "\n\n")

        Thread {
            val startTime = System.currentTimeMillis()

            try {
                runOnUiThread {
                    forceUpdateUI("🔧 Inicializando procesador de vectores NIST...\n")
                    forceUpdateUI("📂 Buscando archivos JSON en assets/\n\n")
                }

                // Ejecutar tests de generación
                /*
                runOnUiThread {
                    forceUpdateUI("1️⃣ EJECUTANDO TESTS DE GENERACIÓN DE FIRMAS\n")
                    forceUpdateUI("-".repeat(50) + "\n")
                }

                val generationResults = nistVectorTester.testSignatureGeneration()

                runOnUiThread {
                    displayNISTVectorResults("Generación de Firmas", generationResults)
                }

                // Ejecutar tests de verificación
                runOnUiThread {
                    forceUpdateUI("\n2️⃣ EJECUTANDO TESTS DE VERIFICACIÓN DE FIRMAS\n")
                    forceUpdateUI("-".repeat(50) + "\n")
                }

                val verificationResults = nistVectorTester.testSignatureVerification()

                runOnUiThread {
                    displayNISTVectorResults("Verificación de Firmas", verificationResults)
                }

                // Ejecutar test combinado
                runOnUiThread {
                    forceUpdateUI("\nEJECUTANDO TEST COMBINADO SHAKE\n")
                    forceUpdateUI("-".repeat(50) + "\n")
                }
                */

                val combinedResults = nistVectorTester.testOnlySHAKE()

                runOnUiThread {
                    displayNISTVectorResults("Test Combinado SHAKE", combinedResults)
                }

                val totalTime = System.currentTimeMillis() - startTime

                runOnUiThread {
                    // Resumen final
                    forceUpdateUI("\n🏁 PROCESAMIENTO VECTORES NIST COMPLETADO\n")
                    forceUpdateUI("⏱️ Tiempo total: ${totalTime}ms (${totalTime/1000.0}s)\n")
                    forceUpdateUI("=".repeat(60) + "\n")

                    // Análisis combinado
                    /*
                    val genTotal = generationResults.totalTests
                    val genPassed = generationResults.passedTests
                    val verTotal = verificationResults.totalTests
                    val verPassed = verificationResults.passedTests
                     */
                    val combTotal = combinedResults.totalTests
                    val combPassed = combinedResults.passedTests

                    forceUpdateUI("\n📊 ANÁLISIS FINAL VECTORES NIST:\n")
                    /*
                    forceUpdateUI("   🔧 Generación: $genPassed/$genTotal (${if(genTotal > 0) (genPassed*100/genTotal) else 0}%)\n")
                    forceUpdateUI("   🔍 Verificación: $verPassed/$verTotal (${if(verTotal > 0) (verPassed*100/verTotal) else 0}%)\n")
                    */
                    forceUpdateUI("   🎯 Combinado: $combPassed/$combTotal (${if(combTotal > 0) (combPassed*100/combTotal) else 0}%)\n")


                    // Estado del sistema NIST
                    val overallRate = if (combTotal > 0) (combPassed * 100.0 / combTotal) else 0.0
                    val status = when {
                        overallRate >= 95 -> "🟢 EXCELENTE - Vectores NIST completamente compatibles"
                        overallRate >= 80 -> "🟡 BUENO - Vectores NIST mayormente compatibles"
                        overallRate >= 60 -> "🟠 REGULAR - Vectores NIST parcialmente compatibles"
                        else -> "🔴 PROBLEMÁTICO - Vectores NIST requieren revisión"
                    }

                    forceUpdateUI("   🔍 Estado NIST: $status\n")

                    if (overallRate < 100) {
                        forceUpdateUI("\n💡 RECOMENDACIONES VECTORES NIST:\n")
                        /*
                        if (generationResults.errorMessage != null) {
                            forceUpdateUI("   • Revisar generación: ${generationResults.errorMessage}\n")
                        }
                        if (verificationResults.errorMessage != null) {
                            forceUpdateUI("   • Revisar verificación: ${verificationResults.errorMessage}\n")
                        }
                         */
                        forceUpdateUI("   • Verificar archivos JSON en assets/\n")
                        forceUpdateUI("   • Consultar logs detallados con 'adb logcat | grep NIST_VECTOR_TESTER'\n")
                    } else {
                        forceUpdateUI("\n🎉 ¡PERFECTO! Todos los vectores NIST funcionan correctamente\n")
                    }

                    forceUpdateUI("\n📚 ARCHIVOS PROCESADOS:\n")
                    forceUpdateUI("   📂 firmaGen_json_tests/prompt.json\n")
                    forceUpdateUI("   📂 firmaGen_json_tests/expectedResults.json\n")
                    forceUpdateUI("   📂 firmaVer_json_tests/prompt.json\n")
                    forceUpdateUI("   📂 firmaVer_json_tests/expectedResults.json\n")
                    forceUpdateUI("=".repeat(60) + "\n\n")

                    // Restaurar UI
                    btnNistTest.isEnabled = true
                    btnNistTest.text = "Vectores NIST"
                    isTestRunning.set(false)
                }

            } catch (e: Exception) {
                runOnUiThread {
                    forceUpdateUI("💥 ERROR en procesamiento vectores NIST: ${e.message}\n")
                    forceUpdateUI("📚 Stack trace:\n")
                    e.stackTrace.take(3).forEach {
                        forceUpdateUI("   $it\n")
                    }
                    forceUpdateUI("\n")

                    btnNistTest.isEnabled = true
                    btnNistTest.text = "Vectores NIST"
                    isTestRunning.set(false)
                }
            }
        }.start()
    }

    // Reemplazar la función displayNISTVectorResults en MainActivity.kt
    private fun displayNISTVectorResults(testName: String, result: NISTVectorTester.TestResults) {
        forceUpdateUI("📋 RESULTADOS: $testName\n")
        forceUpdateUI("   🔧 Algoritmo: ${result.algorithm}\n")
        forceUpdateUI("   📊 Tests: ${result.passedTests}/${result.totalTests} exitosos\n")

        if (result.totalTests > 0) {
            val successRate = (result.passedTests * 100.0 / result.totalTests).toInt()
            forceUpdateUI("   📈 Tasa de éxito: $successRate%\n")
        }

        if (result.errorMessage != null) {
            forceUpdateUI("   ❌ Error: ${result.errorMessage}\n")
        }

        if (result.results.isNotEmpty()) {
            forceUpdateUI("   📂 Detalle por test case:\n")

            // Mostrar failures primero
            val failures = result.results.filter { !it.passed }
            if (failures.isNotEmpty()) {
                forceUpdateUI("   🔴 FALLOS DETECTADOS:\n")
                failures.take(3).forEach { test ->
                    forceUpdateUI("      ❌ TC${test.tcId}: ${test.message}\n")
                    if (test.duration > 0) {
                        forceUpdateUI("         ⏱️ Tiempo: ${test.duration}ms\n")
                    }
                    // Mostrar detalles adicionales si existen
                    test.details?.let { details ->
                        forceUpdateUI("         🔍 Detalles: $details\n")
                    }
                }
                if (failures.size > 3) {
                    forceUpdateUI("      ... y ${failures.size - 3} fallos más\n")
                }
                forceUpdateUI("\n")
            }

            // Mostrar algunos éxitos para verificar que el sistema funciona
            val successes = result.results.filter { it.passed }
            if (successes.isNotEmpty()) {
                forceUpdateUI("   🟢 ÉXITOS (muestra):\n")
                successes.take(2).forEach { test ->
                    forceUpdateUI("      ✅ TC${test.tcId}: ${test.message.lines().first()}\n")
                    if (test.duration > 0) {
                        forceUpdateUI("         ⏱️ Tiempo: ${test.duration}ms\n")
                    }
                }
                if (successes.size > 2) {
                    forceUpdateUI("      ... y ${successes.size - 2} éxitos más\n")
                }
            }
        }

        // Agregar recomendación para ver logs detallados
        if (result.results.any { !it.passed }) {
            forceUpdateUI("\n   💡 Para ver comparaciones detalladas de firmas:\n")
            forceUpdateUI("      adb logcat | grep 'NIST_SIGNATURE_DEBUG'\n")
        }

        forceUpdateUI("\n")
    }

    private fun checkLibraryStatus() {
        Thread {
            try {
                val isWorking = FIPS205Tester.runQuickTest()
                runOnUiThread {
                    if (isWorking) {
                        statusText.text = "✅ Biblioteca SLH-DSA funcionando correctamente"
                        statusText.setTextColor(Color.GREEN)
                        log("✅ Sistema iniciado correctamente\n")
                    } else {
                        statusText.text = "❌ Error con la biblioteca SLH-DSA"
                        statusText.setTextColor(Color.RED)
                        log("❌ Error: La biblioteca no funciona correctamente\n")
                    }
                }
            } catch (e: Exception) {
                runOnUiThread {
                    statusText.text = "💥 Error crítico en inicialización"
                    statusText.setTextColor(Color.RED)
                    log("💥 Error crítico: ${e.message}\n")
                }
            }
        }.start()
    }

    private fun runQuickTest() {
        if (!isTestRunning.compareAndSet(false, true)) {
            log("⚠️ Ya hay un test ejecutándose, espera a que termine\n")
            return
        }

        log("🚀 Ejecutando test rápido...\n")

        Thread {
            try {
                val result = FIPS205Tester.runQuickTest()
                runOnUiThread {
                    if (result) {
                        log("✅ Test rápido exitoso - Funciones básicas OK\n\n")
                    } else {
                        log("❌ Test rápido falló\n\n")
                    }
                    isTestRunning.set(false)
                }
            } catch (e: Exception) {
                runOnUiThread {
                    log("💥 Error en test rápido: ${e.message}\n\n")
                    isTestRunning.set(false)
                }
            }
        }.start()
    }

    private fun runFullTestWithDebug() {
        if (!isTestRunning.compareAndSet(false, true)) {
            log("⚠️ Ya hay un test ejecutándose, espera a que termine\n")
            return
        }

        // UI updates en UI thread
        val btnFullTest = findViewById<Button>(R.id.btnFullTest)
        btnFullTest.isEnabled = false
        btnFullTest.text = "Ejecutando..."

        log("🧪 INICIANDO TESTS COMPLETOS DE FIPS 205\n")
        log("⏱️ Esto puede tomar varios minutos.\n")
        log("🔍 DEBUG MODE: Verás cada paso individual.\n")
        log("=".repeat(60) + "\n\n")

        Thread {
            val startTime = System.currentTimeMillis()

            try {
                // Log inicial de debug
                runOnUiThread {
                    forceUpdateUI("🔬 Thread de testing iniciado...\n")
                    forceUpdateUI("📞 Llamando a fipsTester.runAllTests()...\n")
                }

                // Ejecutar tests con callback en tiempo real
                val results = fipsTester.runAllTests()

                runOnUiThread {
                    val totalTime = System.currentTimeMillis() - startTime

                    forceUpdateUI("\n🏁 TESTS COMPLETADOS EN ${totalTime}ms (${totalTime/1000.0}s)\n")
                    forceUpdateUI("=".repeat(60) + "\n")

                    val passed = results.count { it.passed }
                    val failed = results.size - passed
                    val successRate = (passed * 100.0 / results.size).toInt()

                    forceUpdateUI("📊 RESUMEN FINAL:\n")
                    forceUpdateUI("   ✅ Exitosos: $passed\n")
                    forceUpdateUI("   ❌ Fallidos: $failed\n")
                    forceUpdateUI("   📈 Tasa de éxito: $successRate%\n")

                    if (failed > 0) {
                        forceUpdateUI("\n🔍 Tests que requieren atención:\n")
                        results.filter { !it.passed }.forEach { result ->
                            forceUpdateUI("   • ${result.testName}\n")
                            forceUpdateUI("     Motivo: ${result.message}\n")
                        }
                    } else {
                        forceUpdateUI("\n🎉 ¡Todos los tests pasaron exitosamente!\n")
                    }

                    forceUpdateUI("=".repeat(60) + "\n\n")

                    // Estadísticas adicionales
                    showTestStatistics(results, totalTime)

                    // Restaurar UI y estado
                    btnFullTest.isEnabled = true
                    btnFullTest.text = "Tests Completos"
                    isTestRunning.set(false)
                }

            } catch (e: Exception) {
                runOnUiThread {
                    forceUpdateUI("💥 ERROR CRÍTICO durante los tests: ${e.message}\n")
                    forceUpdateUI("Stack trace:\n")
                    e.stackTrace.take(5).forEach {
                        forceUpdateUI("   $it\n")
                    }
                    forceUpdateUI("\n")

                    // Restaurar UI y estado
                    btnFullTest.isEnabled = true
                    btnFullTest.text = "Tests Completos"
                    isTestRunning.set(false)
                }
            }
        }.start()
    }

    private fun showTestStatistics(results: List<FIPS205Tester.TestResult>, totalTime: Long) {
        forceUpdateUI("📈 ESTADÍSTICAS DETALLADAS:\n")

        // Categorizar tests
        val basicTests = results.filter { it.testName in listOf("genLen2", "toInt32", "toByte", "base2b", "RoundTripConversion") }
        val structureTests = results.filter { it.testName in listOf("ADRS", "computeHash") }
        val cryptoTests = results.filter { it.testName.contains("Algorithms") }

        forceUpdateUI("   🔧 Tests básicos: ${basicTests.count { it.passed }}/${basicTests.size}\n")
        forceUpdateUI("   🏗️ Tests estructura: ${structureTests.count { it.passed }}/${structureTests.size}\n")
        forceUpdateUI("   🔐 Tests criptográficos: ${cryptoTests.count { it.passed }}/${cryptoTests.size}\n")

        // Tiempo promedio por test
        val avgTime = totalTime / results.size
        forceUpdateUI("   ⏱️ Tiempo promedio por test: ${avgTime}ms\n")

        // Estado del sistema
        val allBasicPassed = basicTests.all { it.passed }
        val allStructurePassed = structureTests.all { it.passed }
        val allCryptoPassed = cryptoTests.all { it.passed }

        forceUpdateUI("\n🎯 EVALUACIÓN DEL SISTEMA:\n")
        forceUpdateUI("   ${if (allBasicPassed) "✅" else "❌"} Funciones básicas: ${if (allBasicPassed) "CORRECTAS" else "PROBLEMÁTICAS"}\n")
        forceUpdateUI("   ${if (allStructurePassed) "✅" else "❌"} Estructuras de datos: ${if (allStructurePassed) "CORRECTAS" else "PROBLEMÁTICAS"}\n")
        forceUpdateUI("   ${if (allCryptoPassed) "✅" else "❌"} Algoritmos criptográficos: ${if (allCryptoPassed) "CORRECTOS" else "PROBLEMÁTICOS"}\n")

        val systemHealth = when {
            allBasicPassed && allStructurePassed && allCryptoPassed -> "🟢 EXCELENTE"
            allBasicPassed && allStructurePassed -> "🟡 BUENO (problemas en cripto)"
            allBasicPassed -> "🟠 REGULAR (problemas en estructura/cripto)"
            else -> "🔴 CRÍTICO (problemas básicos)"
        }

        forceUpdateUI("   🩺 Estado general del sistema: $systemHealth\n")
    }

    private fun generateKeys() {
        log("🔑 Generando claves ${algorithms[currentAlgorithm]}...\n")
        val btnGenerateKeys = findViewById<Button>(R.id.btnGenerateKeys)
        btnGenerateKeys.isEnabled = false

        Thread {
            try {
                val functionLink = FunctionLink()
                val start = System.currentTimeMillis()
                val keyPair = functionLink.slhKeyGen()
                val time = System.currentTimeMillis() - start

                currentKeys = keyPair

                runOnUiThread {
                    log("✅ Claves generadas en ${time}ms\n")
                    log("Algoritmo: ${algorithms[currentAlgorithm]}\n")
                    log("Clave pública: ${keyPair[0].size} bytes\n")
                    log("Clave privada: ${keyPair[1].size} bytes\n\n")

                    updateKeyInfo()
                    btnSign.isEnabled = true
                    btnGenerateKeys.isEnabled = true
                }
            } catch (e: Exception) {
                runOnUiThread {
                    log("❌ Error generando claves: ${e.message}\n\n")
                    btnGenerateKeys.isEnabled = true
                }
            }
        }.start()
    }

    private fun signMessage() {
        val message = etMessage.text.toString()
        if (message.isBlank()) {
            log("⚠️ El mensaje no puede estar vacío\n\n")
            return
        }

        val keys = currentKeys
        if (keys == null) {
            log("⚠️ Primero debes generar las claves\n\n")
            return
        }

        log("✍️ Firmando mensaje...\n")
        btnSign.isEnabled = false

        Thread {
            try {
                val functionLink = FunctionLink()
                val messageBytes = message.toByteArray()
                val context = ByteArray(0)

                // Firmar
                val signStart = System.currentTimeMillis()
                val signature = functionLink.slhSign(messageBytes, context, keys[1])
                val signTime = System.currentTimeMillis() - signStart

                // Verificar
                val verifyStart = System.currentTimeMillis()
                val isValid = functionLink.slhVerify(messageBytes, signature, context, keys[0])
                val verifyTime = System.currentTimeMillis() - verifyStart

                runOnUiThread {
                    log("✅ FIRMA COMPLETADA\n")
                    log("Mensaje: \"${message.take(50)}${if (message.length > 50) "..." else ""}\"\n")
                    log("Algoritmo: ${algorithms[currentAlgorithm]}\n")
                    log("Tiempo firma: ${signTime}ms\n")
                    log("Tiempo verificación: ${verifyTime}ms\n")
                    log("Tamaño firma: ${signature.size} bytes\n")
                    log("Verificación: ${if (isValid) "✅ VÁLIDA" else "❌ INVÁLIDA"}\n")

                    // Mostrar inicio de la firma
                    val sigHex = signature.take(8).joinToString("") { String.format("%02X", it) }
                    log("Firma (inicio): $sigHex...\n")

                    // Test de seguridad
                    testSignatureSecurity(functionLink, messageBytes, context, signature, keys[0])

                    btnSign.isEnabled = true
                }
            } catch (e: Exception) {
                runOnUiThread {
                    log("❌ Error firmando: ${e.message}\n\n")
                    btnSign.isEnabled = true
                }
            }
        }.start()
    }

    private fun testSignatureSecurity(
        functionLink: FunctionLink,
        originalMessage: ByteArray,
        context: ByteArray,
        signature: ByteArray,
        publicKey: ByteArray
    ) {
        try {
            // Test con mensaje modificado
            val modifiedMessage = originalMessage.clone()
            if (modifiedMessage.isNotEmpty()) {
                modifiedMessage[0] = (modifiedMessage[0] + 1).toByte()
            }

            val shouldFail = functionLink.slhVerify(modifiedMessage, signature, context, publicKey)
            log("🔍 Test seguridad: ${if (!shouldFail) "✅ CORRECTO" else "❌ FALLO"}\n\n")

        } catch (e: Exception) {
            log("⚠️ Error en test seguridad: ${e.message}\n\n")
        }
    }

    private fun updateKeyInfo() {
        val keys = currentKeys
        if (keys != null) {
            layoutKeyInfo.visibility = View.VISIBLE
            val timestamp = SimpleDateFormat("HH:mm:ss", Locale.getDefault()).format(Date())
            tvKeyInfo.text = """
                Generadas: $timestamp
                Algoritmo: ${algorithms[currentAlgorithm]}
                Clave pública: ${keys[0].size} bytes
                Clave privada: ${keys[1].size} bytes
            """.trimIndent()
        } else {
            layoutKeyInfo.visibility = View.GONE
        }
    }

    private fun clearResults() {
        tvResults.text = "📝 Resultados limpiados - Listo para nuevos tests.\n\n"
    }

    private fun log(text: String) {
        forceUpdateUI(text)
    }

    companion object {
        init {
            System.loadLibrary("TFG_PARTE1")
        }
    }
}