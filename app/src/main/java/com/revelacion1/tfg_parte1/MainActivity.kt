package com.revelacion1.tfg_parte1

import android.content.ContentValues.TAG
import android.graphics.Color
import android.os.Bundle
import android.util.Log
import android.view.View
import android.widget.*
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.text.SimpleDateFormat
import java.util.*
import java.util.concurrent.atomic.AtomicBoolean

class MainActivity : AppCompatActivity() {

    // Views existentes
    private lateinit var statusText: TextView
    private lateinit var spinnerAlgorithm: Spinner
    private lateinit var etMessage: EditText
    private lateinit var layoutKeyInfo: LinearLayout
    private lateinit var tvPublicKeyInfo: TextView
    private lateinit var tvPrivateKeyInfo: TextView
    private lateinit var tvResults: TextView
    private lateinit var btnSign: Button
    private lateinit var btnNistTest: Button

    // NUEVOS Views para verificación
    private lateinit var etSignature: EditText
    private lateinit var etOriginalMessage: EditText
    private lateinit var etPublicKey: EditText
    private lateinit var btnVerify: Button
    private lateinit var layoutVerifyResult: LinearLayout
    private lateinit var tvVerifyResult: TextView

    // Estado mejorado
    private var currentKeys: Array<ByteArray>? = null  // [privateKey, publicKey] - orden interno
    private var currentPublicKeyHex: String? = null   // Clave pública en hex para fácil acceso
    private var currentAlgorithm = 0
    private lateinit var fipsTester: FIPS205Tester
    private lateinit var nistVectorTester: NISTVectorTester

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
        nistVectorTester = NISTVectorTester(this)

        setupFipsTesterLogger()
        setupNISTVectorTesterLogger()

        initViews()
        initFipsLibrary()
        setupListeners()
    }

    private fun initFipsLibrary(){
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

    private fun forceUpdateUI(message: String) {
        try {
            val current = tvResults.text.toString()
            val newText = current + message
            tvResults.text = newText

            tvResults.post {
                val scrollView = tvResults.parent as? ScrollView
                scrollView?.fullScroll(View.FOCUS_DOWN)
            }

            tvResults.invalidate()

        } catch (e: Exception) {
            println("Error updating UI: ${e.message}")
        }
    }

    private fun initViews() {
        // Views existentes
        statusText = findViewById(R.id.statusText)
        spinnerAlgorithm = findViewById(R.id.spinnerAlgorithm)
        etMessage = findViewById(R.id.etMessage)
        layoutKeyInfo = findViewById(R.id.layoutKeyInfo)
        tvPublicKeyInfo = findViewById(R.id.tvPublicKeyInfo)
        tvPrivateKeyInfo = findViewById(R.id.tvPrivateKeyInfo)
        tvResults = findViewById(R.id.tvResults)
        btnSign = findViewById(R.id.btnSign)
        btnNistTest = findViewById(R.id.btnNistTest)

        // NUEVOS Views para verificación
        etSignature = findViewById(R.id.etSignature)
        etOriginalMessage = findViewById(R.id.etOriginalMessage)
        etPublicKey = findViewById(R.id.etPublicKey)
        btnVerify = findViewById(R.id.btnVerify)
        layoutVerifyResult = findViewById(R.id.layoutVerifyResult)
        tvVerifyResult = findViewById(R.id.tvVerifyResult)

        // Configurar spinner
        val adapter = ArrayAdapter(this, android.R.layout.simple_spinner_item, algorithms)
        adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)
        spinnerAlgorithm.adapter = adapter
        spinnerAlgorithm.setSelection(1) // SHAKE-128s por defecto
    }

    private fun setupListeners() {
        // Listeners existentes
        findViewById<Button>(R.id.btnFullTest).setOnClickListener {
            if (!isTestRunning.get()) runFullTestWithDebug()
        }
        findViewById<Button>(R.id.btnGenerateKeys).setOnClickListener { generateKeys() }
        findViewById<Button>(R.id.btnSign).setOnClickListener { signMessage() }
        findViewById<Button>(R.id.btnClear).setOnClickListener { clearResults() }

        btnNistTest.setOnClickListener {
            if (!isTestRunning.get()) runNISTVectorTest()
        }

        // NUEVO: Listener para verificación
        btnVerify.setOnClickListener { verifySignature() }

        spinnerAlgorithm.onItemSelectedListener = object : AdapterView.OnItemSelectedListener {
            override fun onItemSelected(parent: AdapterView<*>?, view: View?, position: Int, id: Long) {
                currentAlgorithm = position
                currentKeys = null
                currentPublicKeyHex = null
                updateKeyInfo()
                btnSign.isEnabled = false
            }
            override fun onNothingSelected(parent: AdapterView<*>?) {}
        }
    }

    /**
     * NUEVA FUNCIÓN: Verificación de firmas
     */
    private fun verifySignature() {
        val signatureHex = etSignature.text.toString().trim()
        val originalMessage = etOriginalMessage.text.toString().trim()
        val publicKeyHex = etPublicKey.text.toString().trim()

        // Validaciones
        if (signatureHex.isEmpty() || originalMessage.isEmpty() || publicKeyHex.isEmpty()) {
            showVerifyResult(false, "⚠️ Por favor complete todos los campos")
            return
        }

        if (!isValidHexString(signatureHex)) {
            showVerifyResult(false, "⚠️ La firma debe estar en formato hexadecimal válido")
            return
        }

        if (!isValidHexString(publicKeyHex)) {
            showVerifyResult(false, "⚠️ La clave pública debe estar en formato hexadecimal válido")
            return
        }

        log("🔍 Verificando firma...\n")
        log("Mensaje: \"${originalMessage.take(50)}${if (originalMessage.length > 50) "..." else ""}\"\n")
        log("Algoritmo: ${algorithms[currentAlgorithm]}\n")

        btnVerify.isEnabled = false

        Thread {
            try {
                val functionLink = FunctionLink()
                val messageBytes = originalMessage.toByteArray()
                val signatureBytes = hexStringToByteArray(signatureHex)
                val publicKeyBytes = hexStringToByteArray(publicKeyHex)
                val context = ByteArray(0)

                val verifyStart = System.currentTimeMillis()
                val isValid = functionLink.slhVerify(messageBytes, signatureBytes, context, publicKeyBytes)
                val verifyTime = System.currentTimeMillis() - verifyStart

                runOnUiThread {
                    val resultText = if (isValid) "✅ FIRMA VÁLIDA" else "❌ FIRMA INVÁLIDA"
                    showVerifyResult(isValid, resultText)

                    log("🔍 VERIFICACIÓN COMPLETADA\n")
                    log("Resultado: $resultText\n")
                    log("Tiempo verificación: ${verifyTime}ms\n")
                    log("Tamaño firma: ${signatureBytes.size} bytes\n")
                    log("Tamaño clave pública: ${publicKeyBytes.size} bytes\n\n")

                    // 🆕 LOGCAT: Información de verificación en logcat
                    Log.i(TAG_VERIFY, "=".repeat(60))
                    Log.i(TAG_VERIFY, "🔍 VERIFICACIÓN DE FIRMA SLH-DSA")
                    Log.i(TAG_VERIFY, "Algoritmo: ${algorithms[currentAlgorithm]}")
                    Log.i(TAG_VERIFY, "Mensaje verificado: $originalMessage")
                    Log.i(TAG_VERIFY, "Resultado: ${if (isValid) "FIRMA VÁLIDA ✅" else "FIRMA INVÁLIDA ❌"}")
                    Log.i(TAG_VERIFY, "Tiempo verificación: ${verifyTime}ms")
                    Log.i(TAG_VERIFY, "Tamaño firma: ${signatureBytes.size} bytes")
                    Log.i(TAG_VERIFY, "Tamaño clave pública: ${publicKeyBytes.size} bytes")
                    Log.i(TAG_VERIFY, "-".repeat(40))
                    Log.i(TAG_VERIFY, "Clave pública usada: $publicKeyHex")
                    Log.i(TAG_VERIFY, "Firma verificada: $signatureHex")
                    Log.i(TAG_VERIFY, "=".repeat(60))

                    btnVerify.isEnabled = true
                }

            } catch (e: Exception) {
                runOnUiThread {
                    showVerifyResult(false, "💥 Error durante verificación: ${e.message}")
                    log("❌ Error verificando: ${e.message}\n\n")
                    btnVerify.isEnabled = true
                }
            }
        }.start()
    }

    /**
     * Mostrar resultado de verificación
     */
    private fun showVerifyResult(isValid: Boolean, message: String) {
        tvVerifyResult.text = message
        tvVerifyResult.setTextColor(
            getColor(
                if (isValid) android.R.color.holo_green_light
                else android.R.color.holo_red_light
            )
        )
        layoutVerifyResult.visibility = View.VISIBLE
    }

    /**
     * FUNCIÓN MEJORADA: Generación de claves con mejor gestión
     */
    private fun generateKeys() {
        log("🔑 Generando claves ${algorithms[currentAlgorithm]}...\n")
        val btnGenerateKeys = findViewById<Button>(R.id.btnGenerateKeys)
        btnGenerateKeys.isEnabled = false

        Thread {
            try {
                val functionLink = FunctionLink()
                val start = System.currentTimeMillis()
                val keyPair = functionLink.slhKeyGen()  // Retorna [publicKey, privateKey]
                val time = System.currentTimeMillis() - start

                // Guardar claves (orden interno: [privateKey, publicKey] para compatibilidad)
                currentKeys = arrayOf(keyPair[1], keyPair[0])  // [privateKey, publicKey]
                currentPublicKeyHex = byteArrayToHexString(keyPair[0])  // Solo la pública en hex

                runOnUiThread {
                    log("✅ Claves generadas en ${time}ms\n")
                    log("Algoritmo: ${algorithms[currentAlgorithm]}\n")
                    log("Clave pública: ${keyPair[0].size} bytes\n")
                    log("Clave privada: ${keyPair[1].size} bytes\n\n")

                    // 🆕 LOGCAT: Información de generación de claves
                    Log.i(TAG_KEYGEN, "=".repeat(60))
                    Log.i(TAG_KEYGEN, "🔑 GENERACIÓN DE CLAVES SLH-DSA")
                    Log.i(TAG_KEYGEN, "Algoritmo: ${algorithms[currentAlgorithm]}")
                    Log.i(TAG_KEYGEN, "Tiempo generación: ${time}ms")
                    Log.i(TAG_KEYGEN, "Tamaño clave pública: ${keyPair[0].size} bytes")
                    Log.i(TAG_KEYGEN, "Tamaño clave privada: ${keyPair[1].size} bytes")
                    Log.i(TAG_KEYGEN, "-".repeat(40))
                    Log.i(TAG_KEYGEN, "🔓 CLAVE PÚBLICA (HEX):")
                    Log.i(TAG_KEYGEN, currentPublicKeyHex!!)
                    Log.i(TAG_KEYGEN, "-".repeat(40))
                    Log.i(TAG_KEYGEN, "⚠️  CLAVE PRIVADA: ALMACENADA INTERNAMENTE (NO EXPUESTA)")
                    Log.i(TAG_KEYGEN, "=".repeat(60))

                    // Auto-rellenar el campo de clave pública para verificación
                    etPublicKey.setText(currentPublicKeyHex)

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

                // Firmar con clave privada
                val signStart = System.currentTimeMillis()
                val signature = functionLink.slhSign(messageBytes, context, keys[0]) // privateKey
                val signTime = System.currentTimeMillis() - signStart

                // Verificar con clave pública
                val verifyStart = System.currentTimeMillis()
                val isValid = functionLink.slhVerify(messageBytes, signature, context, keys[1]) // publicKey
                val verifyTime = System.currentTimeMillis() - verifyStart

                // Convertir firma a hexadecimal
                val signatureHex = byteArrayToHexString(signature)

                runOnUiThread {
                    log("✅ FIRMA COMPLETADA\n")
                    log("Mensaje: \"${message.take(50)}${if (message.length > 50) "..." else ""}\"\n")
                    log("Algoritmo: ${algorithms[currentAlgorithm]}\n")
                    log("Tiempo firma: ${signTime}ms\n")
                    log("Tiempo verificación: ${verifyTime}ms\n")
                    log("Tamaño firma: ${signature.size} bytes\n")
                    log("Verificación: ${if (isValid) "✅ VÁLIDA" else "❌ INVÁLIDA"}\n")

                    // Mostrar inicio de la firma en UI
                    val sigHex = signature.take(8).joinToString("") { String.format("%02X", it) }
                    log("Firma (inicio): $sigHex...\n")

                    // 🆕 LOGCAT: Mostrar información completa en el logcat del sistema
                    Log.i(TAG_SIGNATURE, "=".repeat(60))
                    Log.i(TAG_SIGNATURE, "🔐 FIRMA DIGITAL SLH-DSA GENERADA")
                    Log.i(TAG_SIGNATURE, "Algoritmo: ${algorithms[currentAlgorithm]}")
                    Log.i(TAG_SIGNATURE, "Mensaje original: $message")
                    Log.i(TAG_SIGNATURE, "Tamaño mensaje: ${messageBytes.size} bytes")
                    Log.i(TAG_SIGNATURE, "Tamaño firma: ${signature.size} bytes")
                    Log.i(TAG_SIGNATURE, "Tiempo generación: ${signTime}ms")
                    Log.i(TAG_SIGNATURE, "Verificación inicial: ${if (isValid) "VÁLIDA" else "INVÁLIDA"}")
                    Log.i(TAG_SIGNATURE, "-".repeat(40))
                    Log.i(TAG_SIGNATURE, "🔑 CLAVE PÚBLICA (HEX):")
                    Log.i(TAG_SIGNATURE, currentPublicKeyHex ?: "N/A")
                    Log.i(TAG_SIGNATURE, "-".repeat(40))
                    Log.i(TAG_SIGNATURE, "✍️ FIRMA COMPLETA (HEX):")
                    Log.i(TAG_SIGNATURE, signatureHex)
                    Log.i(TAG_SIGNATURE, "-".repeat(40))
                    Log.i(TAG_SIGNATURE, "📋 Para copiar desde logcat: adb logcat | grep SLH_DSA_SIGNATURE")
                    Log.i(TAG_SIGNATURE, "=".repeat(60))

                    // AUTO-RELLENAR campos de verificación para conveniencia
                    etSignature.setText(signatureHex)
                    etOriginalMessage.setText(message)
                    // etPublicKey ya está rellenado desde generateKeys()

                    log("\n📋 DATOS COPIADOS A VERIFICACIÓN:\n")
                    log("   🔤 Firma: Copiada automáticamente\n")
                    log("   📝 Mensaje: Copiado automáticamente\n")
                    log("   🔑 Clave pública: Ya disponible\n")
                    log("   ➡️ Puedes probar la verificación ahora\n")
                    log("   📱 Ver firma completa: adb logcat | grep SLH_DSA_SIGNATURE\n\n")

                    // Test de seguridad
                    testSignatureSecurity(functionLink, messageBytes, context, signature, keys[1])

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

    /**
     * FUNCIÓN MEJORADA: Actualizar información de claves
     */
    private fun updateKeyInfo() {
        val keys = currentKeys
        if (keys != null) {
            layoutKeyInfo.visibility = View.VISIBLE
            val timestamp = SimpleDateFormat("HH:mm:ss", Locale.getDefault()).format(Date())

            // Mostrar información de la clave pública (la que se expone)
            tvPublicKeyInfo.text = """🔓 Clave Pública (${keys[1].size} bytes):
${currentPublicKeyHex?.take(64)}${if ((currentPublicKeyHex?.length ?: 0) > 64) "..." else ""}"""

            // Mostrar información básica de la clave privada (sin exponer el contenido)
            tvPrivateKeyInfo.text = """🔐 Clave Privada (${keys[0].size} bytes):
Generada: $timestamp | Algoritmo: ${algorithms[currentAlgorithm]}"""

        } else {
            layoutKeyInfo.visibility = View.GONE
        }
    }

    /**
     * NUEVA FUNCIÓN: Limpiar resultados mejorado
     */
    private fun clearResults() {
        tvResults.text = "📝 Resultados limpiados - Listo para nuevos tests.\n\n"

        // Limpiar también los campos de verificación
        etSignature.setText("")
        etOriginalMessage.setText("")
        etPublicKey.setText("")
        layoutVerifyResult.visibility = View.GONE
    }

    // FUNCIONES AUXILIARES NUEVAS
    private fun isValidHexString(hex: String): Boolean {
        return hex.matches(Regex("^[0-9A-Fa-f]*$")) && hex.length % 2 == 0
    }

    private fun hexStringToByteArray(hex: String): ByteArray {
        val cleanHex = hex.replace("\\s".toRegex(), "").uppercase()
        return ByteArray(cleanHex.length / 2) { i ->
            cleanHex.substring(i * 2, i * 2 + 2).toInt(16).toByte()
        }
    }

    private fun byteArrayToHexString(bytes: ByteArray): String {
        return bytes.joinToString("") { String.format("%02X", it) }
    }

    private fun runNISTVectorTest() {
        if (!isTestRunning.compareAndSet(false, true)) {
            log("⚠️ Ya hay un test ejecutándose, espera a que termine\n")
            return
        }

        btnNistTest.isEnabled = false
        btnNistTest.text = "Ejecutando Vectores NIST..."

        log("🔬 PROCESADOR DE VECTORES NIST - SOLO SHAKE\n")
        log("📌 Configuraciones soportadas: SHAKE-128s/f, SHAKE-192s/f, SHAKE-256s/f\n")
        log("🎯 Procesando archivos JSON reales de NIST\n")
        log("=".repeat(60) + "\n\n")

        // Usar coroutines con Dispatchers.IO para operaciones intensivas
        lifecycleScope.launch(Dispatchers.Main) {
            val startTime = System.currentTimeMillis()

            try {
                withContext(Dispatchers.Main) {
                    forceUpdateUI("🔧 Inicializando procesador de vectores NIST...\n")
                    forceUpdateUI("📂 Buscando archivos JSON en assets/\n\n")
                }

                // Ejecutar en background thread
                val combinedResults = nistVectorTester.testOnlySHAKE()

                val totalTime = System.currentTimeMillis() - startTime

                // Actualizar UI en main thread
                withContext(Dispatchers.Main) {
                    displayNISTVectorResults("Test Combinado SHAKE", combinedResults)

                    forceUpdateUI("\n🏁 PROCESAMIENTO VECTORES NIST COMPLETADO\n")
                    forceUpdateUI("⏱️ Tiempo total: ${totalTime}ms (${totalTime/1000.0}s)\n")
                    forceUpdateUI("=".repeat(60) + "\n")

                    val combTotal = combinedResults.totalTests
                    val combPassed = combinedResults.passedTests

                    forceUpdateUI("\n📊 ANÁLISIS FINAL VECTORES NIST:\n")
                    forceUpdateUI("   🎯 Combinado: $combPassed/$combTotal (${if(combTotal > 0) (combPassed*100/combTotal) else 0}%)\n")

                    val overallRate = if (combTotal > 0) (combPassed * 100.0 / combTotal) else 0.0
                    val status = when {
                        overallRate >= 95 -> "🟢 EXCELENTE - Vectores NIST completamente compatibles"
                        overallRate >= 80 -> "🟡 BUENO - Vectores NIST mayormente compatibles"
                        overallRate >= 60 -> "🟠 REGULAR - Vectores NIST parcialmente compatibles"
                        else -> "🔴 PROBLEMÁTICO - Vectores NIST requieren revisión"
                    }

                    forceUpdateUI("   🔍 Estado NIST: $status\n")

                    btnNistTest.isEnabled = true
                    btnNistTest.text = "🏛️ Test Vectores NIST"
                    isTestRunning.set(false)
                }

            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    forceUpdateUI("💥 ERROR en procesamiento vectores NIST: ${e.message}\n")
                    btnNistTest.isEnabled = true
                    btnNistTest.text = "🏛️ Test Vectores NIST"
                    isTestRunning.set(false)
                }
            }
        }
    }

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

            val failures = result.results.filter { !it.passed }
            if (failures.isNotEmpty()) {
                forceUpdateUI("   🔴 FALLOS DETECTADOS:\n")
                failures.take(3).forEach { test ->
                    forceUpdateUI("      ❌ TC${test.tcId}: ${test.message}\n")
                    if (test.duration > 0) {
                        forceUpdateUI("         ⏱️ Tiempo: ${test.duration}ms\n")
                    }
                    test.details?.let { details ->
                        forceUpdateUI("         🔍 Detalles: $details\n")
                    }
                }
                if (failures.size > 3) {
                    forceUpdateUI("      ... y ${failures.size - 3} fallos más\n")
                }
                forceUpdateUI("\n")
            }

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

        if (result.results.any { !it.passed }) {
            forceUpdateUI("\n   💡 Para ver comparaciones detalladas de firmas:\n")
            forceUpdateUI("      adb logcat | grep 'NIST_SIGNATURE_DEBUG'\n")
        }

        forceUpdateUI("\n")
    }

    private fun runFullTestWithDebug() {
        if (!isTestRunning.compareAndSet(false, true)) {
            log("⚠️ Ya hay un test ejecutándose, espera a que termine\n")
            return
        }

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
                runOnUiThread {
                    forceUpdateUI("🔬 Thread de testing iniciado...\n")
                    forceUpdateUI("📞 Llamando a fipsTester.runAllTests()...\n")
                }

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

                    showTestStatistics(results, totalTime)

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

                    btnFullTest.isEnabled = true
                    btnFullTest.text = "Tests Completos"
                    isTestRunning.set(false)
                }
            }
        }.start()
    }

    private fun showTestStatistics(results: List<FIPS205Tester.TestResult>, totalTime: Long) {
        forceUpdateUI("📈 ESTADÍSTICAS DETALLADAS:\n")

        val basicTests = results.filter { it.testName in listOf("genLen2", "toInt32", "toByte", "base2b", "RoundTripConversion") }
        val structureTests = results.filter { it.testName in listOf("ADRS", "computeHash") }
        val cryptoTests = results.filter { it.testName.contains("Algorithms") }

        forceUpdateUI("   🔧 Tests básicos: ${basicTests.count { it.passed }}/${basicTests.size}\n")
        forceUpdateUI("   🏗️ Tests estructura: ${structureTests.count { it.passed }}/${structureTests.size}\n")
        forceUpdateUI("   🔐 Tests criptográficos: ${cryptoTests.count { it.passed }}/${cryptoTests.size}\n")

        val avgTime = totalTime / results.size
        forceUpdateUI("   ⏱️ Tiempo promedio por test: ${avgTime}ms\n")

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

    private fun log(text: String) {
        forceUpdateUI(text)
        // 📱 LOGCAT: Reflejar todo lo que aparece en la UI
        Log.i(TAG, text.replace("\n", ""))
    }

    /**
     * 🆕 FUNCIÓN: Mostrar instrucciones para acceder a logcat
     */
    private fun showLogcatInstructions() {
        log("\n📱 INSTRUCCIONES LOGCAT:\n")
        log("   Para ver información completa en logcat:\n")
        log("   • Generación claves: adb logcat | grep SLH_DSA_KEYGEN\n")
        log("   • Firma completa: adb logcat | grep SLH_DSA_SIGNATURE\n")
        log("   • Verificación: adb logcat | grep SLH_DSA_VERIFY\n")
        log("   • Todo junto: adb logcat | grep 'SLH_DSA_'\n\n")

        // También enviarlo al logcat
        Log.i(TAG_INFO, "=".repeat(50))
        Log.i(TAG_INFO, "📱 INSTRUCCIONES DE USO LOGCAT")
        Log.i(TAG_INFO, "Para filtrar logs específicos:")
        Log.i(TAG_INFO, "  adb logcat | grep SLH_DSA_KEYGEN")
        Log.i(TAG_INFO, "  adb logcat | grep SLH_DSA_SIGNATURE")
        Log.i(TAG_INFO, "  adb logcat | grep SLH_DSA_VERIFY")
        Log.i(TAG_INFO, "  adb logcat | grep 'SLH_DSA_'")
        Log.i(TAG_INFO, "=".repeat(50))
    }

    companion object {
        // Tags para logcat
        private const val TAG_KEYGEN = "SLH_DSA_KEYGEN"
        private const val TAG_SIGNATURE = "SLH_DSA_SIGNATURE"
        private const val TAG_VERIFY = "SLH_DSA_VERIFY"
        private const val TAG_INFO = "SLH_DSA_INFO"

        init {
            System.loadLibrary("TFG_PARTE1")
        }
    }
}