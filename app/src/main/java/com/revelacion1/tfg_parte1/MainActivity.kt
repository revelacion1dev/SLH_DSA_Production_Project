package com.revelacion1.tfg_parte1

import android.annotation.SuppressLint
import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.widget.Button
import android.widget.TextView
import com.revelacion1.tfg_parte1.databinding.ActivityMainBinding

@SuppressLint("UnstableApiUsage")
class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding
    private lateinit var tester: FIPS205Tester

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        // Inicializar el tester
        tester = FIPS205Tester()

        // Obtener referencias a las vistas
        val runTestsButton = findViewById<Button>(R.id.runTestsButton)
        val testResultsTextView = findViewById<TextView>(R.id.testResultsTextView)

        // Configurar listener para el botón
        runTestsButton.setOnClickListener {
            // Cambiar el texto mientras se ejecutan los tests
            testResultsTextView.text = "Ejecutando tests..."

            // Ejecutar tests y mostrar resultados
            val results = tester.runAllTests()
            val resultText = buildResultText(results)
            testResultsTextView.text = resultText
        }
    }

    private fun buildResultText(results: List<FIPS205Tester.TestResult>): String {
        val sb = StringBuilder("Resultados de las pruebas:\n\n")

        for (result in results) {
            // Añadir símbolo visual para pasado/fallado
            val statusSymbol = if (result.passed) "✓" else "✗"
            val statusText = if (result.passed) "PASÓ" else "FALLÓ"

            sb.append("$statusSymbol ${result.testName}: $statusText\n")
            sb.append("${result.message}\n\n")
        }

        val passedCount = results.count { it.passed }
        val totalCount = results.size

        sb.append("Resumen: $passedCount de $totalCount tests pasaron")

        return sb.toString()
    }

    companion object {
        // Used to load the 'tfg_parte1' library on application startup.
        init {
            System.loadLibrary("TFG_PARTE1") // Carga la biblioteca nativa
        }
    }
}