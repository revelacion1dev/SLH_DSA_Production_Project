package com.revelacion1.tfg_parte1

import org.junit.Test
import org.junit.Assert.*
import org.junit.Before

class FIPS205Test {

    companion object {
        init {
            System.loadLibrary("TFG_PARTE1")
        }
    }

    private lateinit var testClass: FunctionLink

    @Before
    fun setup() {
        testClass = FunctionLink()
    }

    @Test
    fun testGenLen2() {
        // Test cases from FIPS 205 spec
        assertEquals("For n=16, lg_w=4", 3, testClass.genLen2(16, 4))
        assertEquals("For n=24, lg_w=4", 3, testClass.genLen2(24, 4))
        assertEquals("For n=32, lg_w=4", 3, testClass.genLen2(32, 4))

        // Additional test cases
        assertEquals("For n=8, lg_w=2", 4, testClass.genLen2(8, 2))
        assertEquals("For n=32, lg_w=8", 1, testClass.genLen2(32, 8))
    }

    @Test
    fun testToInt() {
        // Test conversion of byte arrays to integers
        // Test case 1: Simple value
        val testBytes1 = byteArrayOf(0x12, 0x34)
        assertEquals("Simple 2-byte value", 0x1234L, testClass.toInt(testBytes1, 2))

        // Test case 2: Maximum value for 4 bytes
        val testBytes2 = byteArrayOf(
            0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte()
        )
        assertEquals("Max 4-byte value", 0xFFFFFFFFL, testClass.toInt(testBytes2, 4))

        // Test case 3: Zero value
        val testBytes3 = byteArrayOf(0x00, 0x00, 0x00, 0x00)
        assertEquals("Zero value", 0L, testClass.toInt(testBytes3, 4))
    }

    @Test
    fun testToByte() {
        // Test case 1: Simple value
        val bytes1 = testClass.toByte(0x1234L, 2)
        assertArrayEquals("Simple 2-byte value",
            byteArrayOf(0x12, 0x34), bytes1)

        // Test case 2: Large value
        val bytes2 = testClass.toByte(0xFFFFFFFFL, 4)
        assertArrayEquals("Large 4-byte value",
            byteArrayOf(0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte()), bytes2)

        // Test case 3: Zero value
        val bytes3 = testClass.toByte(0L, 2)
        assertArrayEquals("Zero value",
            byteArrayOf(0x00, 0x00), bytes3)
    }

    @Test
    fun testRoundTripConversion() {
        // Test that toInt(toByte(x)) = x
        val testValues = listOf(0L, 1L, 0x1234L, 0xABCDEFL, 0xFFFFFFFF)

        for (value in testValues) {
            val bytes = testClass.toByte(value, 4)
            val roundTrip = testClass.toInt(bytes, 4)
            assertEquals("Round-trip conversion of $value failed", value, roundTrip)
        }
    }
}