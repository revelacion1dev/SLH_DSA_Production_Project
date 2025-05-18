#include <jni.h>
#include "fips205.h"
#include <vector>



// Extern "C" is used to prevent C++ name mangling ( to allow Java to find the functions by not changing the name in the compiler)
extern "C" {

// Helper function to throw Java exceptions from C++
void throwJavaException(JNIEnv* env, const char* exceptionClass, const char* message) {
    jclass cls = env->FindClass(exceptionClass);
    if (cls != nullptr) {
        env->ThrowNew(cls, message);
    }
}

JNIEXPORT jbyteArray JNICALL
Java_com_revelacion1_tfg_1parte1_FunctionLink_computeHash(JNIEnv *env,
                                                          jobject /*thisObj*/,
                                                          jbyteArray input,
                                                          jint outputLen) {
    // Obtener la longitud del array de entrada
    jsize inputLen = env->GetArrayLength(input);

    // Copiar los datos del jbyteArray a un ByteVector
    ByteVector inputVec(inputLen);
    env->GetByteArrayRegion(input, 0, inputLen, reinterpret_cast<jbyte*>(inputVec.data()));

    // Prepara el vector de vectores para concatenateAndHash (en este caso, solo uno)
    std::vector<ByteVector> inputs = {inputVec};

    // Vector de salida
    ByteVector output;
    bool ok = concatenateAndHash(inputs, output, static_cast<size_t>(outputLen));

    if (!ok) return nullptr;

    // Convertir el resultado a jbyteArray para devolverlo a Java/Kotlin
    jbyteArray result = env->NewByteArray(output.size());
    env->SetByteArrayRegion(result, 0, output.size(), reinterpret_cast<const jbyte*>(output.data()));
    return result;
}
/*
 * Class:     com_revelacion1_tfg_parte1_FunctionLink
 * Method:    genLen2
 * Signature: (JJ)J
 */
JNIEXPORT jlong JNICALL
Java_com_revelacion1_tfg_1parte1_FunctionLink_genLen2(JNIEnv *env, jobject thiz, jlong n, jlong lg_w) {
    return gen_len2(static_cast<uint64_t>(n), static_cast<uint64_t>(lg_w));
}

/*
 * Class:     com_revelacion1_tfg_parte1_FunctionLink
 * Method:    toInt
 * Signature: ([BJ)J
 */
JNIEXPORT jlong JNICALL
Java_com_revelacion1_tfg_1parte1_FunctionLink_toInt(JNIEnv *env, jobject thiz, jbyteArray x, jint n) {
    jsize len = env->GetArrayLength(x);
    if (len < n) {
        jclass exceptionClass = env->FindClass("java/lang/IllegalArgumentException");
        env->ThrowNew(exceptionClass, "Input array is too short");
        return 0;
    }

    std::vector<uint8_t> X(len);
    env->GetByteArrayRegion(x, 0, len, reinterpret_cast<jbyte*>(X.data()));

    try {
        return toInt(X, static_cast<uint64_t>(n));
    } catch (const std::exception& e) {
        jclass exceptionClass = env->FindClass("java/lang/RuntimeException");
        env->ThrowNew(exceptionClass, e.what());
        return 0;
    }
}

/*
 * Class:     com_revelacion1_tfg_parte1_ExampleUnitTest
 * Method:    toByte
 * Signature: (JJ)[B
 */
JNIEXPORT jbyteArray JNICALL
Java_com_revelacion1_tfg_1parte1_FunctionLink_toByte(JNIEnv *env, jobject thiz, jlong x, jint n) {
    try {
        std::vector<uint8_t> xVector;
        uint64_t temp = static_cast<uint64_t>(x);

        // Convertir jlong a vector de bytes (big-endian)
        while (temp > 0 || xVector.empty()) {
            xVector.push_back(temp & 0xFF);
            temp >>= 8;
        }
        std::reverse(xVector.begin(), xVector.end());

        // Llamar a la función C++ toByte
        std::vector<uint8_t> result = toByte(xVector, static_cast<uint64_t>(n));

        // Convertir resultado a jbyteArray
        jbyteArray byteArray = env->NewByteArray(result.size());
        env->SetByteArrayRegion(byteArray, 0, result.size(), reinterpret_cast<jbyte*>(result.data()));

        return byteArray;
    } catch (const std::exception& e) {
        jclass exceptionClass = env->FindClass("java/lang/RuntimeException");
        env->ThrowNew(exceptionClass, e.what());
        return nullptr;
    }
}


/*
 * Class:     com_revelacion1_tfg_parte1_ExampleUnitTest
 * Method:    base2b
 * Signature: ([BII)[I
 */
JNIEXPORT jintArray JNICALL
Java_com_revelacion1_tfg_1parte1_FunctionLink_base2b(JNIEnv *env, jobject thiz, jbyteArray x, jint b, jint out_len) {

    // Input validation
    if (b <= 0 || b > 31) {
        jclass exceptionClass = env->FindClass("java/lang/IllegalArgumentException");
        env->ThrowNew(exceptionClass, "b must be between 1 and 31");
        return nullptr;
    }

    // Convert Java byte array to C++ vector
    jsize len = env->GetArrayLength(x);
    std::vector<uint8_t> X(len);
    env->GetByteArrayRegion(x, 0, len, reinterpret_cast<jbyte*>(X.data()));

    try {
        // Call the implementation
        std::vector<uint32_t> result = base_2b(X, b, out_len);

        // Convert result to Java int array
        jintArray intArray = env->NewIntArray(result.size());
        env->SetIntArrayRegion(intArray, 0, result.size(), reinterpret_cast<jint*>(result.data()));
        return intArray;
    } catch (const std::exception& e) {
        // Handle all exceptions
        jclass exceptionClass = env->FindClass("java/lang/RuntimeException");
        env->ThrowNew(exceptionClass, e.what());
        return nullptr;
    }
}

/*
 * Class:     com_revelacion1_tfg_parte1_ExampleUnitTest
 * Method:    createADRS
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL
Java_com_revelacion1_tfg_1parte1_FunctionLink_createADRS(
        JNIEnv* env, jobject /* this */) {
    try {
        // Crear una instancia de ADRS y devolver su puntero como un valor long
        ADRS* adrs = new ADRS();
        return reinterpret_cast<jlong>(adrs);
    } catch (const std::exception& e) {
        throwJavaException(env, "java/lang/RuntimeException", e.what());
        return 0;
    }
}

/*
 * Class:     com_revelacion1_tfg_parte1_FunctionLink
 * Method:    disposeADRS
 * Signature: (J)V
 */
JNIEXPORT void JNICALL
Java_com_revelacion1_tfg_1parte1_FunctionLink_disposeADRS(
        JNIEnv* env, jobject /* this */, jlong adrsPtr) {
    try {
        if (adrsPtr != 0) {
            ADRS* adrs = reinterpret_cast<ADRS*>(adrsPtr);
            delete adrs;
        }
    } catch (const std::exception& e) {
        throwJavaException(env, "java/lang/RuntimeException", e.what());
    }
}

/*
 * Class:     com_revelacion1_tfg_parte1_FunctionLink
 * Method:    getAddressBytes
 * Signature: (J)[B
 */
JNIEXPORT jbyteArray JNICALL
Java_com_revelacion1_tfg_1parte1_FunctionLink_getAddressBytes(
        JNIEnv* env, jobject /* this */, jlong adrsPtr) {
    try {
        ADRS* adrs = reinterpret_cast<ADRS*>(adrsPtr);        // Crea la estructura a partir del puntero
        jbyteArray result = env->NewByteArray(32);
        env->SetByteArrayRegion(result, 0, 32, reinterpret_cast<const jbyte*>(adrs->addr.data()));
        return result;
    } catch (const std::exception& e) {
        throwJavaException(env, "java/lang/RuntimeException", e.what());
        return nullptr;
    }
}


/*
 * Class:     com_revelacion1_tfg_parte1_FunctionLink
 * Method:    setLayerAddress
 * Signature: (JI)V
 */
JNIEXPORT void JNICALL
Java_com_revelacion1_tfg_1parte1_FunctionLink_setLayerAddress(
        JNIEnv* env, jobject /* this */, jlong adrsPtr, jint layer) {
    try {
        ADRS* adrs = reinterpret_cast<ADRS*>(adrsPtr);
        adrs->setLayerAddress(static_cast<uint32_t>(layer));
    } catch (const std::exception& e) {
        throwJavaException(env, "java/lang/RuntimeException", e.what());
    }
}

/*
 * Class:     com_revelacion1_tfg_parte1_FunctionLink
 * Method:    setTreeAddress
 * Signature: (JJ)V
 */
JNIEXPORT void JNICALL
Java_com_revelacion1_tfg_1parte1_FunctionLink_setTreeAddress(
        JNIEnv* env, jobject /* this */, jlong adrsPtr, jbyteArray treeArray) {

    try {
        if (adrsPtr == 0 || treeArray == nullptr) return;

        jsize len = env->GetArrayLength(treeArray);
        if (len != 12) {
            throwJavaException(env, "java/lang/IllegalArgumentException", "Tree address must be 12 bytes");
            return;
        }

        // Extraer los bytes del array correctamente
        jbyte buffer[12];
        env->GetByteArrayRegion(treeArray, 0, len, buffer);

        // Convertir jbyte* a uint8_t* - esto es seguro
        ADRS* adrs = reinterpret_cast<ADRS*>(adrsPtr);
        adrs->setTreeAddress(reinterpret_cast<const uint8_t*>(buffer));

    } catch (const std::exception& e) {
        throwJavaException(env, "java/lang/RuntimeException", e.what());
    }
}

/*
 * Class:     com_revelacion1_tfg_parte1_FunctionLink
 * Method:    setTypeAndClear
 * Signature: (JI)V
 */
JNIEXPORT void JNICALL
Java_com_revelacion1_tfg_1parte1_FunctionLink_setTypeAndClear(
        JNIEnv* env, jobject /* this */, jlong adrsPtr, jint type) {
    try {
    ADRS* adrs = reinterpret_cast<ADRS*>(adrsPtr);
    adrs->setTypeAndClear(static_cast<uint32_t>(type));
    } catch (const std::exception& e) {
    throwJavaException(env, "java/lang/RuntimeException", e.what());
    }
}

/*
 * Class:     com_revelacion1_tfg_parte1_FunctionLink
 * Method:    setKeyPairAddress
 * Signature: (JI)V
 */
JNIEXPORT void JNICALL
Java_com_revelacion1_tfg_1parte1_FunctionLink_setKeyPairAddress(
        JNIEnv* env, jobject /* this */, jlong adrsPtr, jint keyPair) {
    try {
        ADRS* adrs = reinterpret_cast<ADRS*>(adrsPtr);
        adrs->setKeyPairAddress(static_cast<uint32_t>(keyPair));
    } catch (const std::exception& e) {
        throwJavaException(env, "java/lang/RuntimeException", e.what());
    }
}

/*
 * Class:     com_revelacion1_tfg_parte1_FunctionLink
 * Method:    setChainAddress
 * Signature: (JI)V
 */
JNIEXPORT void JNICALL
Java_com_revelacion1_tfg_1parte1_FunctionLink_setChainAddress(
        JNIEnv* env, jobject /* this */, jlong adrsPtr, jint chain) {
    try {
        ADRS *adrs = reinterpret_cast<ADRS *>(adrsPtr);
        adrs->setChainAddress(static_cast<uint32_t>(chain));
    }
    catch (const std::exception& e) {
        throwJavaException(env, "java/lang/RuntimeException", e.what());
    }
}

/*
 * Class:     com_revelacion1_tfg_parte1_FunctionLink
 * Method:    setTreeHeight
 * Signature: (JI)V
 */
JNIEXPORT void JNICALL
Java_com_revelacion1_tfg_1parte1_FunctionLink_setTreeHeight(
        JNIEnv* env, jobject /* this */, jlong adrsPtr, jint height) {
try {
    ADRS* adrs = reinterpret_cast<ADRS*>(adrsPtr);
    adrs->setTreeHeight(static_cast<uint32_t>(height));
    } catch (const std::exception& e) {
    throwJavaException(env, "java/lang/RuntimeException", e.what());
    }
}

/*
 * Class:     com_revelacion1_tfg_parte1_FunctionLink
 * Method:    setHashAddress
 * Signature: (JI)V
 */
JNIEXPORT void JNICALL
Java_com_revelacion1_tfg_1parte1_FunctionLink_setHashAddress(
        JNIEnv* env, jobject /* this */, jlong adrsPtr, jint hash) {
    try {
    ADRS* adrs = reinterpret_cast<ADRS*>(adrsPtr);
    adrs->setHashAddress(static_cast<uint32_t>(hash));
    } catch (const std::exception& e) {
    throwJavaException(env, "java/lang/RuntimeException", e.what());
    }
}

/*
 * Class:     com_revelacion1_tfg_parte1_FunctionLink
 * Method:    setTreeIndex
 * Signature: (JI)V
 */
JNIEXPORT void JNICALL
Java_com_revelacion1_tfg_1parte1_FunctionLink_setTreeIndex(
        JNIEnv* env, jobject /* this */, jlong adrsPtr, jint index) {
try {
    ADRS* adrs = reinterpret_cast<ADRS*>(adrsPtr);
    adrs->setTreeIndex(static_cast<uint32_t>(index));
    } catch (const std::exception& e) {
    throwJavaException(env, "java/lang/RuntimeException", e.what());
    }
}

/*
 * Class:     com_revelacion1_tfg_parte1_FunctionLink
 * Method:    getKeyPairAddress
 * Signature: (J)J
 */
JNIEXPORT jlong JNICALL
        Java_com_revelacion1_tfg_1parte1_FunctionLink_getKeyPairAddress(
        JNIEnv* env, jobject /* this */, jlong adrsPtr) {
    try {
    ADRS* adrs = reinterpret_cast<ADRS*>(adrsPtr);
    return static_cast<jlong>(adrs->getKeyPairAddress());
    } catch (const std::exception& e) {
    throwJavaException(env, "java/lang/RuntimeException", e.what());
    return 0;
    }
}

/*
 * Class:     com_revelacion1_tfg_parte1_FunctionLink
 * Method:    getTreeIndex
 * Signature: (J)J
 */
JNIEXPORT jlong JNICALL
        Java_com_revelacion1_tfg_1parte1_FunctionLink_getTreeIndex(
        JNIEnv* env, jobject /* this */, jlong adrsPtr) {
    try {
    ADRS* adrs = reinterpret_cast<ADRS*>(adrsPtr);
    return static_cast<jlong>(adrs->getTreeIndex());
    } catch (const std::exception& e) {
    throwJavaException(env, "java/lang/RuntimeException", e.what());
    return 0;
    }
}

/*
 *      Link WOTS+ class
 */
// Funciones para algoritmos WOTS+
/*
 * Class:     com_revelacion1_tfg_parte1_FunctionLink
 * Method:    chain
 * Signature: ([BII[BJI)[B
 */
JNIEXPORT jbyteArray JNICALL
Java_com_revelacion1_tfg_1parte1_FunctionLink_chain(
        JNIEnv *env, jobject /* this */, jbyteArray X, jint i, jint s,
        jbyteArray PKseed, jlong adrsPtr, jint n) {
    try {
        // Convertir jbyteArray a ByteVector
        jsize x_len = env->GetArrayLength(X);
        ByteVector x_vec(x_len);
        env->GetByteArrayRegion(X, 0, x_len, reinterpret_cast<jbyte*>(x_vec.data()));

        // Convertir PKseed a ByteVector
        jsize pkseed_len = env->GetArrayLength(PKseed);
        ByteVector pkseed_vec(pkseed_len);
        env->GetByteArrayRegion(PKseed, 0, pkseed_len, reinterpret_cast<jbyte*>(pkseed_vec.data()));

        // Obtener referencia a ADRS
        ADRS* adrs = reinterpret_cast<ADRS*>(adrsPtr);

        // Llamar a la función chain
        ByteVector result = chain(x_vec, static_cast<uint32_t>(i), static_cast<uint32_t>(s),
                                  pkseed_vec, *adrs, static_cast<size_t>(n));

        // Convertir resultado a jbyteArray
        jbyteArray resultArray = env->NewByteArray(result.size());
        env->SetByteArrayRegion(resultArray, 0, result.size(), reinterpret_cast<jbyte*>(result.data()));
        return resultArray;
    } catch (const std::exception& e) {
        throwJavaException(env, "java/lang/RuntimeException", e.what());
        return nullptr;
    }
}

/*
 * Class:     com_revelacion1_tfg_parte1_FunctionLink
 * Method:    wotsPkGen
 * Signature: ([B[BJI)[B
 */
JNIEXPORT jbyteArray JNICALL
Java_com_revelacion1_tfg_1parte1_FunctionLink_wotsPkGen(
        JNIEnv *env, jobject /* this */, jbyteArray SKseed, jbyteArray PKseed,
        jlong adrsPtr, jint n, jint wots_len) {
    try {
        // Convertir SKseed a ByteVector
        jsize skseed_len = env->GetArrayLength(SKseed);
        ByteVector skseed_vec(skseed_len);
        env->GetByteArrayRegion(SKseed, 0, skseed_len, reinterpret_cast<jbyte*>(skseed_vec.data()));

        // Convertir PKseed a ByteVector
        jsize pkseed_len = env->GetArrayLength(PKseed);
        ByteVector pkseed_vec(pkseed_len);
        env->GetByteArrayRegion(PKseed, 0, pkseed_len, reinterpret_cast<jbyte*>(pkseed_vec.data()));

        // Obtener referencia a ADRS
        ADRS* adrs = reinterpret_cast<ADRS*>(adrsPtr);

        // Llamar a la función wots_pkGen
        ByteVector result = wots_pkGen(skseed_vec, pkseed_vec, *adrs,
                                       static_cast<size_t>(n), static_cast<size_t>(wots_len));

        // Convertir resultado a jbyteArray
        jbyteArray resultArray = env->NewByteArray(result.size());
        env->SetByteArrayRegion(resultArray, 0, result.size(), reinterpret_cast<jbyte*>(result.data()));
        return resultArray;
    } catch (const std::exception& e) {
        throwJavaException(env, "java/lang/RuntimeException", e.what());
        return nullptr;
    }
}

/*
 * Class:     com_revelacion1_tfg_parte1_FunctionLink
 * Method:    wotsSign
 * Signature: ([B[B[BJI)[B
 */
JNIEXPORT jbyteArray JNICALL
Java_com_revelacion1_tfg_1parte1_FunctionLink_wotsSign(
        JNIEnv *env, jobject /* this */, jbyteArray M, jbyteArray SKseed,
        jbyteArray PKseed, jlong adrsPtr, jint n, jint wots_len) {
    try {
        // Convertir M a ByteVector
        jsize m_len = env->GetArrayLength(M);
        ByteVector m_vec(m_len);
        env->GetByteArrayRegion(M, 0, m_len, reinterpret_cast<jbyte*>(m_vec.data()));

        // Convertir SKseed a ByteVector
        jsize skseed_len = env->GetArrayLength(SKseed);
        ByteVector skseed_vec(skseed_len);
        env->GetByteArrayRegion(SKseed, 0, skseed_len, reinterpret_cast<jbyte*>(skseed_vec.data()));

        // Convertir PKseed a ByteVector
        jsize pkseed_len = env->GetArrayLength(PKseed);
        ByteVector pkseed_vec(pkseed_len);
        env->GetByteArrayRegion(PKseed, 0, pkseed_len, reinterpret_cast<jbyte*>(pkseed_vec.data()));

        // Obtener referencia a ADRS
        ADRS* adrs = reinterpret_cast<ADRS*>(adrsPtr);

        // Llamar a la función wots_sign
        ByteVector result = wots_sign(m_vec, skseed_vec, pkseed_vec, *adrs,
                                      static_cast<size_t>(n), static_cast<size_t>(wots_len));

        // Convertir resultado a jbyteArray
        jbyteArray resultArray = env->NewByteArray(result.size());
        env->SetByteArrayRegion(resultArray, 0, result.size(), reinterpret_cast<jbyte*>(result.data()));
        return resultArray;
    } catch (const std::exception& e) {
        throwJavaException(env, "java/lang/RuntimeException", e.what());
        return nullptr;
    }
}

/*
 * Class:     com_revelacion1_tfg_parte1_FunctionLink
 * Method:    wotsPkFromSig
 * Signature: ([B[B[BJI)[B
 */
JNIEXPORT jbyteArray JNICALL
Java_com_revelacion1_tfg_1parte1_FunctionLink_wotsPkFromSig(
        JNIEnv *env, jobject /* this */, jbyteArray sig, jbyteArray M,
        jbyteArray PKseed, jlong adrsPtr, jint n, jint wots_len) {
    try {
        // Convertir sig a ByteVector
        jsize sig_len = env->GetArrayLength(sig);
        ByteVector sig_vec(sig_len);
        env->GetByteArrayRegion(sig, 0, sig_len, reinterpret_cast<jbyte*>(sig_vec.data()));

        // Convertir M a ByteVector
        jsize m_len = env->GetArrayLength(M);
        ByteVector m_vec(m_len);
        env->GetByteArrayRegion(M, 0, m_len, reinterpret_cast<jbyte*>(m_vec.data()));

        // Convertir PKseed a ByteVector
        jsize pkseed_len = env->GetArrayLength(PKseed);
        ByteVector pkseed_vec(pkseed_len);
        env->GetByteArrayRegion(PKseed, 0, pkseed_len, reinterpret_cast<jbyte*>(pkseed_vec.data()));

        // Obtener referencia a ADRS
        ADRS* adrs = reinterpret_cast<ADRS*>(adrsPtr);

        // Llamar a la función wots_pkFromSig
        ByteVector result = wots_pkFromSig(sig_vec, m_vec, pkseed_vec, *adrs,
                                           static_cast<size_t>(n), static_cast<size_t>(wots_len));

        // Convertir resultado a jbyteArray
        jbyteArray resultArray = env->NewByteArray(result.size());
        env->SetByteArrayRegion(resultArray, 0, result.size(), reinterpret_cast<jbyte*>(result.data()));
        return resultArray;
    } catch (const std::exception& e) {
        throwJavaException(env, "java/lang/RuntimeException", e.what());
        return nullptr;
    }
}


} // extern "C"