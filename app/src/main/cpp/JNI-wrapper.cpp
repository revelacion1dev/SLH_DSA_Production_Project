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
Java_com_revelacion1_tfg_1parte1_FunctionLink_toInt(JNIEnv *env, jobject thiz, jbyteArray x, jlong n) {
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
Java_com_revelacion1_tfg_1parte1_FunctionLink_toByte(JNIEnv *env, jobject thiz, jlong x, jlong n) {
    try {
        // Primero convertir el jlong a un vector<uint8_t>
        std::vector<uint8_t> xVector;
        uint64_t temp = static_cast<uint64_t>(x);

        // Crear el vector de bytes
        while (temp > 0 || xVector.empty()) {
            xVector.push_back(temp & 0xFF);
            temp >>= 8;
        }

        // Invertir para formato big-endian
        std::reverse(xVector.begin(), xVector.end());

        // Usar el operador de ámbito global para llamar a toByte
        std::vector<uint8_t> result = toByte(xVector, static_cast<uint64_t>(n));

        // Convertir el resultado a un jbyteArray de Java
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
        adrs_ops::setLayerAddress(*adrs, static_cast<uint32_t>(layer));
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
        if (adrsPtr == 0 || treeArray == nullptr) return ; // Asegurar que los parametros se meten de forma correcta
        jsize len = env->GetArrayLength(treeArray);
        if (len != 12) {
            throwJavaException(env, "java/lang/IllegalArgumentException", "Tree address must be 12 bytes");
            return;
        }
        // Extraer los bytes del array
        jbyte buffer[12];
        env->GetByteArrayRegion(treeArray, 0, len, buffer);
        // Convertir el array de bytes a un array de uint8_t y llamar a la funcion
        ADRS* adrs = reinterpret_cast<ADRS*>(adrsPtr);
        adrs_ops::setTreeAddress(*adrs, reinterpret_cast<const uint8_t*>(buffer)); // Convertir a uint8_t (dado que convertimos un tipo en java a C++ no se permite usar static_cast)
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
    adrs_ops::setTypeAndClear(*adrs, static_cast<uint32_t>(type));
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
adrs_ops::setKeyPairAddress(*adrs, static_cast<uint32_t>(keyPair));
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
ADRS* adrs = reinterpret_cast<ADRS*>(adrsPtr);
adrs_ops::setChainAddress(*adrs, static_cast<uint32_t>(chain));
} catch (const std::exception& e) {
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
adrs_ops::setTreeHeight(*adrs, static_cast<uint32_t>(height));
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
adrs_ops::setHashAddress(*adrs, static_cast<uint32_t>(hash));
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
adrs_ops::setTreeIndex(*adrs, static_cast<uint32_t>(index));
} catch (const std::exception& e) {
throwJavaException(env, "java/lang/RuntimeException", e.what());
}
}

/*
 * Class:     com_revelacion1_tfg_parte1_FunctionLink
 * Method:    getKeyPairAddress
 * Signature: (J)I
 */
JNIEXPORT jint JNICALL
        Java_com_revelacion1_tfg_1parte1_FunctionLink_getKeyPairAddress(
        JNIEnv* env, jobject /* this */, jlong adrsPtr) {
try {
ADRS* adrs = reinterpret_cast<ADRS*>(adrsPtr);
return static_cast<jint>(adrs_ops::getKeyPairAddress(*adrs));
} catch (const std::exception& e) {
throwJavaException(env, "java/lang/RuntimeException", e.what());
return 0;
}
}

/*
 * Class:     com_revelacion1_tfg_parte1_FunctionLink
 * Method:    getTreeIndex
 * Signature: (J)I
 */
JNIEXPORT jint JNICALL
        Java_com_revelacion1_tfg_1parte1_FunctionLink_getTreeIndex(
        JNIEnv* env, jobject /* this */, jlong adrsPtr) {
    try {
    ADRS* adrs = reinterpret_cast<ADRS*>(adrsPtr);
    return static_cast<jint>(adrs_ops::getTreeIndex(*adrs));
    } catch (const std::exception& e) {
    throwJavaException(env, "java/lang/RuntimeException", e.what());
    return 0;
    }
}

} // extern "C"