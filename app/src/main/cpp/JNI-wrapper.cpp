#include <jni.h>
#include "fips205.h"
#include <string>
#include <vector>
#include <memory>

// Funciones de utilidad para conversiones JNI
ByteVector jbyteArrayToByteVector(JNIEnv* env, jbyteArray array) {
    if (array == nullptr) return ByteVector();

    jsize length = env->GetArrayLength(array);
    jbyte* bytes = env->GetByteArrayElements(array, nullptr);

    ByteVector result(bytes, bytes + length);

    env->ReleaseByteArrayElements(array, bytes, JNI_ABORT);
    return result;
}

jbyteArray byteVectorToJbyteArray(JNIEnv* env, const ByteVector& vec) {
    jbyteArray result = env->NewByteArray(static_cast<jsize>(vec.size()));
    if (result != nullptr) {
        env->SetByteArrayRegion(result, 0, static_cast<jsize>(vec.size()),
                                reinterpret_cast<const jbyte*>(vec.data()));
    }
    return result;
}

//Esta recibe el mensaje
void handleCppException(JNIEnv* env, std::exception_ptr e) {
    jclass exceptionClass = env->FindClass("java/lang/RuntimeException");

    try {
        if (e) {
            std::rethrow_exception(e);  // Relanza la excepción para capturarla
        }
    } catch (const std::exception& ex) {
        env->ThrowNew(exceptionClass, ex.what());  // Usa el mensaje de la excepción
        return;
    } catch (...) {
        env->ThrowNew(exceptionClass, "Unknown C++ exception");  // Para excepciones no estándar
        return;
    }
}

// Configuration Manager Functions

extern "C" JNIEXPORT jboolean JNICALL
Java_com_revelacion1_tfg_1parte1_FunctionLink_initializeConfig(
        JNIEnv* env, jobject /* this */,
        jint defaultScheme) {
    try {
        auto scheme = static_cast<SLH_DSA_ParamSet>(defaultScheme);
        FIPS205ConfigManager::initialize(scheme);
        return JNI_TRUE;

    } catch(...) {
        handleCppException(env, std::current_exception());
        return JNI_FALSE;
    }
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_revelacion1_tfg_1parte1_FunctionLink_setParameterScheme(
        JNIEnv* env, jobject /* this */, jint scheme) {
    try {
        SLH_DSA_ParamSet paramSet = static_cast<SLH_DSA_ParamSet>(scheme);
        bool success = FIPS205ConfigManager::setSchema(paramSet);
        return static_cast<jboolean>(success);
    } catch(...) {
        handleCppException(env,std::current_exception());
        return JNI_FALSE;
    }
}
extern "C" JNIEXPORT jintArray JNICALL
Java_com_revelacion1_tfg_1parte1_FunctionLink_getCurrentParameters(
        JNIEnv* env, jobject /* this */) {
    try {
        const SLH_DSA_Params* params = FIPS205ConfigManager::getCurrentParams();
        if (!params) {
            return nullptr;
        }

        jintArray result = env->NewIntArray(9);
        jint values[9] = {
                static_cast<jint>(params->n),
                static_cast<jint>(params->h),
                static_cast<jint>(params->d),
                static_cast<jint>(params->h_prima),
                static_cast<jint>(params->a),
                static_cast<jint>(params->k),
                static_cast<jint>(params->lg_w),
                static_cast<jint>(params->m),
                static_cast<jint>(params->security_category)
        };

        env->SetIntArrayRegion(result, 0, 9, values);
        return result;
    } catch(...) {
        handleCppException(env,std::current_exception());
        return nullptr;
    }
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_revelacion1_tfg_1parte1_FunctionLink_getCurrentSchemaName(
        JNIEnv* env, jobject /* this */) {
    try {
        const SLH_DSA_Params* params = FIPS205ConfigManager::getCurrentParams();
        if (!params || !params->name) {
            return env->NewStringUTF("Unknown");
        }
        return env->NewStringUTF(params->name);
    } catch(...) {
        handleCppException(env,std::current_exception());
        return env->NewStringUTF("Error");
    }
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_revelacion1_tfg_1parte1_FunctionLink_isUsingCustomParameters(
        JNIEnv* env, jobject /* this */) {
    try {
        return static_cast<jboolean>(FIPS205ConfigManager::isUsingCustomParams());
    } catch(...) {
        handleCppException(env,std::current_exception());
        return JNI_FALSE;
    }
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_revelacion1_tfg_1parte1_FunctionLink_setCustomParameters(
        JNIEnv* env, jobject /* this */, jint n, jint h, jint d,
        jint h_prima, jint a, jint k, jint lg_w) {
    try {
        bool success = FIPS205ConfigManager::setCustomParams(
                static_cast<uint32_t>(n),
                static_cast<uint32_t>(h),
                static_cast<uint32_t>(d),
                static_cast<uint32_t>(h_prima),
                static_cast<uint32_t>(a),
                static_cast<uint32_t>(k),
                static_cast<uint32_t>(lg_w)
        );
        return static_cast<jboolean>(success);
    } catch(...) {
        handleCppException(env,std::current_exception());
        return JNI_FALSE;
    }
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_revelacion1_tfg_1parte1_FunctionLink_resetToStandard(
        JNIEnv* env, jobject /* this */, jint scheme) {
    try {
        SLH_DSA_ParamSet paramSet = static_cast<SLH_DSA_ParamSet>(scheme);
        return static_cast<jboolean>(FIPS205ConfigManager::resetToStandard(paramSet));
    } catch(...) {
        handleCppException(env,std::current_exception());
        return JNI_FALSE;
    }
}

extern "C" JNIEXPORT void JNICALL
Java_com_revelacion1_tfg_1parte1_FunctionLink_printCurrentConfig(
        JNIEnv* env, jobject /* this */) {
    try {
        const SLH_DSA_Params* params = FIPS205ConfigManager::getCurrentParams();
        if (params) {
            printf("FIPS205 Config: %s (n=%d, h=%d, d=%d)\n",
                   params->name, params->n, params->h, params->d);
        }
    }catch(...) {
        handleCppException(env,std::current_exception());
    }
}

extern "C" JNIEXPORT jintArray JNICALL
Java_com_revelacion1_tfg_1parte1_FunctionLink_calculateDerivedParams(
        JNIEnv* env, jobject /* this */) {
    try {
        const SLH_DSA_Params* params = FIPS205ConfigManager::getCurrentParams();
        if (!params) {
            return nullptr;
        }

        uint32_t w = 1 << params->lg_w;
        uint32_t len1 = (8 * params->n + params->lg_w - 1) / params->lg_w;
        uint32_t len2 = gen_len2(params->n, params->lg_w);
        uint32_t len = len1 + len2;
        uint32_t t = 1 << params->a;

        size_t wots_sig_size = len * params->n;
        size_t xmss_sig_size = wots_sig_size + params->h_prima * params->n;
        size_t fors_sig_size = params->k * (1 + params->a) * params->n;

        jintArray result = env->NewIntArray(8);
        jint values[8] = {
                static_cast<jint>(w),
                static_cast<jint>(len1),
                static_cast<jint>(len2),
                static_cast<jint>(len),
                static_cast<jint>(t),
                static_cast<jint>(wots_sig_size),
                static_cast<jint>(xmss_sig_size),
                static_cast<jint>(fors_sig_size)
        };

        env->SetIntArrayRegion(result, 0, 8, values);
        return result;
    } catch (...) {
        handleCppException(env,std::current_exception());
        return nullptr;
    }
}

extern "C" JNIEXPORT jintArray JNICALL
Java_com_revelacion1_tfg_1parte1_FunctionLink_getAllSchemaParameters(
        JNIEnv* env, jobject /* this */, jint schemeIndex) {
    try {
        if (schemeIndex < 0 || schemeIndex >= static_cast<int>(SLH_DSA_ParamSet::PARAM_COUNT)) {
            return nullptr;
        }

        const SLH_DSA_Params* params = get_params(static_cast<SLH_DSA_ParamSet>(schemeIndex));
        if (!params) {
            return nullptr;
        }

        jintArray result = env->NewIntArray(12);
        jint values[12] = {
                static_cast<jint>(params->n),
                static_cast<jint>(params->h),
                static_cast<jint>(params->d),
                static_cast<jint>(params->h_prima),
                static_cast<jint>(params->a),
                static_cast<jint>(params->k),
                static_cast<jint>(params->lg_w),
                static_cast<jint>(params->m),
                static_cast<jint>(params->security_category),
                static_cast<jint>(params->pk_bytes),
                static_cast<jint>(params->sig_bytes),
                static_cast<jint>(params->is_shake ? 1 : 0)
        };

        env->SetIntArrayRegion(result, 0, 12, values);
        return result;
    } catch (...) {
        handleCppException(env,std::current_exception());
        return nullptr;
    }
}



//
// SECCIÓN 1: FUNCIONES DE UTILIDAD
//

extern "C" JNIEXPORT jlong JNICALL
Java_com_revelacion1_tfg_1parte1_FunctionLink_genLen2(
        JNIEnv* env, jobject /* this */,jint n, jint lg_w) {
    try {
        uint32_t result = gen_len2(static_cast<uint32_t>(n), static_cast<uint32_t>(lg_w));
        return static_cast<jlong>(result);
    } catch (...) {
        handleCppException(env,std::current_exception());
        return 0;
    }
}

extern "C" JNIEXPORT jlong JNICALL
Java_com_revelacion1_tfg_1parte1_FunctionLink_toInt(
        JNIEnv* env, jobject /* this */, jbyteArray xBytes, jint n) {
    try {
        ByteVector x = jbyteArrayToByteVector(env, xBytes);
        uint32_t result = toInt(x, static_cast<uint64_t>(n));
        return static_cast<jlong>(result);
    } catch (...) {
        handleCppException(env,std::current_exception());
        return 0;
    }
}

extern "C" JNIEXPORT jbyteArray JNICALL
Java_com_revelacion1_tfg_1parte1_FunctionLink_toByte(
        JNIEnv* env, jobject /* this */, jlong x, jint n) {
    try {
        ByteVector input(static_cast<size_t>(n), 0);
        // Convertir el long a ByteVector - implementación simplificada
        for (int i = 0; i < n && i < 8; i++) {
            input[i] = static_cast<uint8_t>((x >> (8 * i)) & 0xFF);
        }
        ByteVector result = toByte(input, static_cast<uint64_t>(n));
        return byteVectorToJbyteArray(env, result);
    } catch (...) {
        handleCppException(env,std::current_exception());
        return nullptr;
    }
}

extern "C" JNIEXPORT jintArray JNICALL
Java_com_revelacion1_tfg_1parte1_FunctionLink_base2b(
        JNIEnv* env, jobject /* this */, jbyteArray xBytes, jint b, jint out_len) {
    try {
        ByteVector x = jbyteArrayToByteVector(env, xBytes);
        std::vector<uint32_t> result = base_2b(x, static_cast<int>(b), static_cast<int>(out_len));

        jintArray outputArray = env->NewIntArray(static_cast<jsize>(result.size()));
        if (outputArray != nullptr) {
            env->SetIntArrayRegion(outputArray, 0, static_cast<jsize>(result.size()),
                                   reinterpret_cast<const jint*>(result.data()));
        }
        return outputArray;
    } catch (...) {
        handleCppException(env,std::current_exception());
        return nullptr;
    }
}

//
// SECCIÓN 2: MANEJO DE ADRS
//

extern "C" JNIEXPORT jlong JNICALL
Java_com_revelacion1_tfg_1parte1_FunctionLink_createADRS(
        JNIEnv* env, jobject /* this */) {
    try {
        ADRS* adrs = new ADRS();
        return reinterpret_cast<jlong>(adrs);
    } catch (...) {
        handleCppException(env,std::current_exception());
        return 0;
    }
}

extern "C" JNIEXPORT void JNICALL
Java_com_revelacion1_tfg_1parte1_FunctionLink_disposeADRS(
        JNIEnv* env, jobject /* this */, jlong adrsPtr) {
    try {
        ADRS* adrs = reinterpret_cast<ADRS*>(adrsPtr);
        delete adrs;
    } catch (...) {
        handleCppException(env,std::current_exception());
    }
}

extern "C" JNIEXPORT jbyteArray JNICALL
Java_com_revelacion1_tfg_1parte1_FunctionLink_getAddressBytes(
        JNIEnv* env, jobject /* this */, jlong adrsPtr) {
    try {
        ADRS* adrs = reinterpret_cast<ADRS*>(adrsPtr);
        ByteVector result = adrs->toVector();
        return byteVectorToJbyteArray(env, result);
    } catch (...) {
        handleCppException(env,std::current_exception());
        return nullptr;
    }
}

extern "C" JNIEXPORT void JNICALL
Java_com_revelacion1_tfg_1parte1_FunctionLink_setLayerAddress(
        JNIEnv* env, jobject /* this */, jlong adrsPtr, jint layer) {
    try {
        ADRS* adrs = reinterpret_cast<ADRS*>(adrsPtr);
        adrs->setLayerAddress(static_cast<uint32_t>(layer));
    } catch (...) {
        handleCppException(env,std::current_exception());
    }
}

// Nueva función más directa
extern "C" JNIEXPORT void JNICALL
Java_com_revelacion1_tfg_1parte1_FunctionLink_setTreeAddress(
        JNIEnv* env, jobject, jlong adrsPtr, jlong treeIndex) {
    try {
        ADRS* adrs = reinterpret_cast<ADRS*>(adrsPtr);
        adrs->setTreeAddress(static_cast<uint64_t>(treeIndex));
    } catch (...) {
        handleCppException(env,std::current_exception());
    }
}

extern "C" JNIEXPORT void JNICALL
Java_com_revelacion1_tfg_1parte1_FunctionLink_setTypeAndClear(
        JNIEnv* env, jobject /* this */, jlong adrsPtr, jint type) {
    try {
        ADRS* adrs = reinterpret_cast<ADRS*>(adrsPtr);
        adrs->setTypeAndClear(static_cast<uint32_t>(type));
    } catch (...) {
        handleCppException(env,std::current_exception());
    }
}

extern "C" JNIEXPORT void JNICALL
Java_com_revelacion1_tfg_1parte1_FunctionLink_setKeyPairAddress(
        JNIEnv* env, jobject /* this */, jlong adrsPtr, jint keyPair) {
    try {
        ADRS* adrs = reinterpret_cast<ADRS*>(adrsPtr);
        adrs->setKeyPairAddress(static_cast<uint32_t>(keyPair));
    } catch (...) {
        handleCppException(env,std::current_exception());
    }
}

extern "C" JNIEXPORT void JNICALL
Java_com_revelacion1_tfg_1parte1_FunctionLink_setChainAddress(
        JNIEnv* env, jobject /* this */, jlong adrsPtr, jint chain) {
    try {
        ADRS* adrs = reinterpret_cast<ADRS*>(adrsPtr);
        adrs->setChainAddress(static_cast<uint32_t>(chain));
    } catch (...) {
        handleCppException(env,std::current_exception());
    }
}

extern "C" JNIEXPORT void JNICALL
Java_com_revelacion1_tfg_1parte1_FunctionLink_setTreeHeight(
        JNIEnv* env, jobject /* this */, jlong adrsPtr, jint height) {
    try {
        ADRS* adrs = reinterpret_cast<ADRS*>(adrsPtr);
        adrs->setTreeHeight(static_cast<uint32_t>(height));
    } catch (...) {
        handleCppException(env,std::current_exception());
    }
}

extern "C" JNIEXPORT void JNICALL
Java_com_revelacion1_tfg_1parte1_FunctionLink_setHashAddress(
        JNIEnv* env, jobject /* this */, jlong adrsPtr, jint hash) {
    try {
        ADRS* adrs = reinterpret_cast<ADRS*>(adrsPtr);
        adrs->setHashAddress(static_cast<uint32_t>(hash));
    } catch (...) {
        handleCppException(env,std::current_exception());
    }
}

extern "C" JNIEXPORT void JNICALL
Java_com_revelacion1_tfg_1parte1_FunctionLink_setTreeIndex(
        JNIEnv* env, jobject /* this */, jlong adrsPtr, jint index) {
    try {
        ADRS* adrs = reinterpret_cast<ADRS*>(adrsPtr);
        adrs->setTreeIndex(static_cast<uint32_t>(index));
    } catch (...) {
        handleCppException(env,std::current_exception());
    }
}

extern "C" JNIEXPORT jlong JNICALL
Java_com_revelacion1_tfg_1parte1_FunctionLink_getKeyPairAddress(
        JNIEnv* env, jobject /* this */, jlong adrsPtr) {
    try {
        ADRS* adrs = reinterpret_cast<ADRS*>(adrsPtr);
        return static_cast<jlong>(adrs->getKeyPairAddress());
    } catch (...) {
        handleCppException(env,std::current_exception());
        return 0;
    }
}

extern "C" JNIEXPORT jlong JNICALL
Java_com_revelacion1_tfg_1parte1_FunctionLink_getTreeIndex(
        JNIEnv* env, jobject /* this */, jlong adrsPtr) {
    try {
        ADRS* adrs = reinterpret_cast<ADRS*>(adrsPtr);
        return static_cast<jlong>(adrs->getTreeIndex());
    } catch (...) {
        handleCppException(env,std::current_exception());
        return 0;
    }
}

//
// SECCIÓN 3: FUNCIÓN DE HASH DE PRUEBA
//

extern "C" JNIEXPORT jbyteArray JNICALL
Java_com_revelacion1_tfg_1parte1_FunctionLink_computeHash(
        JNIEnv* env, jobject /* this */, jbyteArray inputBytes, jint version) {
    try {
        ByteVector input = jbyteArrayToByteVector(env, inputBytes);
        ByteVector output(32); // SHA-256 produce 32 bytes

        bool success = computeShake(input, output, 32);
        if (!success) {
            jclass exceptionClass = env->FindClass("java/lang/RuntimeException");
            env->ThrowNew(exceptionClass, "Hash computation failed");
            return nullptr;
        }

        return byteVectorToJbyteArray(env, output);
    } catch (...) {
        handleCppException(env,std::current_exception());
        return nullptr;
    }
}

//
// SECCIÓN 4: ALGORITMOS WOTS+
//

extern "C" JNIEXPORT jbyteArray JNICALL
Java_com_revelacion1_tfg_1parte1_FunctionLink_chain(
        JNIEnv* env, jobject /* this */,
        jbyteArray XBytes,
        jint i,
        jint s,
        jbyteArray PKseedBytes,
        jlong adrsPtr) {
    try {
        ByteVector X = jbyteArrayToByteVector(env, XBytes);
        ByteVector PKseed = jbyteArrayToByteVector(env, PKseedBytes);
        ADRS* adrs = reinterpret_cast<ADRS*>(adrsPtr);

        ByteVector result = chain(X, static_cast<uint32_t>(i), static_cast<uint32_t>(s),
                                  PKseed, *adrs);
        return byteVectorToJbyteArray(env, result);
    } catch (...) {
        handleCppException(env,std::current_exception());
        return nullptr;
    }
}

extern "C" JNIEXPORT jbyteArray JNICALL
Java_com_revelacion1_tfg_1parte1_FunctionLink_wotsPkGen(
        JNIEnv* env, jobject /* this */, jbyteArray SKseedBytes,
        jbyteArray PKseedBytes, jlong adrsPtr) {
    try {
        ByteVector SKseed = jbyteArrayToByteVector(env, SKseedBytes);
        ByteVector PKseed = jbyteArrayToByteVector(env, PKseedBytes);
        ADRS* adrs = reinterpret_cast<ADRS*>(adrsPtr);

        ByteVector result = wots_pkGen(SKseed, PKseed, *adrs);
        return byteVectorToJbyteArray(env, result);
    } catch (...) {
        handleCppException(env,std::current_exception());
        return nullptr;
    }
}

extern "C" JNIEXPORT jbyteArray JNICALL
Java_com_revelacion1_tfg_1parte1_FunctionLink_wotsSign(
        JNIEnv* env, jobject /* this */, jbyteArray MBytes,
        jbyteArray SKseedBytes, jbyteArray PKseedBytes, jlong adrsPtr) {
    try {
        ByteVector M = jbyteArrayToByteVector(env, MBytes);
        ByteVector SKseed = jbyteArrayToByteVector(env, SKseedBytes);
        ByteVector PKseed = jbyteArrayToByteVector(env, PKseedBytes);
        ADRS* adrs = reinterpret_cast<ADRS*>(adrsPtr);

        ByteVector result = wots_sign(M, SKseed, PKseed, *adrs);
        return byteVectorToJbyteArray(env, result);
    } catch (...) {
        handleCppException(env,std::current_exception());
        return nullptr;
    }
}

extern "C" JNIEXPORT jbyteArray JNICALL
Java_com_revelacion1_tfg_1parte1_FunctionLink_wotsPkFromSig(
        JNIEnv* env, jobject /* this */, jbyteArray sigBytes,
        jbyteArray MBytes, jbyteArray PKseedBytes, jlong adrsPtr) {
    try {
        ByteVector sig = jbyteArrayToByteVector(env, sigBytes);
        ByteVector M = jbyteArrayToByteVector(env, MBytes);
        ByteVector PKseed = jbyteArrayToByteVector(env, PKseedBytes);
        ADRS* adrs = reinterpret_cast<ADRS*>(adrsPtr);

        ByteVector result = wots_pkFromSig(sig, M, PKseed, *adrs);
        return byteVectorToJbyteArray(env, result);
    } catch (...) {
        handleCppException(env,std::current_exception());
        return nullptr;
    }
}

//
// SECCIÓN 5: ALGORITMOS XMSS
//

extern "C" JNIEXPORT jbyteArray JNICALL
Java_com_revelacion1_tfg_1parte1_FunctionLink_xmssNode(
        JNIEnv* env, jobject /* this */, jbyteArray SKseedBytes,
        jint i, jint z, jbyteArray PKseedBytes, jlong adrsPtr) {
    try {
        ByteVector SKseed = jbyteArrayToByteVector(env, SKseedBytes);
        ByteVector PKseed = jbyteArrayToByteVector(env, PKseedBytes);
        ADRS* adrs = reinterpret_cast<ADRS*>(adrsPtr);

        ByteVector result = xmss_node(SKseed, static_cast<uint32_t>(i),
                                      static_cast<uint32_t>(z), PKseed, *adrs);
        return byteVectorToJbyteArray(env, result);
    } catch (...) {
        handleCppException(env,std::current_exception());
        return nullptr;
    }
}

extern "C" JNIEXPORT jbyteArray JNICALL
Java_com_revelacion1_tfg_1parte1_FunctionLink_xmssSign(
        JNIEnv* env, jobject /* this */, jbyteArray MBytes,
        jbyteArray SKseedBytes, jint idx, jbyteArray PKseedBytes,
        jlong adrsPtr) {
    try {
        ByteVector M = jbyteArrayToByteVector(env, MBytes);
        ByteVector SKseed = jbyteArrayToByteVector(env, SKseedBytes);
        ByteVector PKseed = jbyteArrayToByteVector(env, PKseedBytes);
        ADRS* adrs = reinterpret_cast<ADRS*>(adrsPtr);

        ByteVector result = xmss_sign(M, SKseed, static_cast<uint32_t>(idx), PKseed, *adrs);
        return byteVectorToJbyteArray(env, result);
    } catch (...) {
        handleCppException(env,std::current_exception());
        return nullptr;
    }
}

extern "C" JNIEXPORT jbyteArray JNICALL
Java_com_revelacion1_tfg_1parte1_FunctionLink_xmssPkFromSig(
        JNIEnv* env, jobject /* this */, jint idx, jbyteArray SIGXMSSBytes,
        jbyteArray MBytes, jbyteArray PKseedBytes, jlong adrsPtr) {
    try {
        ByteVector SIGXMSS = jbyteArrayToByteVector(env, SIGXMSSBytes);
        ByteVector M = jbyteArrayToByteVector(env, MBytes);
        ByteVector PKseed = jbyteArrayToByteVector(env, PKseedBytes);
        ADRS* adrs = reinterpret_cast<ADRS*>(adrsPtr);

        ByteVector result = xmss_pkFromSig(static_cast<uint32_t>(idx), SIGXMSS, M, PKseed, *adrs);
        return byteVectorToJbyteArray(env, result);
    } catch (...) {
        handleCppException(env,std::current_exception());
        return nullptr;
    }
}

//
// SECCIÓN 6: ALGORITMOS HT (HYPERTREE)
//

extern "C" JNIEXPORT jbyteArray JNICALL
Java_com_revelacion1_tfg_1parte1_FunctionLink_htSign(
        JNIEnv* env, jobject /* this */, jbyteArray MBytes,
        jbyteArray SKseedBytes, jbyteArray PKseedBytes,
        jlong idxtree, jint idxleaf) {
    try {
        ByteVector M = jbyteArrayToByteVector(env, MBytes);
        ByteVector SKseed = jbyteArrayToByteVector(env, SKseedBytes);
        ByteVector PKseed = jbyteArrayToByteVector(env, PKseedBytes);

        ByteVector result = ht_sign(M, SKseed, PKseed, static_cast<uint32_t>(idxtree),
                                    static_cast<uint32_t>(idxleaf));
        return byteVectorToJbyteArray(env, result);
    } catch (...) {
        handleCppException(env,std::current_exception());
        return nullptr;
    }
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_revelacion1_tfg_1parte1_FunctionLink_htVerify(
        JNIEnv* env, jobject /* this */, jbyteArray MBytes,
        jbyteArray SIGHTBytes, jbyteArray PKseedBytes,
        jlong idxtree, jint idxleaf, jbyteArray PKrootBytes) {
    try {
        ByteVector M = jbyteArrayToByteVector(env, MBytes);
        ByteVector SIGHT = jbyteArrayToByteVector(env, SIGHTBytes);
        ByteVector PKseed = jbyteArrayToByteVector(env, PKseedBytes);
        ByteVector PKroot = jbyteArrayToByteVector(env, PKrootBytes);

        bool result = ht_verify(M, SIGHT, PKseed, static_cast<uint32_t>(idxtree),
                                static_cast<uint32_t>(idxleaf), PKroot);
        return static_cast<jboolean>(result);
    } catch (...) {
        handleCppException(env,std::current_exception());
        return JNI_FALSE;
    }
}

//
// SECCIÓN 7: ALGORITMOS FORS
//

extern "C" JNIEXPORT jbyteArray JNICALL
Java_com_revelacion1_tfg_1parte1_FunctionLink_forsSkGen(
        JNIEnv* env, jobject /* this */, jbyteArray SKseedBytes,
        jbyteArray PKseedBytes, jlong adrsPtr, jint idx) {
    try {
        ByteVector SKseed = jbyteArrayToByteVector(env, SKseedBytes);
        ByteVector PKseed = jbyteArrayToByteVector(env, PKseedBytes);
        ADRS* adrs = reinterpret_cast<ADRS*>(adrsPtr);

        ByteVector result = fors_skGen(SKseed, PKseed, *adrs, static_cast<uint32_t>(idx));
        return byteVectorToJbyteArray(env, result);
    } catch (...) {
        handleCppException(env,std::current_exception());
        return nullptr;
    }
}

extern "C" JNIEXPORT jbyteArray JNICALL
Java_com_revelacion1_tfg_1parte1_FunctionLink_forsNode(
        JNIEnv* env, jobject /* this */, jbyteArray SKseedBytes,
        jint i, jint z, jbyteArray PKseedBytes, jlong adrsPtr) {
    try {
        ByteVector SKseed = jbyteArrayToByteVector(env, SKseedBytes);
        ByteVector PKseed = jbyteArrayToByteVector(env, PKseedBytes);
        ADRS* adrs = reinterpret_cast<ADRS*>(adrsPtr);

        ByteVector result = fors_node(SKseed, static_cast<uint32_t>(i),
                                      static_cast<uint32_t>(z), PKseed, *adrs);
        return byteVectorToJbyteArray(env, result);
    } catch (...) {
        handleCppException(env,std::current_exception());
        return nullptr;
    }
}

extern "C" JNIEXPORT jbyteArray JNICALL
Java_com_revelacion1_tfg_1parte1_FunctionLink_forsSign(
        JNIEnv* env, jobject /* this */, jbyteArray mdBytes,
        jbyteArray SKseedBytes, jbyteArray PKseedBytes,
        jlong adrsPtr) {
    try {
        ByteVector md = jbyteArrayToByteVector(env, mdBytes);
        ByteVector SKseed = jbyteArrayToByteVector(env, SKseedBytes);
        ByteVector PKseed = jbyteArrayToByteVector(env, PKseedBytes);
        ADRS* adrs = reinterpret_cast<ADRS*>(adrsPtr);

        ByteVector result = fors_sign(md, SKseed, PKseed, *adrs);
        return byteVectorToJbyteArray(env, result);
    } catch (...) {
        handleCppException(env,std::current_exception());
        return nullptr;
    }
}

extern "C" JNIEXPORT jbyteArray JNICALL
Java_com_revelacion1_tfg_1parte1_FunctionLink_forsPkFromSig(
        JNIEnv* env, jobject /* this */,
        jbyteArray SIGFORSBytes,
        jbyteArray mdBytes,
        jbyteArray PKseedBytes,
        jlong adrsPtr) {
    try {
        ByteVector SIGFORS = jbyteArrayToByteVector(env, SIGFORSBytes);
        ByteVector md = jbyteArrayToByteVector(env, mdBytes);
        ByteVector PKseed = jbyteArrayToByteVector(env, PKseedBytes);
        ADRS* adrs = reinterpret_cast<ADRS*>(adrsPtr);

        ByteVector result = fors_pkFromSig(SIGFORS, md, PKseed, *adrs);
        return byteVectorToJbyteArray(env, result);
    } catch (...) {
        handleCppException(env,std::current_exception());
        return nullptr;
    }
}
// ALGORITMOS SLH-DSA PRINCIPALES , preparados para ser llamados
extern "C" JNIEXPORT jobjectArray JNICALL
Java_com_revelacion1_tfg_1parte1_FunctionLink_slhKeyGen(
        JNIEnv* env, jobject /* this */) {
    try {
        auto keyPair = slh_keygen();

        jbyteArray publicKeyBytes = byteVectorToJbyteArray(env, keyPair.second.toBytes());
        jbyteArray privateKeyBytes = byteVectorToJbyteArray(env, keyPair.first.toBytes());

        jclass byteArrayClass = env->FindClass("[B");
        jobjectArray result = env->NewObjectArray(2, byteArrayClass, nullptr);

        env->SetObjectArrayElement(result, 0, publicKeyBytes);
        env->SetObjectArrayElement(result, 1, privateKeyBytes);

        return result;
    } catch (...) {
        handleCppException(env,std::current_exception());
        return nullptr;
    }
}

// Interfaces Externas
extern "C" JNIEXPORT jbyteArray JNICALL
Java_com_revelacion1_tfg_1parte1_FunctionLink_slhSign(
        JNIEnv* env, jobject /* this */,
        jbyteArray MBytes,
        jbyteArray ctxBytes,
        jbyteArray SKBytes) {  // ¡Sin paramSet!
    try {
        ByteVector M = jbyteArrayToByteVector(env, MBytes);
        ByteVector ctx = jbyteArrayToByteVector(env, ctxBytes);
        ByteVector SKData = jbyteArrayToByteVector(env, SKBytes);

        SLH_DSA_PrivateKey SK = SLH_DSA_PrivateKey::fromBytes(SKData);

        ByteVector signature = slh_sign(M, ctx, SK);
        return byteVectorToJbyteArray(env, signature);
    } catch (...) {
        handleCppException(env,std::current_exception());
        return nullptr;
    }
}
extern "C" JNIEXPORT jboolean JNICALL
Java_com_revelacion1_tfg_1parte1_FunctionLink_slhVerify(
        JNIEnv* env, jobject /* this */,
        jbyteArray MBytes,
        jbyteArray SIGBytes,
        jbyteArray ctxBytes,
        jbyteArray PKBytes) {
    try {
        ByteVector M = jbyteArrayToByteVector(env, MBytes);
        ByteVector SIG = jbyteArrayToByteVector(env, SIGBytes);
        ByteVector ctx = jbyteArrayToByteVector(env, ctxBytes);
        ByteVector PKData = jbyteArrayToByteVector(env, PKBytes);

        SLH_DSA_PublicKey PK = SLH_DSA_PublicKey::fromBytes(PKData);

        bool result = slh_verify(M, SIG, ctx, PK);
        return static_cast<jboolean>(result);
    } catch (...) {
        handleCppException(env,std::current_exception());
        return JNI_FALSE;
    }
}


// Interfaces internas
extern "C" JNIEXPORT jbyteArray JNICALL
Java_com_revelacion1_tfg_1parte1_FunctionLink_slhInternalSign(
        JNIEnv* env,
        jobject /* this */,
        jbyteArray MArray,
        jbyteArray SKSeed,
        jbyteArray addrndArray) {
    try {
        // Implementación simplificada - en realidad necesitarías una función slh_sign_internal
        ByteVector M = jbyteArrayToByteVector(env, MArray);
        ByteVector S = jbyteArrayToByteVector(env, SKSeed);
        ByteVector addrnd = jbyteArrayToByteVector(env, addrndArray);

        SLH_DSA_PrivateKey SK = SLH_DSA_PrivateKey::fromBytes(S);

        //
        SLH_DSA_Signature signature = slh_sign_internal(M, SK, addrnd);

        // Convertir la firma a ByteVector
        ByteVector signatureBytes = signature.toBytes();

        return byteVectorToJbyteArray(env, signatureBytes);
    } catch (...) {
        handleCppException(env,std::current_exception());
        return nullptr;
    }
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_revelacion1_tfg_1parte1_FunctionLink_slhInternalVerify(
        JNIEnv* env, jobject /* this */,
        jbyteArray MBytes,
        jbyteArray SIGBytes,
        jbyteArray PK) {
    try {
        // Implementación simplificada - en realidad necesitarías una función slh_verify_internal
        ByteVector M = jbyteArrayToByteVector(env, MBytes);
        ByteVector SIG = jbyteArrayToByteVector(env, SIGBytes);
        ByteVector PKData = jbyteArrayToByteVector(env, PK);

        SLH_DSA_PublicKey PK = SLH_DSA_PublicKey::fromBytes(PKData);

        bool result = slh_verify_internal(M, SIG, PK);
        return static_cast<jboolean>(result);
    } catch (...) {
        handleCppException(env,std::current_exception());
        return JNI_FALSE;
    }
}


extern "C" JNIEXPORT jbyteArray JNICALL
Java_com_revelacion1_tfg_1parte1_FunctionLink_hashSlhSign(
        JNIEnv* env, jobject /* this */, jbyteArray MBytes,
        jbyteArray ctxBytes, jbyteArray PHBytes, jbyteArray SKBytes) {
    try {
        // Implementación simplificada - en realidad necesitarías una función hash_slh_sign
        ByteVector M = jbyteArrayToByteVector(env, MBytes);
        ByteVector ctx = jbyteArrayToByteVector(env, ctxBytes);
        ByteVector SKData = jbyteArrayToByteVector(env, SKBytes);

        SLH_DSA_PrivateKey SK = SLH_DSA_PrivateKey::fromBytes(SKData);

        ByteVector signature = slh_sign(M, ctx, SK);
        return byteVectorToJbyteArray(env, signature);
    } catch (...) {
        handleCppException(env,std::current_exception());
        return nullptr;
    }
}


extern "C" JNIEXPORT jboolean JNICALL
Java_com_revelacion1_tfg_1parte1_FunctionLink_hashSlhVerify(
        JNIEnv* env, jobject /* this */, jbyteArray MBytes,
        jbyteArray SIGBytes, jbyteArray ctxBytes, jbyteArray PHBytes,
        jbyteArray PKBytes) {
    try {
        // Implementación simplificada - en realidad necesitarías una función hash_slh_verify
        ByteVector M = jbyteArrayToByteVector(env, MBytes);
        ByteVector SIG = jbyteArrayToByteVector(env, SIGBytes);
        ByteVector ctx = jbyteArrayToByteVector(env, ctxBytes);
        ByteVector PKData = jbyteArrayToByteVector(env, PKBytes);

        SLH_DSA_PublicKey PK = SLH_DSA_PublicKey::fromBytes(PKData);

        bool result = slh_verify(M, SIG, ctx, PK);
        return static_cast<jboolean>(result);
    } catch (...) {
        handleCppException(env,std::current_exception());
        return JNI_FALSE;
    }
}