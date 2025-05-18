cmake_minimum_required(VERSION 3.22.1)
project("TFG_PARTE1")

# Set the path to the prebuilt OpenSSL files
set(OPENSSL_DIR ${CMAKE_CURRENT_SOURCE_DIR}/prebuilt-openssl)

# Instead of creating a separate library, we'll include the shake256 implementation directly
# into the main library as source files
add_library(${CMAKE_PROJECT_NAME} SHARED
        fips205.cpp
        JNI-wrapper.cpp
)  # Include the wrapper directly in the main library

# Include OpenSSL headers
target_include_directories(${CMAKE_PROJECT_NAME} PRIVATE
        ${OPENSSL_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR})

# Link with the appropriate OpenSSL library based on ABI
if(${ANDROID_ABI} STREQUAL "arm64-v8a")
    set(OPENSSL_LIB_DIR ${OPENSSL_DIR}/lib/arm64-v8a)
elseif(${ANDROID_ABI} STREQUAL "armeabi-v7a")
    set(OPENSSL_LIB_DIR ${OPENSSL_DIR}/lib/armeabi-v7a)
elseif(${ANDROID_ABI} STREQUAL "x86")
    set(OPENSSL_LIB_DIR ${OPENSSL_DIR}/lib/x86)
elseif(${ANDROID_ABI} STREQUAL "x86_64")
    set(OPENSSL_LIB_DIR ${OPENSSL_DIR}/lib/x86_64)
else()
    message(FATAL_ERROR "Unsupported ABI: ${ANDROID_ABI}")
endif()

# Link against the appropriate static libraries
target_link_libraries(${CMAKE_PROJECT_NAME}
        ${OPENSSL_LIB_DIR}/libcrypto.a
        android
        log)