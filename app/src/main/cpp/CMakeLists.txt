
cmake_minimum_required(VERSION 3.22.1)
project("TFG_PARTE1")


add_library(${CMAKE_PROJECT_NAME} SHARED
        fips205.cpp
        JNI-wrapper.cpp)

target_include_directories(${CMAKE_PROJECT_NAME}
        PRIVATE
        src/main/cpp)

target_link_libraries(${CMAKE_PROJECT_NAME}
        android
        log)
