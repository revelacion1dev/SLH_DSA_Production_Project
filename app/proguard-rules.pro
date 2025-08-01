# Add project specific ProGuard rules here.
# You can control the set of applied configuration files using the
# proguardFiles setting in build.gradle.
#
# For more details, see
#   http://developer.android.com/guide/developing/tools/proguard.html

# If your project uses WebView with JS, uncomment the following
# and specify the fully qualified class name to the JavaScript interface
# class:
#-keepclassmembers class fqcn.of.javascript.interface.for.webview {
#   public *;
#}

# Uncomment this to preserve the line number information for
# debugging stack traces.
#-keepattributes SourceFile,LineNumberTable

# If you keep the line number information, uncomment this to
# hide the original source file name.
#-renamesourcefileattribute SourceFile

# Reglas ProGuard para reducir tamaño de APK

# Mantener clases de la aplicación principal
-keep class com.revelacion1.tfg_parte1.** { *; }

# Mantener funciones nativas JNI
-keepclasseswithmembernames class * {
    native <methods>;
}

# Mantener clases con métodos main
-keepclasseswithmembers public class * {
    public static void main(java.lang.String[]);
}

# Optimizaciones adicionales
-optimizations !code/simplification/arithmetic,!code/simplification/cast,!field/*,!class/merging/*
-optimizationpasses 5
-allowaccessmodification
-dontpreverify

# Eliminar logs en release
-assumenosideeffects class android.util.Log {
    public static boolean isLoggable(java.lang.String, int);
    public static int v(...);
    public static int i(...);
    public static int w(...);
    public static int d(...);
    public static int e(...);
}

# Mantener anotaciones
-keepattributes *Annotation*

# Mantener números de línea para stack traces
-keepattributes SourceFile,LineNumberTable

# Kotlin específico
-keep class kotlin.** { *; }
-keep class kotlinx.** { *; }

# Mantener clases de serialización si las usas
-keepattributes Signature
-keepattributes *Annotation*

# Para debugging - remover en release final
-printmapping mapping.txt
-verbose