# R8 rules for the release build.
#
# Two goals: strip the debug logging that used to ship in release APKs (audit
# A-3's second half), and shrink/obfuscate without breaking the things in this
# app that are resolved by *name* at runtime rather than by reference.

# ── JNI ──────────────────────────────────────────────────────────────────────
# The Rust bridge exports symbols named after the class and method:
# `Java_com_vela_android_core_NativeVelaCore_nativeIdentitySignJson`. Renaming
# either side breaks resolution at first call — at runtime, in release only.
-keepclasseswithmembernames,includedescriptorclasses class * {
    native <methods>;
}
-keep class com.vela.android.core.NativeVelaCore { *; }

# ── Crash triage ─────────────────────────────────────────────────────────────
# Keep stack traces readable. `SourceFile` is renamed so it leaks nothing while
# line numbers still map through the retrace mapping file.
-keepattributes SourceFile,LineNumberTable
-renamesourcefileattribute SourceFile

# ── Debug logging ────────────────────────────────────────────────────────────
# The actual fix for "Log.d metadata ships in release": R8 removes these calls
# and, with them, the string constants they were built from. Warnings and errors
# stay — they are what a bug report needs.
-assumenosideeffects class android.util.Log {
    public static int v(...);
    public static int d(...);
}
