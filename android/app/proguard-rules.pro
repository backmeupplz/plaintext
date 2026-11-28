# UniFFI's generated bindings reach Rust through JNA, which looks classes and fields up by name.
-keep class com.sun.jna.** { *; }
-keep class * extends com.sun.jna.** { *; }
-keep class uniffi.plaintext_ffi.** { *; }
-dontwarn java.awt.**
# No logging in release builds.
-assumenosideeffects class android.util.Log {
    public static int v(...);
    public static int d(...);
    public static int i(...);
    public static int w(...);
    public static int e(...);
}
