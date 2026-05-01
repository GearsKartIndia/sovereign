# Sovereign proguard rules

# Keep the JS bridge class intact — its methods are called reflectively from WebView
-keep class com.copps.sovereign.MainActivity$SovereignBridge { *; }
-keepclassmembers class com.copps.sovereign.MainActivity$SovereignBridge {
    @android.webkit.JavascriptInterface <methods>;
}

# Biometric
-keep class androidx.biometric.** { *; }

# Security crypto
-keep class androidx.security.crypto.** { *; }
