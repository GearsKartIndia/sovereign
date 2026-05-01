package com.copps.sovereign;

import android.annotation.SuppressLint;
import android.content.Context;
import android.os.Bundle;
import android.webkit.JavascriptInterface;
import android.webkit.WebResourceRequest;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;
import androidx.biometric.BiometricManager;
import androidx.biometric.BiometricPrompt;
import androidx.core.content.ContextCompat;
import androidx.security.crypto.EncryptedSharedPreferences;
import androidx.security.crypto.MasterKey;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.concurrent.Executor;

public class MainActivity extends AppCompatActivity {

    private WebView webView;
    private BiometricPrompt biometricPrompt;

    @SuppressLint({"SetJavaScriptEnabled", "AddJavascriptInterface"})
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        webView = findViewById(R.id.webview);
        setupWebView();
        setupBiometricPrompt();

        // Load the Sovereign web app (bundled in assets)
        webView.loadUrl("file:///android_asset/www/index.html");
    }

    @SuppressLint("SetJavaScriptEnabled")
    private void setupWebView() {
        WebSettings settings = webView.getSettings();

        // Required for the app to function
        settings.setJavaScriptEnabled(true);
        settings.setDomStorageEnabled(true);        // localStorage
        settings.setDatabaseEnabled(true);
        settings.setAllowFileAccessFromFileURLs(true);
        settings.setAllowUniversalAccessFromFileURLs(true);

        // Security
        settings.setAllowFileAccess(false);         // block file:// from web content
        settings.setGeolocationEnabled(false);
        settings.setSavePassword(false);
        settings.setSaveFormData(false);

        // Performance
        settings.setCacheMode(WebSettings.LOAD_DEFAULT);
        settings.setMediaPlaybackRequiresUserGesture(true);

        // Android-native bridge for biometrics and secure storage
        webView.addJavascriptInterface(new SovereignBridge(this), "SovereignAndroid");

        webView.setWebViewClient(new WebViewClient() {
            @Override
            public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) {
                // Keep all navigation inside the WebView
                return false;
            }
        });

        // Enable WebView debugging in debug builds
        if (BuildConfig.DEBUG) {
            WebView.setWebContentsDebuggingEnabled(true);
        }
    }

    private void setupBiometricPrompt() {
        Executor executor = ContextCompat.getMainExecutor(this);
        biometricPrompt = new BiometricPrompt(this, executor,
            new BiometricPrompt.AuthenticationCallback() {
                @Override
                public void onAuthenticationSucceeded(BiometricPrompt.AuthenticationResult result) {
                    super.onAuthenticationSucceeded(result);
                    // Notify the web layer
                    webView.post(() ->
                        webView.evaluateJavascript("window.onBiometricResult(true)", null)
                    );
                }

                @Override
                public void onAuthenticationError(int errorCode, CharSequence errString) {
                    super.onAuthenticationError(errorCode, errString);
                    webView.post(() ->
                        webView.evaluateJavascript("window.onBiometricResult(false)", null)
                    );
                }

                @Override
                public void onAuthenticationFailed() {
                    super.onAuthenticationFailed();
                    // Keep the prompt open on failure — Android handles retry
                }
            });
    }

    /**
     * JavaScript bridge — called from JS via SovereignAndroid.methodName()
     */
    public class SovereignBridge {
        private final Context context;

        SovereignBridge(Context ctx) { this.context = ctx; }

        /** Trigger native biometric prompt */
        @JavascriptInterface
        public void authenticate(String title, String subtitle) {
            BiometricPrompt.PromptInfo promptInfo = new BiometricPrompt.PromptInfo.Builder()
                .setTitle(title != null ? title : "Sovereign")
                .setSubtitle(subtitle != null ? subtitle : "Verify your identity")
                .setNegativeButtonText("Use password instead")
                .setAllowedAuthenticators(
                    BiometricManager.Authenticators.BIOMETRIC_STRONG |
                    BiometricManager.Authenticators.BIOMETRIC_WEAK
                )
                .build();
            runOnUiThread(() -> biometricPrompt.authenticate(promptInfo));
        }

        /** Check if biometric hardware + enrollment is available */
        @JavascriptInterface
        public boolean isBiometricAvailable() {
            BiometricManager bm = BiometricManager.from(context);
            int result = bm.canAuthenticate(
                BiometricManager.Authenticators.BIOMETRIC_STRONG |
                BiometricManager.Authenticators.BIOMETRIC_WEAK
            );
            return result == BiometricManager.BIOMETRIC_SUCCESS;
        }

        /**
         * Store a string securely in Android Keystore-backed EncryptedSharedPreferences.
         * The key material never leaves the secure element.
         */
        @JavascriptInterface
        public void secureStore(String key, String value) {
            try {
                getEncryptedPrefs().edit().putString(key, value).apply();
            } catch (Exception e) {
                runOnUiThread(() ->
                    Toast.makeText(context, "Secure storage error", Toast.LENGTH_SHORT).show()
                );
            }
        }

        /** Retrieve a value from Keystore-backed storage */
        @JavascriptInterface
        public String secureGet(String key) {
            try {
                return getEncryptedPrefs().getString(key, null);
            } catch (Exception e) {
                return null;
            }
        }

        /** Remove a key from secure storage */
        @JavascriptInterface
        public void secureDelete(String key) {
            try {
                getEncryptedPrefs().edit().remove(key).apply();
            } catch (Exception ignored) {}
        }

        private androidx.security.crypto.EncryptedSharedPreferences getEncryptedPrefs()
                throws GeneralSecurityException, IOException {
            MasterKey masterKey = new MasterKey.Builder(context)
                .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                .build();
            return (EncryptedSharedPreferences) EncryptedSharedPreferences.create(
                context,
                "sovereign_secure_prefs",
                masterKey,
                EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
            );
        }
    }

    @Override
    public void onBackPressed() {
        if (webView.canGoBack()) webView.goBack();
        else super.onBackPressed();
    }

    @Override
    protected void onPause() {
        super.onPause();
        // Pause WebView when app is backgrounded
        webView.onPause();
    }

    @Override
    protected void onResume() {
        super.onResume();
        webView.onResume();
    }
}
