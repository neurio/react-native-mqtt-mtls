package com.reactnativemqttmtls;

import android.util.Log;
import androidx.annotation.NonNull;
import com.facebook.react.bridge.Callback;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.ReadableMap;
import com.facebook.react.modules.core.DeviceEventManagerModule;
import info.mqtt.android.service.MqttAndroidClient;
import org.eclipse.paho.client.mqttv3.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.io.*;
import java.net.*;
import java.security.*;
import java.security.cert.*;
import java.util.*;
import javax.net.ssl.*;

public class MqttModule extends ReactContextBaseJavaModule {
    private static final String TAG = "MqttModule";
    private final ReactApplicationContext reactContext;
    private MqttAndroidClient client;

    public MqttModule(ReactApplicationContext reactContext) {
        super(reactContext);
        this.reactContext = reactContext;
        setupBouncyCastle();
    }

    private void setupBouncyCastle() {
        try {
            Security.removeProvider("BC");
            Security.addProvider(new BouncyCastleProvider());
            Log.d(TAG, "✓ BouncyCastle Provider initialized");
        } catch (Exception e) {
            Log.e(TAG, "Failed to register BC provider", e);
        }
    }

    @NonNull
    @Override
    public String getName() {
        return "MqttModule";
    }

    // --- Helper Methods ---
    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }

    private void verifyCertMatchesKey(X509Certificate cert, String privateKeyAlias, KeyStore keyStore)
            throws Exception {
        Log.d(TAG, "→ Verifying certificate matches private key...");

        PublicKey certPublicKey = cert.getPublicKey();

        KeyStore.Entry entry = keyStore.getEntry(privateKeyAlias, null);
        if (!(entry instanceof KeyStore.PrivateKeyEntry)) {
            throw new KeyException("Not a private key entry");
        }

        KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) entry;
        PublicKey keystorePublicKey = privateKeyEntry.getCertificate().getPublicKey();

        byte[] certPubBytes = certPublicKey.getEncoded();
        byte[] keystorePubBytes = keystorePublicKey.getEncoded();

        Log.d(TAG, "Cert public key (first 32 bytes): "
                + bytesToHex(Arrays.copyOf(certPubBytes, Math.min(32, certPubBytes.length))));
        Log.d(TAG, "Keystore public key (first 32 bytes): "
                + bytesToHex(Arrays.copyOf(keystorePubBytes, Math.min(32, keystorePubBytes.length))));

        if (!Arrays.equals(certPubBytes, keystorePubBytes)) {
            Log.e(TAG, "❌ CERTIFICATE PUBLIC KEY DOES NOT MATCH PRIVATE KEY!");
            throw new KeyException("Certificate does not match the private key in keystore!");
        }

        Log.d(TAG, "✅ Certificate public key MATCHES private key");
    }

    // --- Custom Socket Factory ---
    private static class SniSocketFactory extends SSLSocketFactory {
        private final SSLSocketFactory delegate;
        private final String sniHost;

        public SniSocketFactory(SSLSocketFactory delegate, String sniHost) {
            this.delegate = delegate;
            this.sniHost = sniHost;
            Log.d(TAG, "▶▶▶ SniSocketFactory CONSTRUCTOR - SNI: " + sniHost);
        }

        @Override
        public Socket createSocket(Socket s, String h, int p, boolean a) throws IOException {
            Log.d(TAG, "▶▶▶ createSocket(Socket, String, int, boolean) CALLED");
            Log.d(TAG, "  Host: " + h + ", Port: " + p + ", SNI: " + sniHost);

            String effectiveHost = (sniHost != null && !sniHost.isEmpty()) ? sniHost : h;
            SSLSocket ssl = (SSLSocket) delegate.createSocket(s, effectiveHost, p, a);

            if (sniHost != null && !sniHost.isEmpty()) {
                SSLParameters params = ssl.getSSLParameters();
                params.setServerNames(Collections.singletonList(new SNIHostName(sniHost)));
                ssl.setSSLParameters(params);
                Log.d(TAG, "  ✓ SNI set to: " + sniHost);
            }

            return ssl;
        }

        @Override
        public Socket createSocket() throws IOException {
            Log.d(TAG, "▶▶▶ createSocket() CALLED");
            return delegate.createSocket();
        }

        @Override
        public Socket createSocket(String h, int p) throws IOException {
            return delegate.createSocket(h, p);
        }

        @Override
        public Socket createSocket(String h, int p, InetAddress l, int lp) throws IOException {
            return delegate.createSocket(h, p, l, lp);
        }

        @Override
        public Socket createSocket(InetAddress a, int p) throws IOException {
            return delegate.createSocket(a, p);
        }

        @Override
        public Socket createSocket(InetAddress a, int p, InetAddress l, int lp) throws IOException {
            return delegate.createSocket(a, p, l, lp);
        }

        @Override
        public String[] getDefaultCipherSuites() {
            return delegate.getDefaultCipherSuites();
        }

        @Override
        public String[] getSupportedCipherSuites() {
            return delegate.getSupportedCipherSuites();
        }
    }

    // --- Main Connect Method ---
    @ReactMethod
    public void connect(
            String brokerUrl,
            String clientId,
            ReadableMap certificates,
            String sniHost,
            String brokerIp,
            final Callback success,
            final Callback error) {
        try {
            String privateKeyAlias = certificates.hasKey("privateKeyAlias")
                    ? certificates.getString("privateKeyAlias")
                    : null;

            if (privateKeyAlias == null || privateKeyAlias.isEmpty()) {
                throw new IllegalArgumentException("privateKeyAlias required");
            }

            Log.i(TAG, "========================================");
            Log.i(TAG, "MQTT Connection Attempt");
            Log.i(TAG, "Broker: " + brokerUrl);
            Log.i(TAG, "Client ID: " + clientId);
            Log.i(TAG, "Key Alias: " + privateKeyAlias);
            Log.i(TAG, "========================================");

            client = new MqttAndroidClient(
                    getReactApplicationContext(),
                    brokerUrl,
                    clientId);

            MqttConnectOptions options = new MqttConnectOptions();
            options.setCleanSession(true);
            options.setConnectionTimeout(30);
            options.setKeepAliveInterval(60);
            options.setAutomaticReconnect(true);

            SSLContext sslContext = createSSLContextFromKeystore(
                    certificates.getString("clientCert"),
                    certificates.getString("rootCa"),
                    privateKeyAlias);

            SSLSocketFactory socketFactory;
            if (sniHost != null && !sniHost.isEmpty()) {
                socketFactory = new SniSocketFactory(sslContext.getSocketFactory(), sniHost);
                Log.d(TAG, "✓ Created SniSocketFactory");
            } else {
                socketFactory = sslContext.getSocketFactory();
                Log.d(TAG, "✓ Using default factory (no SNI)");
            }

            options.setSocketFactory(socketFactory);

            // Set up callbacks
            client.setCallback(new MqttCallbackExtended() {
                @Override
                public void connectComplete(boolean reconnect, String serverURI) {
                    Log.i(TAG, "✅ MQTT Connection Complete - " + serverURI);
                    sendEvent("MqttConnected", "Connected to broker: " + serverURI);
                }

                @Override
                public void connectionLost(Throwable cause) {
                    Log.e(TAG, "❌ MQTT Connection Lost: " + (cause != null ? cause.getMessage() : "Unknown"));
                    sendEvent("MqttDisconnected", "Connection lost");
                }

                @Override
                public void messageArrived(String topic, MqttMessage message) {
                    String payload = new String(message.getPayload());
                    Log.d(TAG, "📨 Message received on topic: " + topic);
                    String eventData = "{\"topic\":\"" + topic + "\",\"message\":\"" + payload + "\"}";
                    sendEvent("MqttMessage", eventData);
                }

                @Override
                public void deliveryComplete(IMqttDeliveryToken token) {
                    Log.d(TAG, "✓ Message delivery complete");
                    sendEvent("MqttDeliveryComplete", "Message delivered");
                }
            });

            client.connect(options, null, new IMqttActionListener() {
                @Override
                public void onSuccess(IMqttToken asyncActionToken) {
                    Log.i(TAG, "✅✅✅ SUCCESS! MQTT CONNECTED! ✅✅✅");
                    if (success != null)
                        success.invoke("Connected");
                }

                @Override
                public void onFailure(IMqttToken asyncActionToken, Throwable exception) {
                    Log.e(TAG, "❌ MQTT Connection FAILED");
                    if (exception != null) {
                        Log.e(TAG, "Error: " + exception.getMessage());
                        exception.printStackTrace();
                    }
                    if (error != null)
                        error.invoke(exception != null ? exception.getMessage() : "Unknown");
                }
            });
        } catch (Exception e) {
            Log.e(TAG, "❌ Setup Error", e);
            if (error != null)
                error.invoke(e.getMessage());
        }
    }

    private SSLContext createSSLContextFromKeystore(
            String clientPem,
            String rootPem,
            String privateKeyAlias) throws Exception {
        Log.d(TAG, "→ Creating SSLContext for: " + privateKeyAlias);

        KeyStore androidKeyStore = KeyStore.getInstance("AndroidKeyStore");
        androidKeyStore.load(null);

        if (!androidKeyStore.containsAlias(privateKeyAlias)) {
            throw new KeyException("Key not found: " + privateKeyAlias);
        }
        Log.d(TAG, "✓ Key found in keystore");

        CertificateFactory cf = CertificateFactory.getInstance("X.509");

        // Load client certificate CHAIN (multiple certificates)
        Collection<? extends java.security.cert.Certificate> clientCertChain = cf.generateCertificates(
                new ByteArrayInputStream(clientPem.getBytes()));
        Log.d(TAG, "✓ Loaded " + clientCertChain.size() + " client certificate(s)");

        X509Certificate[] clientCertArray = clientCertChain.toArray(new X509Certificate[0]);

        for (int i = 0; i < clientCertArray.length; i++) {
            Log.d(TAG, "  Client[" + i + "]: " + clientCertArray[i].getSubjectDN());
        }

        X509Certificate clientCert = clientCertArray[0];

        // Load ALL CA certificates
        Collection<? extends java.security.cert.Certificate> caCerts = cf.generateCertificates(
                new ByteArrayInputStream(rootPem.getBytes()));
        Log.d(TAG, "✓ Loaded " + caCerts.size() + " CA certificate(s)");

        int certNum = 0;
        for (java.security.cert.Certificate cert : caCerts) {
            X509Certificate x509 = (X509Certificate) cert;
            Log.d(TAG, "  CA[" + certNum + "]: " + x509.getSubjectDN());
            certNum++;
        }

        // Verify certificate matches private key
        verifyCertMatchesKey(clientCert, privateKeyAlias, androidKeyStore);

        // Build certificate chain for KeyManager (exclude self-signed root CAs)
        ArrayList<java.security.cert.Certificate> certChainList = new ArrayList<>();
        for (X509Certificate cert : clientCertArray) {
            boolean isSelfSigned = cert.getIssuerDN().equals(cert.getSubjectDN());
            if (!isSelfSigned) {
                certChainList.add(cert);
            }
        }
        java.security.cert.Certificate[] certChain = certChainList.toArray(new java.security.cert.Certificate[0]);

        // Create KeyStore with hardware-backed private key
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null, null);
        
        PrivateKey privateKey = (PrivateKey) androidKeyStore.getKey(privateKeyAlias, null);
        keyStore.setKeyEntry("client-key", privateKey, "".toCharArray(), certChain);
        Log.d(TAG, "✓ Hardware-backed private key added to KeyStore");

        // Initialize KeyManagerFactory
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keyStore, "".toCharArray());
        Log.d(TAG, "✓ KeyManager configured with " + certChain.length + " cert(s) in chain");

        // Add ALL CA certificates to trust store
        KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
        trustStore.load(null, null);

        int i = 0;
        for (java.security.cert.Certificate cert : caCerts) {
            X509Certificate x509 = (X509Certificate) cert;
            trustStore.setCertificateEntry("ca-cert-" + i, x509);
            i++;
        }

        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustStore);
        Log.d(TAG, "✓ TrustManager configured with " + i + " CA cert(s)");

        SSLContext sc = SSLContext.getInstance("TLS");
        sc.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());

        Log.d(TAG, "✅ SSLContext created successfully");
        return sc;
    }

    @ReactMethod
    public void subscribe(String topic, int qos, Callback successCallback, Callback errorCallback) {
        try {
            Log.d(TAG, "📥 Subscribing to topic: " + topic + " with QoS " + qos);

            if (client == null || !client.isConnected()) {
                throw new MqttException(MqttException.REASON_CODE_CLIENT_NOT_CONNECTED);
            }

            client.subscribe(topic, qos, null, new IMqttActionListener() {
                @Override
                public void onSuccess(IMqttToken asyncActionToken) {
                    Log.i(TAG, "✓ Successfully subscribed to: " + topic);
                    successCallback.invoke("Subscribed to " + topic);
                }

                @Override
                public void onFailure(IMqttToken asyncActionToken, Throwable exception) {
                    Log.e(TAG, "❌ Subscribe failed: " + exception.getMessage());
                    errorCallback.invoke("Subscribe failed: " + exception.getMessage());
                }
            });

        } catch (Exception e) {
            Log.e(TAG, "❌ Subscribe failed: " + e.getMessage());
            errorCallback.invoke("Subscribe failed: " + e.getMessage());
        }
    }

    @ReactMethod
    public void unsubscribe(String topic, Callback successCallback, Callback errorCallback) {
        try {
            Log.d(TAG, "📤 Unsubscribing from topic: " + topic);

            if (client == null || !client.isConnected()) {
                throw new MqttException(MqttException.REASON_CODE_CLIENT_NOT_CONNECTED);
            }

            client.unsubscribe(topic, null, new IMqttActionListener() {
                @Override
                public void onSuccess(IMqttToken asyncActionToken) {
                    Log.i(TAG, "✓ Successfully unsubscribed from: " + topic);
                    successCallback.invoke("Unsubscribed from " + topic);
                }

                @Override
                public void onFailure(IMqttToken asyncActionToken, Throwable exception) {
                    Log.e(TAG, "❌ Unsubscribe failed: " + exception.getMessage());
                    errorCallback.invoke("Unsubscribe failed: " + exception.getMessage());
                }
            });

        } catch (Exception e) {
            Log.e(TAG, "❌ Unsubscribe failed: " + e.getMessage());
            errorCallback.invoke("Unsubscribe failed: " + e.getMessage());
        }
    }

    @ReactMethod
    public void publish(String topic, String message, int qos, boolean retained, Callback successCallback,
            Callback errorCallback) {
        try {
            Log.d(TAG, "📤 Publishing to topic: " + topic);

            if (client == null || !client.isConnected()) {
                throw new MqttException(MqttException.REASON_CODE_CLIENT_NOT_CONNECTED);
            }

            MqttMessage mqttMessage = new MqttMessage(message.getBytes());
            mqttMessage.setQos(qos);
            mqttMessage.setRetained(retained);

            client.publish(topic, mqttMessage, null, new IMqttActionListener() {
                @Override
                public void onSuccess(IMqttToken asyncActionToken) {
                    Log.i(TAG, "✓ Message published successfully");
                    successCallback.invoke("Published to " + topic);
                }

                @Override
                public void onFailure(IMqttToken asyncActionToken, Throwable exception) {
                    Log.e(TAG, "❌ Publish failed: " + exception.getMessage());
                    errorCallback.invoke("Publish failed: " + exception.getMessage());
                }
            });

        } catch (Exception e) {
            Log.e(TAG, "❌ Publish failed: " + e.getMessage());
            errorCallback.invoke("Publish failed: " + e.getMessage());
        }
    }

    @ReactMethod
    public void disconnect(Callback successCallback, Callback errorCallback) {
        try {
            Log.d(TAG, "🔌 Disconnecting from MQTT broker...");

            if (client == null) {
                Log.w(TAG, "⚠️ No client to disconnect");
                successCallback.invoke("No active connection");
                return;
            }

            if (client.isConnected()) {
                client.disconnect(null, new IMqttActionListener() {
                    @Override
                    public void onSuccess(IMqttToken asyncActionToken) {
                        Log.i(TAG, "✓ Disconnected from broker");
                        try {
                            client.close();
                            client = null;
                            successCallback.invoke("Disconnected successfully");
                        } catch (Exception e) {
                            errorCallback.invoke("Disconnect error: " + e.getMessage());
                        }
                    }

                    @Override
                    public void onFailure(IMqttToken asyncActionToken, Throwable exception) {
                        Log.e(TAG, "❌ Disconnect failed: " + exception.getMessage());
                        errorCallback.invoke("Disconnect failed: " + exception.getMessage());
                    }
                });
            } else {
                client.close();
                client = null;
                successCallback.invoke("Disconnected successfully");
            }

        } catch (Exception e) {
            Log.e(TAG, "❌ Disconnect failed: " + e.getMessage());
            errorCallback.invoke("Disconnect failed: " + e.getMessage());
        }
    }

    @ReactMethod
    public void isConnected(Callback callback) {
        boolean connected = (client != null && client.isConnected());
        callback.invoke(connected);
    }

    // --- Diagnostic Methods ---
    @ReactMethod
    public void diagnoseKeyPurposes(String privateKeyAlias, Callback callback) {
        try {
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);

            if (!keyStore.containsAlias(privateKeyAlias)) {
                callback.invoke("ERROR: Key not found: " + privateKeyAlias);
                return;
            }

            KeyStore.Entry entry = keyStore.getEntry(privateKeyAlias, null);
            if (!(entry instanceof KeyStore.PrivateKeyEntry)) {
                callback.invoke("ERROR: Not a private key entry");
                return;
            }

            KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) entry;
            PrivateKey privateKey = privateKeyEntry.getPrivateKey();

            StringBuilder result = new StringBuilder();
            result.append("=== Key Purposes for: ").append(privateKeyAlias).append(" ===\n\n");

            try {
                KeyFactory factory = KeyFactory.getInstance(
                        privateKey.getAlgorithm(),
                        "AndroidKeyStore");
                android.security.keystore.KeyInfo keyInfo = factory.getKeySpec(
                        privateKey,
                        android.security.keystore.KeyInfo.class);

                int purposes = keyInfo.getPurposes();
                result.append("Raw purposes value: ").append(purposes).append("\n\n");

                boolean hasSign = (purposes & android.security.keystore.KeyProperties.PURPOSE_SIGN) != 0;
                boolean hasVerify = (purposes & android.security.keystore.KeyProperties.PURPOSE_VERIFY) != 0;
                boolean hasAgreeKey = (purposes & android.security.keystore.KeyProperties.PURPOSE_AGREE_KEY) != 0;

                result.append("Key Purposes:\n");
                result.append("  SIGN: ").append(hasSign ? "✓ YES" : "✗ NO").append("\n");
                result.append("  VERIFY: ").append(hasVerify ? "✓ YES" : "✗ NO").append("\n");
                result.append("  AGREE_KEY: ").append(hasAgreeKey ? "✓ YES" : "✗ NO").append("\n\n");

                if (!hasAgreeKey) {
                    result.append("❌ PROBLEM: Missing PURPOSE_AGREE_KEY!\n");
                } else {
                    result.append("✅ Key has all required purposes for TLS!\n");
                }

                result.append("\nKey Size: ").append(keyInfo.getKeySize()).append(" bits\n");
                result.append("Hardware-backed: ").append(keyInfo.isInsideSecureHardware()).append("\n");

            } catch (Exception e) {
                result.append("ERROR: ").append(e.getMessage()).append("\n");
            }

            callback.invoke(result.toString());

        } catch (Exception e) {
            callback.invoke("ERROR: " + e.getMessage());
        }
    }

    @ReactMethod
    public void checkKeyExists(String privateKeyAlias, Callback callback) {
        try {
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);
            boolean exists = keyStore.containsAlias(privateKeyAlias);
            callback.invoke(exists);
        } catch (Exception e) {
            callback.invoke(false);
        }
    }

    @ReactMethod
    public void listKeyAliases(Callback callback) {
        try {
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);
            Enumeration<String> aliases = keyStore.aliases();
            StringBuilder sb = new StringBuilder("Available aliases:\n");
            while (aliases.hasMoreElements()) {
                sb.append("- ").append(aliases.nextElement()).append("\n");
            }
            callback.invoke(sb.toString());
        } catch (Exception e) {
            callback.invoke("Error: " + e.getMessage());
        }
    }

    private void sendEvent(String eventName, String message) {
        reactContext
                .getJSModule(DeviceEventManagerModule.RCTDeviceEventEmitter.class)
                .emit(eventName, message);
    }
}
