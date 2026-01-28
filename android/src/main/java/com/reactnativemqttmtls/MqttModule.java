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
import java.net.Socket;
import java.security.*;
import java.security.cert.*;
import java.util.*;
import javax.net.ssl.*;

public class MqttModule extends ReactContextBaseJavaModule {
    private static final String TAG = "MqttModule";
    private static final String SOFTWARE_KEYSTORE_FILE = "software_keys.p12";
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
            Log.d(TAG, "BouncyCastle provider initialized");
        } catch (Exception e) {
            Log.e(TAG, "Failed to register BouncyCastle provider", e);
        }
    }

    @NonNull
    @Override
    public String getName() {
        return "MqttModule";
    }

    // ============================================================================
    // CUSTOM TRUSTMANAGER - Server certificate validation
    // ============================================================================
    
    private static class CustomTrustManager implements X509TrustManager {
        private final X509Certificate[] acceptedIssuers;
        
        public CustomTrustManager(KeyStore trustStore) throws Exception {
            List<X509Certificate> certs = new ArrayList<>();
            Enumeration<String> aliases = trustStore.aliases();
            
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                java.security.cert.Certificate cert = trustStore.getCertificate(alias);
                if (cert instanceof X509Certificate) {
                    certs.add((X509Certificate) cert);
                }
            }
            
            this.acceptedIssuers = certs.toArray(new X509Certificate[0]);
            Log.d(TAG, "CustomTrustManager initialized with " + acceptedIssuers.length + " CA(s)");
        }
        
        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) {
            // Not needed for client
        }
        
        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            if (chain == null || chain.length == 0) {
                throw new CertificateException("Server certificate chain is empty");
            }
            
            X509Certificate serverCert = chain[0];
            boolean validated = false;
            
            // Try direct validation (server cert signed by one of our CAs)
            for (X509Certificate ca : acceptedIssuers) {
                try {
                    serverCert.verify(ca.getPublicKey());
                    validated = true;
                    Log.d(TAG, "Server certificate validated by: " + ca.getSubjectDN());
                    break;
                } catch (Exception e) {
                    // Try next CA
                }
            }
            
            // Try validation via intermediate certificates
            if (!validated && chain.length > 1) {
                for (int i = 1; i < chain.length; i++) {
                    X509Certificate intermediate = chain[i];
                    for (X509Certificate ca : acceptedIssuers) {
                        try {
                            intermediate.verify(ca.getPublicKey());
                            serverCert.verify(intermediate.getPublicKey());
                            validated = true;
                            Log.d(TAG, "Server certificate validated via intermediate");
                            break;
                        } catch (Exception e) {
                            // Try next
                        }
                    }
                    if (validated) break;
                }
            }
            
            // Check if intermediate IS a trusted CA
            if (!validated && chain.length > 1) {
                for (int i = 1; i < chain.length; i++) {
                    X509Certificate intermediate = chain[i];
                    for (X509Certificate ca : acceptedIssuers) {
                        if (intermediate.getSubjectDN().equals(ca.getSubjectDN())) {
                            try {
                                byte[] intermediatePubKey = intermediate.getPublicKey().getEncoded();
                                byte[] caPubKey = ca.getPublicKey().getEncoded();
                                
                                if (Arrays.equals(intermediatePubKey, caPubKey)) {
                                    serverCert.verify(intermediate.getPublicKey());
                                    validated = true;
                                    Log.d(TAG, "Server certificate validated by trusted intermediate");
                                    break;
                                }
                            } catch (Exception e) {
                                // Try next
                            }
                        }
                    }
                    if (validated) break;
                }
            }
            
            if (!validated) {
                Log.e(TAG, "Server certificate validation failed - not trusted by any CA");
                throw new CertificateException("Server certificate not trusted by any configured CA");
            }
        }
        
        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return acceptedIssuers;
        }
    }

    // ============================================================================
    // CUSTOM KEYMANAGER - Client certificate presentation
    // ============================================================================
    
    private static class CustomKeyManager extends X509ExtendedKeyManager {
        private final String alias;
        private final X509Certificate[] certChain;
        private final PrivateKey privateKey;
        
        public CustomKeyManager(String alias, X509Certificate[] certChain, PrivateKey privateKey) {
            this.alias = alias;
            this.certChain = certChain;
            this.privateKey = privateKey;
            Log.d(TAG, "CustomKeyManager initialized (alias: " + alias + ", chain: " + certChain.length + " certs)");
        }
        
        @Override
        public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
            return alias;
        }
        
        @Override
        public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
            return null;
        }
        
        @Override
        public X509Certificate[] getCertificateChain(String alias) {
            return this.alias.equals(alias) ? certChain : null;
        }
        
        @Override
        public String[] getClientAliases(String keyType, Principal[] issuers) {
            return new String[] { alias };
        }
        
        @Override
        public String[] getServerAliases(String keyType, Principal[] issuers) {
            return null;
        }
        
        @Override
        public PrivateKey getPrivateKey(String alias) {
            return this.alias.equals(alias) ? privateKey : null;
        }
    }

    // ============================================================================
    // MAIN CONNECT METHOD
    // ============================================================================
    
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
            
            // Default to SOFTWARE keys (hardware keys don't work reliably for TLS)
            boolean useHardwareKey = certificates.hasKey("useHardwareKey") 
                    ? certificates.getBoolean("useHardwareKey") 
                    : false;

            if (privateKeyAlias == null || privateKeyAlias.isEmpty()) {
                throw new IllegalArgumentException("privateKeyAlias required");
            }

            Log.i(TAG, "MQTT connection to " + brokerUrl + " (client: " + clientId + ")");
            Log.i(TAG, "Key: " + privateKeyAlias + " (" + (useHardwareKey ? "hardware" : "software") + ")");

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
                    privateKeyAlias,
                    useHardwareKey);

            options.setSocketFactory(sslContext.getSocketFactory());

            client.setCallback(new MqttCallbackExtended() {
                @Override
                public void connectComplete(boolean reconnect, String serverURI) {
                    Log.i(TAG, "MQTT connected to " + serverURI);
                    sendEvent("MqttConnected", "Connected to broker: " + serverURI);
                }

                @Override
                public void connectionLost(Throwable cause) {
                    Log.w(TAG, "MQTT connection lost: " + (cause != null ? cause.getMessage() : "Unknown"));
                    sendEvent("MqttDisconnected", "Connection lost");
                }

                @Override
                public void messageArrived(String topic, MqttMessage message) {
                    String payload = new String(message.getPayload());
                    String eventData = "{\"topic\":\"" + topic + "\",\"message\":\"" + payload + "\"}";
                    sendEvent("MqttMessage", eventData);
                }

                @Override
                public void deliveryComplete(IMqttDeliveryToken token) {
                    sendEvent("MqttDeliveryComplete", "Message delivered");
                }
            });

            client.connect(options, null, new IMqttActionListener() {
                @Override
                public void onSuccess(IMqttToken asyncActionToken) {
                    Log.i(TAG, "MQTT connection successful");
                    if (success != null) success.invoke("Connected");
                }

                @Override
                public void onFailure(IMqttToken asyncActionToken, Throwable exception) {
                    Log.e(TAG, "MQTT connection failed: " + (exception != null ? exception.getMessage() : "Unknown"));
                    if (exception != null) exception.printStackTrace();
                    if (error != null) error.invoke(exception != null ? exception.getMessage() : "Unknown");
                }
            });
        } catch (Exception e) {
            Log.e(TAG, "MQTT setup error", e);
            if (error != null) error.invoke(e.getMessage());
        }
    }

    // ============================================================================
    // SSL CONTEXT CREATION
    // ============================================================================
    
    private SSLContext createSSLContextFromKeystore(
            String clientPem,
            String rootPem,
            String privateKeyAlias,
            boolean useHardwareKey) throws Exception {
        
        Log.d(TAG, "Creating SSL context (" + (useHardwareKey ? "hardware" : "software") + " key)");

        CertificateFactory cf = CertificateFactory.getInstance("X.509");

        // Load client certificate chain
        Collection<? extends java.security.cert.Certificate> clientCertChain = cf.generateCertificates(
                new ByteArrayInputStream(clientPem.getBytes()));
        X509Certificate[] clientCertArray = clientCertChain.toArray(new X509Certificate[0]);
        X509Certificate clientCert = clientCertArray[0];

        // Load CA certificates
        Collection<? extends java.security.cert.Certificate> caCerts = cf.generateCertificates(
                new ByteArrayInputStream(rootPem.getBytes()));

        // Build certificate chain (exclude self-signed roots)
        ArrayList<X509Certificate> certChainList = new ArrayList<>();
        for (X509Certificate cert : clientCertArray) {
            if (!cert.getIssuerDN().equals(cert.getSubjectDN())) {
                certChainList.add(cert);
            }
        }
        X509Certificate[] certChain = certChainList.toArray(new X509Certificate[0]);

        // Load private key
        PrivateKey privateKey;
        PublicKey publicKey;
        
        if (useHardwareKey) {
            KeyStore androidKeyStore = KeyStore.getInstance("AndroidKeyStore");
            androidKeyStore.load(null);
            
            if (!androidKeyStore.containsAlias(privateKeyAlias)) {
                throw new KeyException("Hardware key not found: " + privateKeyAlias);
            }
            
            KeyStore.Entry entry = androidKeyStore.getEntry(privateKeyAlias, null);
            if (!(entry instanceof KeyStore.PrivateKeyEntry)) {
                throw new KeyException("Not a private key entry");
            }
            
            KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) entry;
            privateKey = privateKeyEntry.getPrivateKey();
            publicKey = privateKeyEntry.getCertificate().getPublicKey();
            
            Log.d(TAG, "Loaded hardware-backed key");
            
        } else {
            String keystorePath = getReactApplicationContext().getFilesDir() + "/" + SOFTWARE_KEYSTORE_FILE;
            FileInputStream fis = new FileInputStream(keystorePath);
            
            KeyStore softwareKeyStore = KeyStore.getInstance("PKCS12");
            softwareKeyStore.load(fis, "".toCharArray());
            fis.close();
            
            if (!softwareKeyStore.containsAlias(privateKeyAlias)) {
                throw new KeyException("Software key not found: " + privateKeyAlias);
            }
            
            KeyStore.Entry entry = softwareKeyStore.getEntry(
                privateKeyAlias, 
                new KeyStore.PasswordProtection("".toCharArray())
            );
            
            if (!(entry instanceof KeyStore.PrivateKeyEntry)) {
                throw new KeyException("Not a private key entry");
            }
            
            KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) entry;
            privateKey = privateKeyEntry.getPrivateKey();
            publicKey = privateKeyEntry.getCertificate().getPublicKey();
            
            Log.d(TAG, "Loaded software key");
        }

        // Verify certificate matches key
        verifyCertMatchesKey(clientCert, publicKey);

        // Setup KeyManager
        KeyManager[] keyManagers = new KeyManager[] {
            new CustomKeyManager(privateKeyAlias, certChain, privateKey)
        };

        // Setup TrustManager
        KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
        trustStore.load(null, null);
        int i = 0;
        for (java.security.cert.Certificate cert : caCerts) {
            trustStore.setCertificateEntry("ca-cert-" + i++, (X509Certificate) cert);
        }

        TrustManager[] trustManagers = new TrustManager[] {
            new CustomTrustManager(trustStore)
        };

        // Create SSL context with TLS 1.3
        SSLContext sc = SSLContext.getInstance("TLSv1.3");
        sc.init(keyManagers, trustManagers, new SecureRandom());

        Log.d(TAG, "SSL context created (TLS 1.3)");
        return sc;
    }

    private void verifyCertMatchesKey(X509Certificate cert, PublicKey publicKey) throws Exception {
        byte[] certPubBytes = cert.getPublicKey().getEncoded();
        byte[] providedPubBytes = publicKey.getEncoded();

        if (!Arrays.equals(certPubBytes, providedPubBytes)) {
            throw new KeyException("Certificate does not match the private key");
        }
    }

    // ============================================================================
    // MQTT OPERATIONS
    // ============================================================================
    
    @ReactMethod
    public void subscribe(String topic, int qos, Callback successCallback, Callback errorCallback) {
        try {
            if (client == null || !client.isConnected()) {
                throw new MqttException(MqttException.REASON_CODE_CLIENT_NOT_CONNECTED);
            }

            client.subscribe(topic, qos, null, new IMqttActionListener() {
                @Override
                public void onSuccess(IMqttToken asyncActionToken) {
                    Log.i(TAG, "Subscribed to: " + topic);
                    successCallback.invoke("Subscribed to " + topic);
                }

                @Override
                public void onFailure(IMqttToken asyncActionToken, Throwable exception) {
                    Log.e(TAG, "Subscribe failed: " + exception.getMessage());
                    errorCallback.invoke("Subscribe failed: " + exception.getMessage());
                }
            });

        } catch (Exception e) {
            Log.e(TAG, "Subscribe error", e);
            errorCallback.invoke("Subscribe failed: " + e.getMessage());
        }
    }

    @ReactMethod
    public void unsubscribe(String topic, Callback successCallback, Callback errorCallback) {
        try {
            if (client == null || !client.isConnected()) {
                throw new MqttException(MqttException.REASON_CODE_CLIENT_NOT_CONNECTED);
            }

            client.unsubscribe(topic, null, new IMqttActionListener() {
                @Override
                public void onSuccess(IMqttToken asyncActionToken) {
                    Log.i(TAG, "Unsubscribed from: " + topic);
                    successCallback.invoke("Unsubscribed from " + topic);
                }

                @Override
                public void onFailure(IMqttToken asyncActionToken, Throwable exception) {
                    Log.e(TAG, "Unsubscribe failed: " + exception.getMessage());
                    errorCallback.invoke("Unsubscribe failed: " + exception.getMessage());
                }
            });

        } catch (Exception e) {
            Log.e(TAG, "Unsubscribe error", e);
            errorCallback.invoke("Unsubscribe failed: " + e.getMessage());
        }
    }

    @ReactMethod
    public void publish(String topic, String message, int qos, boolean retained, 
                       Callback successCallback, Callback errorCallback) {
        try {
            if (client == null || !client.isConnected()) {
                throw new MqttException(MqttException.REASON_CODE_CLIENT_NOT_CONNECTED);
            }

            MqttMessage mqttMessage = new MqttMessage(message.getBytes());
            mqttMessage.setQos(qos);
            mqttMessage.setRetained(retained);

            client.publish(topic, mqttMessage, null, new IMqttActionListener() {
                @Override
                public void onSuccess(IMqttToken asyncActionToken) {
                    successCallback.invoke("Published to " + topic);
                }

                @Override
                public void onFailure(IMqttToken asyncActionToken, Throwable exception) {
                    Log.e(TAG, "Publish failed: " + exception.getMessage());
                    errorCallback.invoke("Publish failed: " + exception.getMessage());
                }
            });

        } catch (Exception e) {
            Log.e(TAG, "Publish error", e);
            errorCallback.invoke("Publish failed: " + e.getMessage());
        }
    }

    @ReactMethod
    public void disconnect(Callback successCallback, Callback errorCallback) {
        try {
            if (client == null) {
                successCallback.invoke("No active connection");
                return;
            }

            if (client.isConnected()) {
                client.disconnect(null, new IMqttActionListener() {
                    @Override
                    public void onSuccess(IMqttToken asyncActionToken) {
                        try {
                            client.close();
                            client = null;
                            Log.i(TAG, "MQTT disconnected");
                            successCallback.invoke("Disconnected successfully");
                        } catch (Exception e) {
                            errorCallback.invoke("Disconnect error: " + e.getMessage());
                        }
                    }

                    @Override
                    public void onFailure(IMqttToken asyncActionToken, Throwable exception) {
                        Log.e(TAG, "Disconnect failed: " + exception.getMessage());
                        errorCallback.invoke("Disconnect failed: " + exception.getMessage());
                    }
                });
            } else {
                client.close();
                client = null;
                successCallback.invoke("Disconnected successfully");
            }

        } catch (Exception e) {
            Log.e(TAG, "Disconnect error", e);
            errorCallback.invoke("Disconnect failed: " + e.getMessage());
        }
    }

    @ReactMethod
    public void isConnected(Callback callback) {
        boolean connected = (client != null && client.isConnected());
        callback.invoke(connected);
    }

    // ============================================================================
    // DIAGNOSTIC METHODS
    // ============================================================================
    
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

            PrivateKey privateKey = ((KeyStore.PrivateKeyEntry) entry).getPrivateKey();

            StringBuilder result = new StringBuilder();
            result.append("Key Purposes Diagnostic\n");
            result.append("========================\n");
            result.append("Alias: ").append(privateKeyAlias).append("\n");
            result.append("Android API: ").append(android.os.Build.VERSION.SDK_INT).append("\n\n");

            try {
                KeyFactory factory = KeyFactory.getInstance(privateKey.getAlgorithm(), "AndroidKeyStore");
                android.security.keystore.KeyInfo keyInfo = factory.getKeySpec(
                        privateKey,
                        android.security.keystore.KeyInfo.class);

                int purposes = keyInfo.getPurposes();
                result.append("Raw purposes: ").append(purposes).append("\n\n");

                boolean hasSign = (purposes & android.security.keystore.KeyProperties.PURPOSE_SIGN) != 0;
                boolean hasVerify = (purposes & android.security.keystore.KeyProperties.PURPOSE_VERIFY) != 0;

                result.append("Purposes:\n");
                result.append("  SIGN: ").append(hasSign ? "YES" : "NO").append("\n");
                result.append("  VERIFY: ").append(hasVerify ? "YES" : "NO").append("\n");

                if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.S) {
                    boolean hasAgreeKey = (purposes & android.security.keystore.KeyProperties.PURPOSE_AGREE_KEY) != 0;
                    result.append("  AGREE_KEY: ").append(hasAgreeKey ? "YES" : "NO").append("\n");
                } else {
                    result.append("  AGREE_KEY: N/A (Android 12+ only)\n");
                }

                result.append("\nKey size: ").append(keyInfo.getKeySize()).append(" bits\n");
                result.append("Hardware-backed: ").append(keyInfo.isInsideSecureHardware()).append("\n");

            } catch (Exception e) {
                result.append("Error: ").append(e.getMessage()).append("\n");
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
            callback.invoke(keyStore.containsAlias(privateKeyAlias));
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
            StringBuilder sb = new StringBuilder("Available key aliases:\n");
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
