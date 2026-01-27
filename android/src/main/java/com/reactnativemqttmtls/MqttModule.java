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

    // --- Custom TrustManager with EXTENSIVE LOGGING ---
    private static class CustomTrustManager implements X509TrustManager {
        private final X509Certificate[] acceptedIssuers;
        
        public CustomTrustManager(KeyStore trustStore) throws Exception {
            List<X509Certificate> certs = new ArrayList<>();
            Enumeration<String> aliases = trustStore.aliases();
            
            Log.d(TAG, "╔════════════════════════════════════════════════════════════════");
            Log.d(TAG, "║ Initializing CustomTrustManager");
            Log.d(TAG, "╚════════════════════════════════════════════════════════════════");
            
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                java.security.cert.Certificate cert = trustStore.getCertificate(alias);
                if (cert instanceof X509Certificate) {
                    X509Certificate x509 = (X509Certificate) cert;
                    certs.add(x509);
                    Log.d(TAG, "  Trusted CA: " + x509.getSubjectDN());
                    Log.d(TAG, "    Issuer: " + x509.getIssuerDN());
                    Log.d(TAG, "    Serial: " + x509.getSerialNumber().toString(16));
                }
            }
            
            this.acceptedIssuers = certs.toArray(new X509Certificate[0]);
            Log.d(TAG, "✓ CustomTrustManager initialized with " + acceptedIssuers.length + " CA(s)");
            Log.d(TAG, "");
        }
        
        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) {
            // Not needed for client
        }
        
        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            Log.d(TAG, "╔════════════════════════════════════════════════════════════════");
            Log.d(TAG, "║ 🔐 SERVER CERTIFICATE VALIDATION STARTING");
            Log.d(TAG, "╠════════════════════════════════════════════════════════════════");
            Log.d(TAG, "║ Auth Type: " + authType);
            Log.d(TAG, "║ Chain Length: " + (chain != null ? chain.length : 0));
            Log.d(TAG, "╚════════════════════════════════════════════════════════════════");
            
            if (chain == null || chain.length == 0) {
                Log.e(TAG, "❌ FAILED: Server certificate chain is empty");
                throw new CertificateException("Server certificate chain is empty");
            }
            
            // Log the entire certificate chain received from server
            Log.d(TAG, "");
            Log.d(TAG, "📋 Server Certificate Chain:");
            for (int i = 0; i < chain.length; i++) {
                X509Certificate cert = chain[i];
                Log.d(TAG, "  [" + i + "] Subject: " + cert.getSubjectDN());
                Log.d(TAG, "      Issuer:  " + cert.getIssuerDN());
                Log.d(TAG, "      Serial:  " + cert.getSerialNumber().toString(16));
                Log.d(TAG, "      Valid:   " + cert.getNotBefore() + " to " + cert.getNotAfter());
                
                try {
                    cert.checkValidity();
                    Log.d(TAG, "      ✓ Certificate is currently valid");
                } catch (Exception e) {
                    Log.e(TAG, "      ❌ Certificate validity check failed: " + e.getMessage());
                }
            }
            
            Log.d(TAG, "");
            Log.d(TAG, "🔍 Starting Validation Process...");
            Log.d(TAG, "");
            
            try {
                X509Certificate serverCert = chain[0];
                boolean validated = false;
                String validationPath = "";
                
                // STEP 1: Try direct validation (server cert signed by one of our CAs)
                Log.d(TAG, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
                Log.d(TAG, "STEP 1: Checking if server cert is directly signed by our CAs");
                Log.d(TAG, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
                
                for (int caIndex = 0; caIndex < acceptedIssuers.length; caIndex++) {
                    X509Certificate ca = acceptedIssuers[caIndex];
                    Log.d(TAG, "  Trying CA[" + caIndex + "]: " + ca.getSubjectDN());
                    
                    try {
                        serverCert.verify(ca.getPublicKey());
                        Log.d(TAG, "  ✅ SUCCESS! Server cert verified by CA[" + caIndex + "]");
                        Log.d(TAG, "     CA Subject: " + ca.getSubjectDN());
                        validationPath = "Direct: Server cert → CA[" + caIndex + "]";
                        validated = true;
                        break;
                    } catch (SignatureException e) {
                        Log.d(TAG, "  ✗ Signature mismatch with CA[" + caIndex + "]");
                    } catch (Exception e) {
                        Log.d(TAG, "  ✗ Verification failed with CA[" + caIndex + "]: " + e.getClass().getSimpleName());
                    }
                }
                
                // STEP 2: Try validation via intermediate certificates in the chain
                if (!validated && chain.length > 1) {
                    Log.d(TAG, "");
                    Log.d(TAG, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
                    Log.d(TAG, "STEP 2: Checking validation via intermediate certificates");
                    Log.d(TAG, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
                    
                    for (int i = 1; i < chain.length; i++) {
                        X509Certificate intermediateCert = chain[i];
                        Log.d(TAG, "  Checking intermediate[" + i + "]: " + intermediateCert.getSubjectDN());
                        
                        // First, verify the intermediate cert against our CAs
                        for (int caIndex = 0; caIndex < acceptedIssuers.length; caIndex++) {
                            X509Certificate ca = acceptedIssuers[caIndex];
                            Log.d(TAG, "    Trying to verify intermediate[" + i + "] with CA[" + caIndex + "]");
                            
                            try {
                                intermediateCert.verify(ca.getPublicKey());
                                Log.d(TAG, "    ✓ Intermediate[" + i + "] verified by CA[" + caIndex + "]");
                                Log.d(TAG, "       CA: " + ca.getSubjectDN());
                                
                                // Now verify server cert is signed by this intermediate
                                Log.d(TAG, "    Now verifying server cert with intermediate[" + i + "]...");
                                serverCert.verify(intermediateCert.getPublicKey());
                                
                                Log.d(TAG, "    ✅ SUCCESS! Complete chain validated");
                                Log.d(TAG, "       Server cert → Intermediate[" + i + "] → CA[" + caIndex + "]");
                                validationPath = "Chain: Server cert → Intermediate[" + i + "] → CA[" + caIndex + "]";
                                validated = true;
                                break;
                            } catch (SignatureException e) {
                                Log.d(TAG, "    ✗ Signature mismatch");
                            } catch (Exception e) {
                                Log.d(TAG, "    ✗ Verification failed: " + e.getClass().getSimpleName());
                            }
                        }
                        
                        if (validated) break;
                    }
                }
                
                // STEP 3: Check if any intermediate in the chain IS one of our trusted CAs
                if (!validated && chain.length > 1) {
                    Log.d(TAG, "");
                    Log.d(TAG, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
                    Log.d(TAG, "STEP 3: Checking if intermediate IS a trusted CA");
                    Log.d(TAG, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
                    
                    for (int i = 1; i < chain.length; i++) {
                        X509Certificate intermediateCert = chain[i];
                        Log.d(TAG, "  Checking if intermediate[" + i + "] is in our trust store");
                        Log.d(TAG, "    Subject: " + intermediateCert.getSubjectDN());
                        
                        for (int caIndex = 0; caIndex < acceptedIssuers.length; caIndex++) {
                            X509Certificate ca = acceptedIssuers[caIndex];
                            
                            // Compare subjects
                            boolean subjectsMatch = intermediateCert.getSubjectDN().equals(ca.getSubjectDN());
                            
                            if (subjectsMatch) {
                                Log.d(TAG, "    ✓ Subject matches CA[" + caIndex + "]");
                                
                                // Compare public keys to be sure
                                try {
                                    byte[] intermediatePubKey = intermediateCert.getPublicKey().getEncoded();
                                    byte[] caPubKey = ca.getPublicKey().getEncoded();
                                    
                                    if (Arrays.equals(intermediatePubKey, caPubKey)) {
                                        Log.d(TAG, "    ✓ Public keys match - same certificate!");
                                        
                                        // Verify server cert with this intermediate
                                        serverCert.verify(intermediateCert.getPublicKey());
                                        
                                        Log.d(TAG, "    ✅ SUCCESS! Server cert verified by trusted intermediate");
                                        validationPath = "Trusted Intermediate: Server cert → Intermediate[" + i + "] (=CA[" + caIndex + "])";
                                        validated = true;
                                        break;
                                    } else {
                                        Log.d(TAG, "    ✗ Public keys don't match");
                                    }
                                } catch (Exception e) {
                                    Log.d(TAG, "    ✗ Verification failed: " + e.getMessage());
                                }
                            }
                        }
                        
                        if (validated) break;
                    }
                }
                
                // Final result
                Log.d(TAG, "");
                Log.d(TAG, "╔════════════════════════════════════════════════════════════════");
                if (validated) {
                    Log.d(TAG, "║ ✅ VALIDATION SUCCESSFUL");
                    Log.d(TAG, "╠════════════════════════════════════════════════════════════════");
                    Log.d(TAG, "║ Path: " + validationPath);
                    Log.d(TAG, "╚════════════════════════════════════════════════════════════════");
                } else {
                    Log.e(TAG, "║ ❌ VALIDATION FAILED");
                    Log.e(TAG, "╠════════════════════════════════════════════════════════════════");
                    Log.e(TAG, "║ Could not validate server certificate with any trusted CA");
                    Log.e(TAG, "╚════════════════════════════════════════════════════════════════");
                    
                    Log.e(TAG, "");
                    Log.e(TAG, "📋 Summary:");
                    Log.e(TAG, "  Server cert: " + serverCert.getSubjectDN());
                    Log.e(TAG, "  Issued by:   " + serverCert.getIssuerDN());
                    Log.e(TAG, "");
                    Log.e(TAG, "  Available trusted CAs:");
                    for (int caIndex = 0; caIndex < acceptedIssuers.length; caIndex++) {
                        Log.e(TAG, "    [" + caIndex + "] " + acceptedIssuers[caIndex].getSubjectDN());
                    }
                    
                    throw new CertificateException("Server certificate not trusted by any configured CA");
                }
                
            } catch (CertificateException e) {
                throw e;
            } catch (Exception e) {
                Log.e(TAG, "");
                Log.e(TAG, "╔════════════════════════════════════════════════════════════════");
                Log.e(TAG, "║ ❌ UNEXPECTED ERROR DURING VALIDATION");
                Log.e(TAG, "╠════════════════════════════════════════════════════════════════");
                Log.e(TAG, "║ Error: " + e.getClass().getName());
                Log.e(TAG, "║ Message: " + e.getMessage());
                Log.e(TAG, "╚════════════════════════════════════════════════════════════════");
                e.printStackTrace();
                throw new CertificateException("Certificate validation failed", e);
            }
        }
        
        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return acceptedIssuers;
        }
    }

    // --- Custom KeyManager for Hardware-Backed Keys ---
    private static class CustomKeyManager extends X509ExtendedKeyManager {
        private final String alias;
        private final X509Certificate[] certChain;
        private final PrivateKey privateKey;
        
        public CustomKeyManager(String alias, X509Certificate[] certChain, PrivateKey privateKey) {
            this.alias = alias;
            this.certChain = certChain;
            this.privateKey = privateKey;
            
            Log.d(TAG, "╔════════════════════════════════════════════════════════════════");
            Log.d(TAG, "║ CustomKeyManager Initialized");
            Log.d(TAG, "╚════════════════════════════════════════════════════════════════");
            Log.d(TAG, "  Alias: " + alias);
            Log.d(TAG, "  Cert chain length: " + certChain.length);
            Log.d(TAG, "  Private key algorithm: " + privateKey.getAlgorithm());
            Log.d(TAG, "  Private key class: " + privateKey.getClass().getName());
            Log.d(TAG, "");
        }
        
        @Override
        public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
            Log.d(TAG, "🔑 chooseClientAlias called");
            Log.d(TAG, "  Key types: " + Arrays.toString(keyType));
            Log.d(TAG, "  Returning alias: " + alias);
            return alias;
        }
        
        @Override
        public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
            return null;
        }
        
        @Override
        public X509Certificate[] getCertificateChain(String alias) {
            Log.d(TAG, "📜 getCertificateChain called for: " + alias);
            if (this.alias.equals(alias)) {
                Log.d(TAG, "  Returning chain with " + certChain.length + " cert(s)");
                for (int i = 0; i < certChain.length; i++) {
                    Log.d(TAG, "    [" + i + "] " + certChain[i].getSubjectDN());
                }
                return certChain;
            }
            return null;
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
            Log.d(TAG, "🔐 getPrivateKey called for: " + alias);
            if (this.alias.equals(alias)) {
                Log.d(TAG, "  Returning hardware-backed private key");
                return privateKey;
            }
            return null;
        }
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

            // DISABLED SNI FOR DEBUGGING
            SSLSocketFactory socketFactory = sslContext.getSocketFactory();
            Log.d(TAG, "✓ Using default SSL factory (SNI disabled for debugging)");

            options.setSocketFactory(socketFactory);

            // Set up callbacks
            client.setCallback(new MqttCallbackExtended() {
                @Override
                public void connectComplete(boolean reconnect, String serverURI) {
                    Log.i(TAG, "╔════════════════════════════════════════════════════════════════");
                    Log.i(TAG, "║ ✅✅✅ MQTT SUCCESSFULLY CONNECTED ✅✅✅");
                    Log.i(TAG, "╠════════════════════════════════════════════════════════════════");
                    Log.i(TAG, "║ Broker: " + serverURI);
                    Log.i(TAG, "║ Reconnect: " + reconnect);
                    Log.i(TAG, "╚════════════════════════════════════════════════════════════════");
                    sendEvent("MqttConnected", "Connected to broker: " + serverURI);
                }

                @Override
                public void connectionLost(Throwable cause) {
                    Log.e(TAG, "❌ MQTT Connection Lost: " + (cause != null ? cause.getMessage() : "Unknown"));
                    if (cause != null) {
                        cause.printStackTrace();
                    }
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
                    Log.i(TAG, "✅ MQTT Connect Action: SUCCESS");
                    if (success != null)
                        success.invoke("Connected");
                }

                @Override
                public void onFailure(IMqttToken asyncActionToken, Throwable exception) {
                    Log.e(TAG, "╔════════════════════════════════════════════════════════════════");
                    Log.e(TAG, "║ ❌ MQTT Connection FAILED");
                    Log.e(TAG, "╚════════════════════════════════════════════════════════════════");
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
        Log.d(TAG, "╔════════════════════════════════════════════════════════════════");
        Log.d(TAG, "║ Creating SSLContext");
        Log.d(TAG, "╚════════════════════════════════════════════════════════════════");
        Log.d(TAG, "Key Alias: " + privateKeyAlias);

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
        ArrayList<X509Certificate> certChainList = new ArrayList<>();
        for (X509Certificate cert : clientCertArray) {
            boolean isSelfSigned = cert.getIssuerDN().equals(cert.getSubjectDN());
            if (!isSelfSigned) {
                certChainList.add(cert);
            }
        }
        X509Certificate[] certChain = certChainList.toArray(new X509Certificate[0]);

        // Get hardware-backed private key (keep it in AndroidKeyStore - don't extract!)
        PrivateKey privateKey = (PrivateKey) androidKeyStore.getKey(privateKeyAlias, null);
        Log.d(TAG, "✓ Retrieved hardware-backed private key (not extracted)");

        // Use custom KeyManager that keeps key in AndroidKeyStore
        KeyManager[] keyManagers = new KeyManager[] {
            new CustomKeyManager(privateKeyAlias, certChain, privateKey)
        };
        Log.d(TAG, "✓ Custom KeyManager configured with " + certChain.length + " cert(s) in chain");

        // Add ALL CA certificates to trust store
        KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
        trustStore.load(null, null);

        int i = 0;
        for (java.security.cert.Certificate cert : caCerts) {
            X509Certificate x509 = (X509Certificate) cert;
            trustStore.setCertificateEntry("ca-cert-" + i, x509);
            i++;
        }

        // USE CUSTOM TRUSTMANAGER (like iOS) with extensive logging
        TrustManager[] trustManagers = new TrustManager[] {
            new CustomTrustManager(trustStore)
        };
        Log.d(TAG, "✓ Custom TrustManager configured");

        SSLContext sc = SSLContext.getInstance("TLS");
        sc.init(keyManagers, trustManagers, new SecureRandom());

        Log.d(TAG, "✅ SSLContext created successfully");
        Log.d(TAG, "");
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
            result.append("Android API Level: ").append(android.os.Build.VERSION.SDK_INT).append("\n\n");

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

                result.append("Key Purposes:\n");
                result.append("  SIGN: ").append(hasSign ? "✓ YES" : "✗ NO").append("\n");
                result.append("  VERIFY: ").append(hasVerify ? "✓ YES" : "✗ NO").append("\n");

                if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.S) {
                    boolean hasAgreeKey = (purposes & android.security.keystore.KeyProperties.PURPOSE_AGREE_KEY) != 0;
                    result.append("  AGREE_KEY: ").append(hasAgreeKey ? "✓ YES" : "✗ NO").append("\n\n");

                    if (!hasAgreeKey) {
                        result.append("❌ PROBLEM: Missing PURPOSE_AGREE_KEY!\n");
                        result.append("   (Required for TLS key agreement on Android 12+)\n");
                    } else {
                        result.append("✅ Key has all required purposes for TLS!\n");
                    }
                } else {
                    result.append("  AGREE_KEY: N/A (Android 12+ only)\n\n");
                    result.append("ℹ️  PURPOSE_AGREE_KEY is only available on Android 12+\n");
                    result.append("   On Android 10-11, TLS key agreement works without this flag.\n");
                    result.append("   Key should work fine for mTLS connections.\n");
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
