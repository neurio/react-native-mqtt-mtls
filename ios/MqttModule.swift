import Foundation
import CocoaMQTT
import Security
import React

@objc(MqttModule)
class MqttModule: RCTEventEmitter {
    private var mqttClient: CocoaMQTT?
    private var trustedCACertificates: [SecCertificate] = []
    private var connectSuccessCallback: RCTResponseSenderBlock?
    private var connectErrorCallback: RCTResponseSenderBlock?
    private var brokerUrl: String = ""
    private var clientIdentifier: String = ""
    private let TAG = "MqttModule"
    
    override init() {
        super.init()
        NSLog("=== MqttModule Initialized ===")
    }
    
    override func supportedEvents() -> [String]! {
        return ["MqttConnected", "MqttDisconnected", "MqttMessage", "MqttDeliveryComplete"]
    }
    
    override static func requiresMainQueueSetup() -> Bool {
        return false
    }
    
    @objc
    func connect(
        _ broker: String,
        clientId: String,
        certificates: NSDictionary,
        sniHostname: String?,
        brokerIp: String?,
        successCallback: @escaping RCTResponseSenderBlock,
        errorCallback: @escaping RCTResponseSenderBlock
    ) {
        do {
            NSLog("╔════════════════════════════════════════════════════════════════")
            NSLog("║ MQTT Connection Request")
            NSLog("╠════════════════════════════════════════════════════════════════")
            NSLog("║ Broker: \(broker)")
            NSLog("║ Client ID: \(clientId)")
            NSLog("║ SNI Hostname: \(sniHostname ?? "nil")")
            NSLog("║ Broker IP: \(brokerIp ?? "nil")")
            NSLog("║ Timestamp: \(Date())")
            NSLog("╚════════════════════════════════════════════════════════════════")
            
            // Extract certificates
            let clientCertPem = certificates["clientCert"] as? String
            let privateKeyAlias = certificates["privateKeyAlias"] as? String
            let rootCaPem = certificates["rootCa"] as? String
            
            // Validate required parameters
            guard let rootCa = rootCaPem, let clientCert = clientCertPem, let keyAlias = privateKeyAlias else {
                let error = "Missing required parameters. Please provide clientCert, privateKeyAlias, and rootCa."
                NSLog("❌ \(error)")
                NSLog("  clientCert provided: \(clientCertPem != nil)")
                NSLog("  privateKeyAlias provided: \(privateKeyAlias != nil)")
                NSLog("  rootCa provided: \(rootCaPem != nil)")
                errorCallback([error])
                return
            }
            
            NSLog("✓ All required parameters provided")
            NSLog("  Client cert length: \(clientCert.count) bytes")
            NSLog("  Private key alias: \(keyAlias)")
            NSLog("  Root CA length: \(rootCa.count) bytes")
            
            // Parse broker URL
            guard let url = URL(string: broker) else {
                throw NSError(domain: "MqttModule", code: -1,
                            userInfo: [NSLocalizedDescriptionKey: "Invalid broker URL"])
            }
            
            // Use brokerIp if provided, otherwise use URL host
            let host = brokerIp ?? url.host ?? ""
            let port = UInt16(url.port ?? 8883)
            let useTLS = url.scheme == "ssl" || url.scheme == "mqtts"
            
            NSLog("")
            NSLog("┌─────────────────────────────────────────────────────────────")
            NSLog("│ Creating MQTT Client")
            NSLog("└─────────────────────────────────────────────────────────────")
            NSLog("  Host: \(host)")
            NSLog("  Port: \(port)")
            NSLog("  Use TLS: \(useTLS)")
            
            // Create MQTT client
            let client = CocoaMQTT(clientID: clientId, host: host, port: port)
            client.username = ""
            client.password = ""
            client.keepAlive = 60
            client.cleanSession = false
            client.autoReconnect = true
            
            if useTLS {
                NSLog("")
                NSLog("┌─────────────────────────────────────────────────────────────")
                NSLog("│ Creating SSL Configuration")
                NSLog("└─────────────────────────────────────────────────────────────")
                
                // Parse and store CA certificates for server validation
                let caCerts = try parseCertificatesFromPEM(rootCa)
                guard !caCerts.isEmpty else {
                    throw NSError(domain: "MqttModule", code: -1,
                                userInfo: [NSLocalizedDescriptionKey: "No CA certificates found"])
                }
                self.trustedCACertificates = caCerts
                NSLog("  ✓ Stored \(caCerts.count) CA certificate(s) for validation")
                
                let sslSettings = try self.createSSLSettings(
                    privateKeyAlias: keyAlias,
                    clientCertPem: clientCert,
                    rootCaPem: rootCa,
                    sniHostname: sniHostname
                )
                
                client.enableSSL = true
                client.allowUntrustCACertificate = true  // We'll validate manually via delegate
                client.sslSettings = sslSettings
                client.delegate = self  // Set delegate for certificate validation
                
                NSLog("✓ SSL settings configured")
                NSLog("  Settings keys: \(sslSettings.keys)")
            }
            
            // Setup callbacks - we'll use delegate methods instead of closures
            // to properly handle certificate validation
            self.connectSuccessCallback = successCallback
            self.connectErrorCallback = errorCallback
            self.brokerUrl = broker
            self.clientIdentifier = clientId
            
            self.mqttClient = client
            
            NSLog("")
            NSLog("╔════════════════════════════════════════════════════════════════")
            NSLog("║ Connecting to Broker...")
            NSLog("╚════════════════════════════════════════════════════════════════")
            
            _ = client.connect()
            
        } catch {
            NSLog("❌ Error: \(error.localizedDescription)")
            errorCallback([error.localizedDescription])
        }
    }
    
    @objc
    func disconnect(_ successCallback: @escaping RCTResponseSenderBlock,
                   errorCallback: @escaping RCTResponseSenderBlock) {
        guard let client = mqttClient else {
            errorCallback(["No active connection"])
            return
        }
        
        NSLog("📡 Disconnecting from broker...")
        client.disconnect()
        mqttClient = nil
        successCallback(["Disconnected"])
    }
    
    @objc
    func subscribe(_ topic: String, qos: NSInteger,
                  successCallback: @escaping RCTResponseSenderBlock,
                  errorCallback: @escaping RCTResponseSenderBlock) {
        guard let client = mqttClient else {
            errorCallback(["No active connection"])
            return
        }
        
        guard client.connState == .connected else {
            errorCallback(["Client not connected"])
            return
        }
        
        NSLog("📥 Subscribing to topic: \(topic) with QoS \(qos)")
        let mqttQos = CocoaMQTTQoS(rawValue: UInt8(qos)) ?? .qos1
        client.subscribe(topic, qos: mqttQos)
        successCallback(["Subscribed to \(topic)"])
    }
    
    @objc
    func unsubscribe(_ topic: String,
                    successCallback: @escaping RCTResponseSenderBlock,
                    errorCallback: @escaping RCTResponseSenderBlock) {
        guard let client = mqttClient else {
            errorCallback(["No active connection"])
            return
        }
        
        guard client.connState == .connected else {
            errorCallback(["Client not connected"])
            return
        }
        
        NSLog("📤 Unsubscribing from topic: \(topic)")
        client.unsubscribe(topic)
        successCallback(["Unsubscribed from \(topic)"])
    }
    
    @objc
    func publish(_ topic: String, message: String, qos: NSInteger, retained: Bool,
                successCallback: @escaping RCTResponseSenderBlock,
                errorCallback: @escaping RCTResponseSenderBlock) {
        guard let client = mqttClient else {
            errorCallback(["No active connection"])
            return
        }
        
        guard client.connState == .connected else {
            errorCallback(["Client not connected"])
            return
        }
        
        NSLog("📤 Publishing to topic: \(topic)")
        let mqttQos = CocoaMQTTQoS(rawValue: UInt8(qos)) ?? .qos1
        client.publish(topic, withString: message, qos: mqttQos, retained: retained)
        successCallback(["Published to \(topic)"])
    }
    
    @objc
    func isConnected(_ callback: @escaping RCTResponseSenderBlock) {
        let connected = mqttClient?.connState == .connected
        callback([connected])
    }
    
    // SSL Configuration (SecIdentity for mTLS)
    
    private func createSSLSettings(
        privateKeyAlias: String,
        clientCertPem: String,
        rootCaPem: String,
        sniHostname: String?
    ) throws -> [String: NSObject] {
        
        NSLog("  Building SSL settings...")
        
        // Create SecIdentity for client certificate
        let identity = try createIdentity(
            privateKeyAlias: privateKeyAlias,
            clientCertPem: clientCertPem
        )
        NSLog("  ✓ Client identity created")
        
        // Build SSL settings dictionary
        // For CocoaMQTT, we need to provide the client certificate identity
        var settings: [String: NSObject] = [:]
        settings[kCFStreamSSLCertificates as String] = [identity] as NSArray
        
        // SNI hostname if provided
        if let sniHost = sniHostname, !sniHost.isEmpty {
            settings[kCFStreamSSLPeerName as String] = sniHost as NSString
            NSLog("  ✓ SNI hostname: \(sniHost)")
        }
        
        NSLog("  ✓ SSL settings created with \(settings.count) entries")
        return settings
    }
    
    private func createIdentity(privateKeyAlias: String, clientCertPem: String) throws -> SecIdentity {
        NSLog("    Creating SecIdentity...")
        
        // Load private key from Keychain using alias
        NSLog("    Loading private key from Keychain: \(privateKeyAlias)")
        guard let privateKey = try loadPrivateKeyFromKeychain(alias: privateKeyAlias) else {
            throw NSError(domain: "MqttModule", code: -1,
                        userInfo: [NSLocalizedDescriptionKey: "Private key not found in Keychain: \(privateKeyAlias)"])
        }
        NSLog("    ✓ Private key loaded from Keychain")
        
        // Parse certificate from PEM
        NSLog("    Parsing client certificate from PEM...")
        let certificates = try parseCertificatesFromPEM(clientCertPem)
        guard let certificate = certificates.first else {
            throw NSError(domain: "MqttModule", code: -1,
                        userInfo: [NSLocalizedDescriptionKey: "Failed to parse client certificate"])
        }
        NSLog("    ✓ Certificate parsed (\(certificates.count) cert(s) in chain)")
        
        // Add certificate to Keychain temporarily to create identity
        let certLabel = "MQTT_CLIENT_CERT_\(privateKeyAlias)"
        
        // Delete existing certificate if any
        let deleteQuery: [String: Any] = [
            kSecClass as String: kSecClassCertificate,
            kSecAttrLabel as String: certLabel
        ]
        SecItemDelete(deleteQuery as CFDictionary)
        
        // Add certificate to Keychain
        let addQuery: [String: Any] = [
            kSecClass as String: kSecClassCertificate,
            kSecValueRef as String: certificate,
            kSecAttrLabel as String: certLabel
        ]
        
        let addStatus = SecItemAdd(addQuery as CFDictionary, nil)
        guard addStatus == errSecSuccess || addStatus == errSecDuplicateItem else {
            NSLog("    ❌ Failed to add certificate: \(addStatus)")
            throw NSError(domain: "MqttModule", code: Int(addStatus),
                        userInfo: [NSLocalizedDescriptionKey: "Failed to add certificate to Keychain: \(addStatus)"])
        }
        NSLog("    ✓ Certificate added to Keychain")
        
        // Query for identity (cert + private key combination)
        let identityQuery: [String: Any] = [
            kSecClass as String: kSecClassIdentity,
            kSecAttrLabel as String: certLabel,
            kSecReturnRef as String: true
        ]
        
        var identityRef: CFTypeRef?
        let identityStatus = SecItemCopyMatching(identityQuery as CFDictionary, &identityRef)
        
        guard identityStatus == errSecSuccess else {
            NSLog("    ❌ Failed to create identity: \(identityStatus)")
            throw NSError(domain: "MqttModule", code: -1,
                        userInfo: [NSLocalizedDescriptionKey: "Failed to create SecIdentity: \(identityStatus)"])
        }
        
        NSLog("    ✓ SecIdentity created successfully")
        return (identityRef as! SecIdentity)
    }
    
    private func loadPrivateKeyFromKeychain(alias: String) throws -> SecKey? {
        guard let tag = alias.data(using: .utf8) else {
            throw NSError(domain: "MqttModule", code: -1,
                        userInfo: [NSLocalizedDescriptionKey: "Invalid alias"])
        }
        
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrApplicationTag as String: tag,
            kSecReturnRef as String: true
        ]
        
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        
        guard status == errSecSuccess else {
            NSLog("    ❌ Private key not found: \(status)")
            return nil
        }
        
        return (item as! SecKey)
    }
    
    private func parseCertificatesFromPEM(_ pem: String) throws -> [SecCertificate] {
        var certificates: [SecCertificate] = []
        
        let components = pem.components(separatedBy: "-----BEGIN CERTIFICATE-----")
        
        for component in components {
            guard component.contains("-----END CERTIFICATE-----") else {
                continue
            }
            
            guard let endRange = component.range(of: "-----END CERTIFICATE-----") else {
                continue
            }
            
            let base64 = String(component[..<endRange.lowerBound])
                .trimmingCharacters(in: .whitespacesAndNewlines)
                .replacingOccurrences(of: "\n", with: "")
                .replacingOccurrences(of: "\r", with: "")
            
            guard let certData = Data(base64Encoded: base64),
                  let cert = SecCertificateCreateWithData(nil, certData as CFData) else {
                continue
            }
            
            certificates.append(cert)
        }
        
        return certificates
    }
}

// CocoaMQTT Delegate for Server Certificate Validation
extension MqttModule: CocoaMQTTDelegate {
    
    func mqtt(_ mqtt: CocoaMQTT, didReceive trust: SecTrust, completionHandler: @escaping (Bool) -> Void) {
        NSLog("🔐 Server certificate validation requested")
        
        // If no CA certificates configured, reject
        guard !trustedCACertificates.isEmpty else {
            NSLog("  ❌ No CA certificates configured - rejecting server")
            completionHandler(false)
            return
        }
        
        // Set our CA certificates as anchors for validation
        let status = SecTrustSetAnchorCertificates(trust, trustedCACertificates as CFArray)
        guard status == errSecSuccess else {
            NSLog("  ❌ Failed to set anchor certificates: \(status)")
            completionHandler(false)
            return
        }
        
        // Enable only our CA certificates (don't use system roots)
        SecTrustSetAnchorCertificatesOnly(trust, true)
        
        // Evaluate the trust
        var error: CFError?
        let isValid = SecTrustEvaluateWithError(trust, &error)
        
        if isValid {
            NSLog("  ✅ Server certificate validated successfully")
            completionHandler(true)
        } else {
            let errorDesc = error?.localizedDescription ?? "Unknown error"
            NSLog("  ❌ Server certificate validation failed: \(errorDesc)")
            completionHandler(false)
        }
    }
    
    func mqtt(_ mqtt: CocoaMQTT, didConnectAck ack: CocoaMQTTConnAck) {
        if ack == .accept {
            NSLog("╔════════════════════════════════════════════════════════════════")
            NSLog("║ ✓✓✓ MQTT SUCCESSFULLY CONNECTED ✓✓✓")
            NSLog("╠════════════════════════════════════════════════════════════════")
            NSLog("║ Broker: \(brokerUrl)")
            NSLog("║ Client ID: \(clientIdentifier)")
            NSLog("║ Timestamp: \(Date())")
            NSLog("╚════════════════════════════════════════════════════════════════")
            
            self.sendEvent(withName: "MqttConnected", body: "Connected")
            connectSuccessCallback?(["Connected to \(brokerUrl)"])
            connectSuccessCallback = nil
            connectErrorCallback = nil
        } else {
            let error = "Connection rejected: \(ack)"
            NSLog("❌ \(error)")
            connectErrorCallback?([error])
            connectSuccessCallback = nil
            connectErrorCallback = nil
        }
    }
    
    func mqtt(_ mqtt: CocoaMQTT, didPublishMessage message: CocoaMQTTMessage, id: UInt16) {
        NSLog("📤 Message delivered: \(message.topic)")
        
        self.sendEvent(withName: "MqttDeliveryComplete", body: [
            "topic": message.topic,
            "messageId": id
        ])
    }
    
    func mqtt(_ mqtt: CocoaMQTT, didPublishAck id: UInt16) {}
    
    func mqtt(_ mqtt: CocoaMQTT, didReceiveMessage message: CocoaMQTTMessage, id: UInt16) {
        NSLog("📨 Message received on topic: \(message.topic)")
        
        self.sendEvent(withName: "MqttMessage", body: [
            "topic": message.topic,
            "message": message.string ?? "",
            "qos": message.qos.rawValue
        ])
    }
    
    func mqtt(_ mqtt: CocoaMQTT, didSubscribeTopics success: NSDictionary, failed: [String]) {}
    func mqtt(_ mqtt: CocoaMQTT, didUnsubscribeTopics topics: [String]) {}
    func mqttDidPing(_ mqtt: CocoaMQTT) {}
    func mqttDidReceivePong(_ mqtt: CocoaMQTT) {}
    
    func mqttDidDisconnect(_ mqtt: CocoaMQTT, withError err: Error?) {
        let errorMsg = err?.localizedDescription ?? "Unknown error"
        
        NSLog("╔════════════════════════════════════════════════════════════════")
        NSLog("║ ❌ MQTT Disconnected")
        NSLog("╠════════════════════════════════════════════════════════════════")
        NSLog("║ Error: \(errorMsg)")
        NSLog("║ Timestamp: \(Date())")
        NSLog("╚════════════════════════════════════════════════════════════════")
        
        self.sendEvent(withName: "MqttDisconnected", body: errorMsg)
    }
}
