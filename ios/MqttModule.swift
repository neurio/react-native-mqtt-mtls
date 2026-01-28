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
            NSLog("MQTT connecting to \(broker) (client: \(clientId))")
            
            let clientCertPem = certificates["clientCert"] as? String
            let privateKeyAlias = certificates["privateKeyAlias"] as? String
            let rootCaPem = certificates["rootCa"] as? String
            
            // For API consistency with Android (iOS handles hardware/software transparently)
            let useHardwareKey = certificates["useHardwareKey"] as? Bool ?? false
            if useHardwareKey {
                NSLog("Note: useHardwareKey=true (iOS uses Secure Enclave for P-256, software for others)")
            }
            
            guard let rootCa = rootCaPem, 
                  let clientCert = clientCertPem, 
                  let keyAlias = privateKeyAlias else {
                let error = "Missing required parameters (clientCert, privateKeyAlias, or rootCa)"
                NSLog("Error: \(error)")
                errorCallback([error])
                return
            }
            
            guard let url = URL(string: broker) else {
                throw NSError(domain: "MqttModule", code: -1,
                            userInfo: [NSLocalizedDescriptionKey: "Invalid broker URL"])
            }
            
            let host = brokerIp ?? url.host ?? ""
            let port = UInt16(url.port ?? 8883)
            let useTLS = url.scheme == "ssl" || url.scheme == "mqtts"
            
            NSLog("Connecting to \(host):\(port) (TLS: \(useTLS))")
            
            let client = CocoaMQTT(clientID: clientId, host: host, port: port)
            client.username = ""
            client.password = ""
            client.keepAlive = 60
            client.cleanSession = false
            client.autoReconnect = true
            
            if useTLS {
                let caCerts = try parseCertificatesFromPEM(rootCa)
                guard !caCerts.isEmpty else {
                    throw NSError(domain: "MqttModule", code: -1,
                                userInfo: [NSLocalizedDescriptionKey: "No CA certificates found"])
                }
                self.trustedCACertificates = caCerts
                NSLog("Loaded \(caCerts.count) CA certificate(s)")
                
                let sslSettings = try self.createSSLSettings(
                    privateKeyAlias: keyAlias,
                    clientCertPem: clientCert,
                    rootCaPem: rootCa,
                    sniHostname: sniHostname
                )
                
                client.enableSSL = true
                client.allowUntrustCACertificate = true
                client.sslSettings = sslSettings
                client.delegate = self
                
                NSLog("SSL configured (SNI: \(sniHostname ?? "none"))")
            }
            
            self.connectSuccessCallback = successCallback
            self.connectErrorCallback = errorCallback
            self.brokerUrl = broker
            self.clientIdentifier = clientId
            self.mqttClient = client
            
            _ = client.connect()
            
        } catch {
            NSLog("MQTT connection error: \(error.localizedDescription)")
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
        
        NSLog("MQTT disconnecting")
        client.disconnect()
        mqttClient = nil
        successCallback(["Disconnected"])
    }
    
    @objc
    func subscribe(_ topic: String, qos: NSInteger,
                  successCallback: @escaping RCTResponseSenderBlock,
                  errorCallback: @escaping RCTResponseSenderBlock) {
        guard let client = mqttClient, client.connState == .connected else {
            errorCallback(["Client not connected"])
            return
        }
        
        NSLog("Subscribing to: \(topic)")
        let mqttQos = CocoaMQTTQoS(rawValue: UInt8(qos)) ?? .qos1
        client.subscribe(topic, qos: mqttQos)
        successCallback(["Subscribed to \(topic)"])
    }
    
    @objc
    func unsubscribe(_ topic: String,
                    successCallback: @escaping RCTResponseSenderBlock,
                    errorCallback: @escaping RCTResponseSenderBlock) {
        guard let client = mqttClient, client.connState == .connected else {
            errorCallback(["Client not connected"])
            return
        }
        
        NSLog("Unsubscribing from: \(topic)")
        client.unsubscribe(topic)
        successCallback(["Unsubscribed from \(topic)"])
    }
    
    @objc
    func publish(_ topic: String, message: String, qos: NSInteger, retained: Bool,
                successCallback: @escaping RCTResponseSenderBlock,
                errorCallback: @escaping RCTResponseSenderBlock) {
        guard let client = mqttClient, client.connState == .connected else {
            errorCallback(["Client not connected"])
            return
        }
        
        let mqttQos = CocoaMQTTQoS(rawValue: UInt8(qos)) ?? .qos1
        
        // Try to decode as Base64 (for binary protobuf messages)
        if let binaryData = Data(base64Encoded: message) {
            // It's Base64-encoded binary data
            client.publish(topic, withData: binaryData, qos: mqttQos, retained: retained)
        } else {
            // It's a plain string
            client.publish(topic, withString: message, qos: mqttQos, retained: retained)
        }
        
        successCallback(["Published to \(topic)"])
    }
    
    @objc
    func isConnected(_ callback: @escaping RCTResponseSenderBlock) {
        let connected = mqttClient?.connState == .connected
        callback([connected])
    }
    
    // ============================================================================
    // SSL CONFIGURATION
    // ============================================================================
    
    private func createSSLSettings(
        privateKeyAlias: String,
        clientCertPem: String,
        rootCaPem: String,
        sniHostname: String?
    ) throws -> [String: NSObject] {
        
        let identity = try createIdentity(
            privateKeyAlias: privateKeyAlias,
            clientCertPem: clientCertPem
        )
        
        var settings: [String: NSObject] = [:]
        settings[kCFStreamSSLCertificates as String] = [identity] as NSArray
        
        if let sniHost = sniHostname, !sniHost.isEmpty {
            settings[kCFStreamSSLPeerName as String] = sniHost as NSString
        }
        
        return settings
    }
    
    private func createIdentity(privateKeyAlias: String, clientCertPem: String) throws -> SecIdentity {
        guard let privateKey = try loadPrivateKeyFromKeychain(alias: privateKeyAlias) else {
            throw NSError(domain: "MqttModule", code: -1,
                        userInfo: [NSLocalizedDescriptionKey: "Private key not found: \(privateKeyAlias)"])
        }
        
        let certificates = try parseCertificatesFromPEM(clientCertPem)
        guard let certificate = certificates.first else {
            throw NSError(domain: "MqttModule", code: -1,
                        userInfo: [NSLocalizedDescriptionKey: "Failed to parse client certificate"])
        }
        
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
            throw NSError(domain: "MqttModule", code: Int(addStatus),
                        userInfo: [NSLocalizedDescriptionKey: "Failed to add certificate: \(addStatus)"])
        }
        
        // Query for identity (cert + private key combination)
        let identityQuery: [String: Any] = [
            kSecClass as String: kSecClassIdentity,
            kSecAttrLabel as String: certLabel,
            kSecReturnRef as String: true
        ]
        
        var identityRef: CFTypeRef?
        let identityStatus = SecItemCopyMatching(identityQuery as CFDictionary, &identityRef)
        
        guard identityStatus == errSecSuccess else {
            throw NSError(domain: "MqttModule", code: -1,
                        userInfo: [NSLocalizedDescriptionKey: "Failed to create identity: \(identityStatus)"])
        }
        
        NSLog("Client identity created")
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
            NSLog("Private key not found: \(status)")
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

// ============================================================================
// COCOAMQTT DELEGATE
// ============================================================================

extension MqttModule: CocoaMQTTDelegate {
    
    func mqtt(_ mqtt: CocoaMQTT, didReceive trust: SecTrust, completionHandler: @escaping (Bool) -> Void) {
        guard !trustedCACertificates.isEmpty else {
            NSLog("Server cert validation failed: No CA certificates configured")
            completionHandler(false)
            return
        }
        
        let status = SecTrustSetAnchorCertificates(trust, trustedCACertificates as CFArray)
        guard status == errSecSuccess else {
            NSLog("Server cert validation failed: Could not set anchor certificates")
            completionHandler(false)
            return
        }
        
        SecTrustSetAnchorCertificatesOnly(trust, true)
        
        var error: CFError?
        let isValid = SecTrustEvaluateWithError(trust, &error)
        
        if isValid {
            NSLog("Server certificate validated")
            completionHandler(true)
        } else {
            let errorDesc = error?.localizedDescription ?? "Unknown error"
            NSLog("Server cert validation failed: \(errorDesc)")
            completionHandler(false)
        }
    }
    
    func mqtt(_ mqtt: CocoaMQTT, didConnectAck ack: CocoaMQTTConnAck) {
        if ack == .accept {
            NSLog("MQTT connected to \(brokerUrl)")
            self.sendEvent(withName: "MqttConnected", body: "Connected")
            connectSuccessCallback?(["Connected to \(brokerUrl)"])
            connectSuccessCallback = nil
            connectErrorCallback = nil
        } else {
            let error = "Connection rejected: \(ack)"
            NSLog("MQTT connection rejected: \(ack)")
            connectErrorCallback?([error])
            connectSuccessCallback = nil
            connectErrorCallback = nil
        }
    }
    
    func mqtt(_ mqtt: CocoaMQTT, didPublishMessage message: CocoaMQTTMessage, id: UInt16) {
        self.sendEvent(withName: "MqttDeliveryComplete", body: [
            "topic": message.topic,
            "messageId": id
        ])
    }
    
    func mqtt(_ mqtt: CocoaMQTT, didPublishAck id: UInt16) {}
    
    func mqtt(_ mqtt: CocoaMQTT, didReceiveMessage message: CocoaMQTTMessage, id: UInt16) {
        // Encode payload as Base64 for safe transmission to JS
        // This handles binary protobuf data correctly
        let payloadBase64 = message.payload.base64EncodedString()
        
        self.sendEvent(withName: "MqttMessage", body: [
            "topic": message.topic,
            "message": payloadBase64,
            "isBinary": true,
            "qos": message.qos.rawValue
        ])
    }
    
    func mqtt(_ mqtt: CocoaMQTT, didSubscribeTopics success: NSDictionary, failed: [String]) {}
    func mqtt(_ mqtt: CocoaMQTT, didUnsubscribeTopics topics: [String]) {}
    func mqttDidPing(_ mqtt: CocoaMQTT) {}
    func mqttDidReceivePong(_ mqtt: CocoaMQTT) {}
    
    func mqttDidDisconnect(_ mqtt: CocoaMQTT, withError err: Error?) {
        let errorMsg = err?.localizedDescription ?? "Disconnected"
        NSLog("MQTT disconnected: \(errorMsg)")
        self.sendEvent(withName: "MqttDisconnected", body: errorMsg)
    }
}