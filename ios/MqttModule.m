#import <React/RCTBridgeModule.h>
#import <React/RCTEventEmitter.h>

@interface RCT_EXTERN_MODULE(MqttModule, RCTEventEmitter)

/**
 * Connect to MQTT broker
 * @param broker - Broker URL (e.g., "ssl://broker.example.com:8883")
 * @param clientId - MQTT client identifier
 * @param certificates - Dictionary containing clientCert, privateKeyAlias, rootCa
 * @param sniHostname - SNI hostname for TLS (optional)
 * @param brokerIp - Explicit broker IP address (optional)
 * @param brokerCommonName - Expected Common Name in broker's certificate (optional)
 * @param successCallback - Called on successful connection
 * @param errorCallback - Called on connection failure
 */
RCT_EXTERN_METHOD(connect:(NSString *)broker
                  clientId:(NSString *)clientId
                  certificates:(NSDictionary *)certificates
                  sniHostname:(NSString *)sniHostname
                  brokerIp:(NSString *)brokerIp
                  brokerCommonName:(NSString *)brokerCommonName
                  successCallback:(RCTResponseSenderBlock)successCallback
                  errorCallback:(RCTResponseSenderBlock)errorCallback)

/**
 * Disconnect from MQTT broker
 */
RCT_EXTERN_METHOD(disconnect:(RCTResponseSenderBlock)successCallback
                  errorCallback:(RCTResponseSenderBlock)errorCallback)

/**
 * Check if client is connected
 */
RCT_EXTERN_METHOD(isConnected:(RCTResponseSenderBlock)callback)

// MARK: - Subscription Methods

/**
 * Subscribe to topic
 * @param topic - Topic to subscribe to
 * @param qos - Quality of Service (0, 1, or 2)
 */
RCT_EXTERN_METHOD(subscribe:(NSString *)topic
                  qos:(NSInteger)qos
                  successCallback:(RCTResponseSenderBlock)successCallback
                  errorCallback:(RCTResponseSenderBlock)errorCallback)

/**
 * Unsubscribe from topic
 * @param topic - Topic to unsubscribe from
 */
RCT_EXTERN_METHOD(unsubscribe:(NSString *)topic
                  successCallback:(RCTResponseSenderBlock)successCallback
                  errorCallback:(RCTResponseSenderBlock)errorCallback)

// MARK: - Publishing Methods

/**
 * Publish message to topic
 * @param topic - Topic to publish to
 * @param message - Message payload
 * @param qos - Quality of Service (0, 1, or 2)
 * @param retained - Whether message should be retained by broker
 */
RCT_EXTERN_METHOD(publish:(NSString *)topic
                  message:(NSString *)message
                  qos:(NSInteger)qos
                  retained:(BOOL)retained
                  successCallback:(RCTResponseSenderBlock)successCallback
                  errorCallback:(RCTResponseSenderBlock)errorCallback)

+ (BOOL)requiresMainQueueSetup
{
  return NO;
}

@end
