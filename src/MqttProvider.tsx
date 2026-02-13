import React, { useState, useEffect, useCallback, useRef } from 'react';
import { NativeEventEmitter } from 'react-native';
import { MqttContext } from './MqttContext';
import MqttModule from './MqttModule';

export const MqttProvider = ({ children }) => {
  const [isConnected, setIsConnected] = useState(false);
  const [error, setError] = useState(null);
  const configRef = useRef(null);
  const eventEmitterRef = useRef(null);

  useEffect(() => {
    // Cleanup any stale MQTT connections from previous app sessions
    if (typeof MqttModule.cleanup === 'function') {
      console.log('MqttProvider: Performing initial cleanup...');
      MqttModule.cleanup(
        (success) => {
          console.log('MqttProvider: Initial cleanup successful:', success);
        },
        (error) => {
          console.log('MqttProvider: Cleanup error (non-critical):', error);
        }
      );
    } else {
      console.log('MqttProvider: cleanup method not available, using disconnect fallback...');
      MqttModule.disconnect(
        (success) => {
          console.log('MqttProvider: Disconnect fallback successful:', success);
        },
        (error) => {
          console.log('MqttProvider: Disconnect fallback error (non-critical):', error);
        }
      );
    }

    // Create event emitter for MQTT events
    eventEmitterRef.current = new NativeEventEmitter(MqttModule);

    const subscriptions = [];

    // Subscribe to MQTT events
    subscriptions.push(
      eventEmitterRef.current.addListener('MqttConnected', (message) => {
        console.log('MQTT Connected:', message);
        setIsConnected(true);
        setError(null);
        if (configRef.current?.onConnect) {
          configRef.current.onConnect();
        }
      })
    );

    subscriptions.push(
      eventEmitterRef.current.addListener('MqttDisconnected', (message) => {
        console.log('MQTT Disconnected:', message);
        setIsConnected(false);
        if (configRef.current?.onConnectionLost) {
          configRef.current.onConnectionLost(message);
        }
      })
    );

    subscriptions.push(
      eventEmitterRef.current.addListener('MqttMessage', (data) => {
        try {
          const parsedData = typeof data === 'string' ? JSON.parse(data) : data;

          // Decode Base64 binary messages automatically
          if (parsedData.isBinary && parsedData.message) {
            try {
              const binaryString = atob(parsedData.message);
              const bytes = new Uint8Array(binaryString.length);
              for (let i = 0; i < binaryString.length; i++) {
                bytes[i] = binaryString.charCodeAt(i);
              }

              // Replace the base64 string with the decoded ArrayBuffer
              parsedData.payload = bytes.buffer;
              console.log('📨 Message received:', parsedData.topic, '(', bytes.length, 'bytes)');
            } catch (decodeErr) {
              console.error('Failed to decode Base64 message:', decodeErr);
              // Keep original message if decode fails
              parsedData.payload = parsedData.message;
            }
          } else {
            // Plain text message
            parsedData.payload = parsedData.message;
            console.log('📨 Message received:', parsedData.topic, '(text)');
          }

          if (configRef.current?.onMessage) {
            configRef.current.onMessage(parsedData);
          }
        } catch (err) {
          console.error('Failed to parse MQTT message:', err);
        }
      })
    );

    subscriptions.push(
      eventEmitterRef.current.addListener('MqttDeliveryComplete', (message) => {
        console.log('MQTT Delivery Complete:', message);
      })
    );

    // Cleanup on unmount
    return () => {
      console.log('MqttProvider: Unmounting, cleaning up subscriptions...');
      subscriptions.forEach(sub => sub.remove());

      // Use cleanup if available, otherwise fall back to disconnect
      if (typeof MqttModule.cleanup === 'function') {
        MqttModule.cleanup(() => { }, () => { });
      } else {
        console.log('MqttProvider: Using disconnect as cleanup fallback');
        MqttModule.disconnect(() => { }, () => { });
      }
    };
  }, []);

  const connect = useCallback(async (config) => {
    try {
      configRef.current = config;
      return new Promise((resolve, reject) => {
        MqttModule.connect(
          config.broker,
          config.clientId,
          config.certificates,
          config.sniHostname,
          config.brokerIp,
          config.brokerCommonName,
          (success) => {
            console.log('Connect success:', success);
            resolve(success);
          },
          (error) => {
            console.error('Connect error:', error);
            setError(error);
            if (config.onError) {
              config.onError(error);
            }
            reject(error);
          }
        );
      });
    } catch (err) {
      setError(err.message);
      throw err;
    }
  }, []);

  const disconnect = useCallback(async () => {
    return new Promise((resolve, reject) => {
      MqttModule.disconnect(
        (success) => {
          console.log('Disconnect success:', success);
          setIsConnected(false);
          configRef.current = null;
          resolve(success);
        },
        (error) => {
          console.error('Disconnect error:', error);
          reject(error);
        }
      );
    });
  }, []);

  const subscribe = useCallback(async (topic, qos = 1) => {
    return new Promise((resolve, reject) => {
      MqttModule.subscribe(
        topic,
        qos,
        (success) => {
          console.log('Subscribe success:', success);
          resolve(success);
        },
        (error) => {
          console.error('Subscribe error:', error);
          reject(error);
        }
      );
    });
  }, []);

  const unsubscribe = useCallback(async (topic) => {
    return new Promise((resolve, reject) => {
      MqttModule.unsubscribe(
        topic,
        (success) => {
          console.log('Unsubscribe success:', success);
          resolve(success);
        },
        (error) => {
          console.error('Unsubscribe error:', error);
          reject(error);
        }
      );
    });
  }, []);

  const publish = useCallback(async (topic, message, qos = 1, retained = false) => {
    return new Promise((resolve, reject) => {
      let publishMessage = message;

      // Check if Buffer is available in the environment
      const isBuffer = typeof Buffer !== 'undefined' && Buffer.isBuffer(message);

      // Handle binary data by converting to Base64 for the React Native bridge
      if (message instanceof Uint8Array || message instanceof ArrayBuffer || isBuffer) {
        let bytes;

        if (message instanceof ArrayBuffer) {
          bytes = new Uint8Array(message);
        } else if (isBuffer) {
          bytes = new Uint8Array(message);
        } else {
          bytes = message; // Already Uint8Array
        }

        // Convert to Base64
        let binary = '';
        const len = bytes.byteLength;
        for (let i = 0; i < len; i++) {
          binary += String.fromCharCode(bytes[i]);
        }
        publishMessage = btoa(binary);

        console.log('Publish: Converted binary protobuf to Base64');
        console.log('  - Topic:', topic);
        console.log('  - Original byte length:', len);
        console.log('  - Base64 string length:', publishMessage.length);
      } else if (typeof message !== 'string') {
        publishMessage = JSON.stringify(message);
      }

      MqttModule.publish(
        topic,
        publishMessage,
        qos,
        retained,
        (success) => {
          console.log('Publish success:', success);
          resolve(success);
        },
        (error) => {
          console.error('Publish error:', error);
          reject(error);
        }
      );
    });
  }, []);

  // ⚡ NEW: Auto-reconnect control methods
  const disableAutoReconnect = useCallback(() => {
    if (typeof MqttModule.disableAutoReconnect === 'function') {
      MqttModule.disableAutoReconnect();
      console.log('⚡ Auto-reconnect disabled');
    } else {
      console.warn('disableAutoReconnect not available in native module');
    }
  }, []);

  const enableAutoReconnect = useCallback(() => {
    if (typeof MqttModule.enableAutoReconnect === 'function') {
      MqttModule.enableAutoReconnect();
      console.log('⚡ Auto-reconnect enabled');
    } else {
      console.warn('enableAutoReconnect not available in native module');
    }
  }, []);

  const value = {
    isConnected,
    error,
    connect,
    disconnect,
    subscribe,
    unsubscribe,
    publish,
    disableAutoReconnect, // ⚡ NEW
    enableAutoReconnect,  // ⚡ NEW
  };

  return <MqttContext.Provider value={value}>{children}</MqttContext.Provider>;
};