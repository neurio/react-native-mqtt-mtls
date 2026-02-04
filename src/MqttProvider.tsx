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
    console.log('MqttProvider: Performing initial cleanup...');
    MqttModule.cleanup(
      (success) => {
        console.log('MqttProvider: Initial cleanup successful:', success);
      },
      (error) => {
        console.log('MqttProvider: Cleanup error (non-critical):', error);
      }
    );

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
      MqttModule.cleanup(() => { }, () => { });
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
      MqttModule.publish(
        topic,
        message,
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

  const value = {
    isConnected,
    error,
    connect,
    disconnect,
    subscribe,
    unsubscribe,
    publish,
  };

  return <MqttContext.Provider value={value}>{children}</MqttContext.Provider>;
};