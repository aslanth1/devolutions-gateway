import { emitPlayerTelemetry } from './telemetry';

let beforeClose = (args: CloseEvent): CloseEvent => {
  return args;
};

export const OnBeforeClose = (callback: (args: CloseEvent) => CloseEvent) => {
  beforeClose = callback;
};

const WebSocketProxy = new Proxy(window.WebSocket, {
  construct(target, args: [url: string | URL, protocols?: string | string[]]) {
    const ws = new target(...args); // Create the actual WebSocket instance
    const websocketUrl = args[0].toString();
    let openedAtUnixMs: number | undefined;
    let firstMessageAtUnixMs: number | undefined;
    let transformedCloseDelivered = false;

    const closeElapsedMs = (closedAtUnixMs: number) => {
      if (openedAtUnixMs === undefined) {
        return undefined;
      }

      return Math.max(0, closedAtUnixMs - openedAtUnixMs);
    };

    const recordTransformedClose = (closeEvent: CloseEvent, deliveryKind: string) => {
      if (transformedCloseDelivered) {
        return closeEvent;
      }

      transformedCloseDelivered = true;
      const closedAtUnixMs = Date.now();
      emitPlayerTelemetry({
        kind: 'websocket_close_transformed',
        websocketUrl,
        openedAtUnixMs,
        firstMessageAtUnixMs,
        closedAtUnixMs,
        elapsedMsSinceOpen: closeElapsedMs(closedAtUnixMs),
        transformedCloseCode: closeEvent.code,
        transformedCloseReason: closeEvent.reason || undefined,
        deliveryKind,
      });

      return closeEvent;
    };

    ws.addEventListener('open', () => {
      openedAtUnixMs = Date.now();
      emitPlayerTelemetry({
        kind: 'websocket_open',
        websocketUrl,
        openedAtUnixMs,
      });
    });

    ws.addEventListener('message', () => {
      if (firstMessageAtUnixMs !== undefined) {
        return;
      }

      firstMessageAtUnixMs = Date.now();
      emitPlayerTelemetry({
        kind: 'websocket_first_message',
        websocketUrl,
        openedAtUnixMs,
        firstMessageAtUnixMs,
        elapsedMsSinceOpen: closeElapsedMs(firstMessageAtUnixMs),
      });
    });

    ws.addEventListener('close', (closeEvent) => {
      const closedAtUnixMs = Date.now();
      emitPlayerTelemetry({
        kind: 'websocket_close_raw',
        websocketUrl,
        openedAtUnixMs,
        firstMessageAtUnixMs,
        closedAtUnixMs,
        elapsedMsSinceOpen: closeElapsedMs(closedAtUnixMs),
        rawCloseCode: closeEvent.code,
        rawCloseReason: closeEvent.reason || undefined,
        wasClean: closeEvent.wasClean,
      });
    });

    // Proxy for intercepting `addEventListener`
    ws.addEventListener = new Proxy(ws.addEventListener, {
      apply(target, thisArg, args) {
        if (args[0] === 'close') {
          const [eventName, listener, options] = args;
          if (typeof listener === 'function') {
            const transformedListener = (closeEvent: CloseEvent) => {
              const transformedCloseEvent = recordTransformedClose(
                beforeClose(closeEvent),
                'add_event_listener',
              );
              listener(transformedCloseEvent);
            };
            return target.apply(thisArg, [eventName, transformedListener, options]);
          }
        }
        return target.apply(thisArg, args);
      },
    });

    // Proxy for intercepting `onclose`
    return new Proxy(ws, {
      set(target, prop, value) {
        if (prop === 'onclose') {
          const transformedValue = (...args) => {
            const transformedArgs = recordTransformedClose(
              beforeClose(args[0] as unknown as CloseEvent),
              'onclose',
            );
            if (typeof value === 'function') {
              value(transformedArgs); // Call the original handler
            }
          };
          return Reflect.set(target, prop, transformedValue);
        }
        return Reflect.set(target, prop, value);
      },
      get(target, prop, receiver) {
        const value = Reflect.get(target, prop, receiver);
        // Because these methods are part of the native WebSocket prototype,
        // they must be called with the original WebSocket as `this`.
        // If they're called with the Proxy as `this`, it results in an "illegal invocation".
        // Binding them to the underlying `target` (the real WebSocket) avoids this issue.
        if (typeof value === 'function') {
          return value.bind(target);
        }
        return value;
      },
    });
  },
});

window.WebSocket = WebSocketProxy;
