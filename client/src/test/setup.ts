// Setup file for Vitest
/* eslint-disable @typescript-eslint/no-explicit-any */

// Polyfill for btoa/atob (browser APIs not available in Node.js)
if (typeof global.btoa === "undefined") {
  global.btoa = (str: string) => Buffer.from(str, "binary").toString("base64");
}

if (typeof global.atob === "undefined") {
  global.atob = (str: string) => Buffer.from(str, "base64").toString("binary");
}

// Mock localStorage for tests
// Initialize storage
if (!(global as any).__localStorage) {
  (global as any).__localStorage = {};
}

const localStorageMock = {
  getItem: (key: string) => {
    return (global as any).__localStorage[key] || null;
  },
  setItem: (key: string, value: string) => {
    (global as any).__localStorage[key] = value;
  },
  removeItem: (key: string) => {
    delete (global as any).__localStorage[key];
  },
  clear: () => {
    (global as any).__localStorage = {};
  },
  get length() {
    return Object.keys((global as any).__localStorage).length;
  },
  key: (index: number) => {
    const keys = Object.keys((global as any).__localStorage);
    return keys[index] || null;
  },
};

// Make localStorage enumerable so Object.keys() works
global.localStorage = new Proxy(localStorageMock as any, {
  ownKeys: () => {
    return Object.keys((global as any).__localStorage);
  },
  getOwnPropertyDescriptor: (target, prop) => {
    if (prop in (global as any).__localStorage) {
      return {
        enumerable: true,
        configurable: true,
        value: (global as any).__localStorage[prop],
      };
    }
    return Object.getOwnPropertyDescriptor(target, prop);
  },
});
