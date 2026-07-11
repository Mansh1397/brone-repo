import React from "react";
import ReactDOM from "react-dom/client";
import { AppShell } from "./components/layout/AppShell";
import "./index.css";

import { Buffer } from 'buffer';
if (typeof window !== 'undefined' && !window.Buffer) {
  window.Buffer = Buffer;
}

// Function to handle conditional MSW initialization
async function prepareApp() {
  // Only start mocks in development environment
  if (process.env.NODE_ENV === 'development' || import.meta.env.DEV) {
    // 🔕 Commented out to let traffic hit your live local gateway & DB:
    // const { worker } = await import("./mocks/browser");
    // return worker.start({
    //   onUnhandledRequest: "bypass", 
    // });
  }
  return Promise.resolve();
}

const rootEl = document.getElementById("root");

if (rootEl) {
  const root = ReactDOM.createRoot(rootEl);

  // Wait for MSW to intercept the network before mounting the UI
  prepareApp().then(() => {
    root.render(
      <React.StrictMode>
        <AppShell />
      </React.StrictMode>
    );
  });
}