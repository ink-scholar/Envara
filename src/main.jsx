import React from "react";
import { createRoot } from "react-dom/client";
import { App } from "./App.jsx";
import { I18nProvider } from "./i18n.jsx";
import { AppearanceProvider } from "./appearance.jsx";
import { api } from "./client.js";
import "./styles.css";

createRoot(document.getElementById("root")).render(
  <React.StrictMode>
    <AppearanceProvider api={api}><I18nProvider api={api}><App /></I18nProvider></AppearanceProvider>
  </React.StrictMode>,
);
