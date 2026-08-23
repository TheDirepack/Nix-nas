import React from "react";
import {createRoot} from "react-dom/client";
import "@patternfly/patternfly/patternfly.css";
import "@patternfly/patternfly/patternfly-addons.css";
import "./cockpit-dark-theme.js";
import App from "./app.jsx";
import "./app.scss";

const root = document.getElementById("root");
if (!root) throw new Error("Cockpit NAS root element is missing");

createRoot(root).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
