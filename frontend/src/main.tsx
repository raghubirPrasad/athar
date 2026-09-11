import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import App from "./App";
import { APP_NAME } from "./branding";
import "./index.css";

document.title = APP_NAME;

const container = document.getElementById("root");
if (!container) throw new Error("#root is missing from index.html");

createRoot(container).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
