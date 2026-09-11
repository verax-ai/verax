import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "./App.tsx";
import { restoreAddress } from "./session.ts";
import "./style.css";

// Before the first render, not after: which tab opens and which seat is
// focused are read off the address as the app mounts.
restoreAddress();

const root = document.getElementById("root");
if (!root) throw new Error("missing-root");
createRoot(root).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
