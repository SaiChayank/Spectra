import { StrictMode, type ComponentType } from "react";
import { createRoot } from "react-dom/client";
import App from "./App";
import "./index.css";

async function boot() {
  // Mock mode (`npm run dev:mock`): both flags are compile-time constants, so
  // a production build drops this branch and the mock chunk entirely.
  if (import.meta.env.DEV && import.meta.env.VITE_MOCK === "1") {
    const { installMocks } = await import("./mock/install");
    installMocks();
  }
  // Dev-only component gallery: `#/styleguide` (never in a build).
  let Styleguide: ComponentType | null = null;
  if (import.meta.env.DEV) {
    const onGuide = window.location.hash === "#/styleguide";
    if (onGuide) Styleguide = (await import("./pages/Styleguide")).default;
    // entering or leaving the gallery swaps the whole tree: reload
    window.addEventListener("hashchange", () => {
      if ((window.location.hash === "#/styleguide") !== onGuide) window.location.reload();
    });
  }
  createRoot(document.getElementById("root")!).render(<StrictMode>{Styleguide ? <Styleguide /> : <App />}</StrictMode>);
}

void boot();
