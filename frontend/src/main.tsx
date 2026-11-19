import { MotionConfig } from "motion/react";
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
  // Dev-only previews (never in a build): `#/styleguide` (component gallery)
  // and `#/styleguide/landing` (the public landing while signed in).
  let Preview: ComponentType | null = null;
  if (import.meta.env.DEV) {
    const hash = window.location.hash;
    const onPreview = hash.startsWith("#/styleguide");
    if (hash === "#/styleguide") Preview = (await import("./pages/Styleguide")).default;
    else if (hash === "#/styleguide/landing") Preview = (await import("./components/Landing")).default;
    // entering, leaving or switching a preview swaps the whole tree: reload
    window.addEventListener("hashchange", () => {
      if (onPreview || window.location.hash.startsWith("#/styleguide")) window.location.reload();
    });
  }
  createRoot(document.getElementById("root")!).render(
    <StrictMode>
      {/* every motion animation honours the OS "reduce motion" setting */}
      <MotionConfig reducedMotion="user">{Preview ? <Preview /> : <App />}</MotionConfig>
    </StrictMode>,
  );
}

void boot();
