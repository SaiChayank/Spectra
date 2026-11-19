import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// `npm run dev:mock` (vite --mode mock) serves the recorded contract fixtures
// instead of a backend (docs/frontend-mock-mode.md). Same-origin endpoints so
// every /api and /ws request reaches the in-page mock in src/mock/.
const mockEnv = {
  "import.meta.env.VITE_MOCK": JSON.stringify("1"),
  "import.meta.env.VITE_API_BASE": JSON.stringify("http://localhost:5173"),
  "import.meta.env.VITE_WS_URL": JSON.stringify("ws://localhost:5173/ws/events"),
};

export default defineConfig(({ mode }) => ({
  plugins: [react()],
  define: mode === "mock" ? mockEnv : {},
  server: {
    port: 5173,
    strictPort: false,
  },
  test: {
    environment: "jsdom",
  },
}));
