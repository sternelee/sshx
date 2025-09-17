import { defineConfig } from "vite";
import { sveltekit } from "@sveltejs/kit/vite";

export default defineConfig({
  define: {
    __APP_VERSION__: JSON.stringify("0.4.1"),
  },
  plugins: [sveltekit()],
});
