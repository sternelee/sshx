import { execSync } from "child_process";
import { defineConfig, searchForWorkspaceRoot } from "vite";
import { sveltekit } from "@sveltejs/kit/vite";
import wasm from "vite-plugin-wasm";
import topLevelAwait from "vite-plugin-top-level-await";

const commitHash = execSync("git rev-parse --short HEAD").toString().trim();

export default defineConfig({
  define: {
    __APP_VERSION__: JSON.stringify("0.4.1-" + commitHash),
  },

  plugins: [sveltekit(), wasm(), topLevelAwait()],

  server: {
    fs: {
      allow: [
        // search up for workspace root
        searchForWorkspaceRoot(process.cwd()),
        // your custom rules
        // "/path/to/custom/allow_directory",
        // "/path/to/custom/allow_file.demo",
      ],
    },
    proxy: {
      "/api": {
        target: "http://[::1]:8051",
        changeOrigin: true,
        ws: true,
      },
    },
  },
});
