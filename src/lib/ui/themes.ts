export interface IWTermTheme {
  foreground: string;
  background: string;
  cursor: string;
  black: string;
  red: string;
  green: string;
  yellow: string;
  blue: string;
  magenta: string;
  cyan: string;
  white: string;
  brightBlack: string;
  brightRed: string;
  brightGreen: string;
  brightYellow: string;
  brightBlue: string;
  brightMagenta: string;
  brightCyan: string;
  brightWhite: string;
}

export function themeToCssVars(theme: IWTermTheme): string {
  const t = theme;
  return [
    `--term-fg: ${t.foreground}`,
    `--term-bg: ${t.background}`,
    `--term-cursor: ${t.cursor}`,
    `--term-color-0: ${t.black}`,
    `--term-color-1: ${t.red}`,
    `--term-color-2: ${t.green}`,
    `--term-color-3: ${t.yellow}`,
    `--term-color-4: ${t.blue}`,
    `--term-color-5: ${t.magenta}`,
    `--term-color-6: ${t.cyan}`,
    `--term-color-7: ${t.white}`,
    `--term-color-8: ${t.brightBlack}`,
    `--term-color-9: ${t.brightRed}`,
    `--term-color-10: ${t.brightGreen}`,
    `--term-color-11: ${t.brightYellow}`,
    `--term-color-12: ${t.brightBlue}`,
    `--term-color-13: ${t.brightMagenta}`,
    `--term-color-14: ${t.brightCyan}`,
    `--term-color-15: ${t.brightWhite}`,
  ].join("; ");
}

export function applyTheme(el: HTMLElement, theme: IWTermTheme) {
  const t = theme;
  el.style.setProperty("--term-fg", t.foreground);
  el.style.setProperty("--term-bg", t.background);
  el.style.setProperty("--term-cursor", t.cursor);
  el.style.setProperty("--term-color-0", t.black);
  el.style.setProperty("--term-color-1", t.red);
  el.style.setProperty("--term-color-2", t.green);
  el.style.setProperty("--term-color-3", t.yellow);
  el.style.setProperty("--term-color-4", t.blue);
  el.style.setProperty("--term-color-5", t.magenta);
  el.style.setProperty("--term-color-6", t.cyan);
  el.style.setProperty("--term-color-7", t.white);
  el.style.setProperty("--term-color-8", t.brightBlack);
  el.style.setProperty("--term-color-9", t.brightRed);
  el.style.setProperty("--term-color-10", t.brightGreen);
  el.style.setProperty("--term-color-11", t.brightYellow);
  el.style.setProperty("--term-color-12", t.brightBlue);
  el.style.setProperty("--term-color-13", t.brightMagenta);
  el.style.setProperty("--term-color-14", t.brightCyan);
  el.style.setProperty("--term-color-15", t.brightWhite);
}

type ThemeName = keyof typeof themes;
const themes = {
  "VS Code Dark": {
    foreground: "#d8d8d8",
    background: "#181818",
    cursor: "#d8d8d8",
    black: "#181818",
    red: "#ab4642",
    green: "#a1b56c",
    yellow: "#f7ca88",
    blue: "#7cafc2",
    magenta: "#ba8baf",
    cyan: "#86c1b9",
    white: "#d8d8d8",
    brightBlack: "#585858",
    brightRed: "#ab4642",
    brightGreen: "#a1b56c",
    brightYellow: "#f7ca88",
    brightBlue: "#7cafc2",
    brightMagenta: "#ba8baf",
    brightCyan: "#86c1b9",
    brightWhite: "#f8f8f8",
  } satisfies IWTermTheme,
  Hybrid: {
    foreground: "#c5c8c6",
    background: "#1d1f21",
    cursor: "#c5c8c6",
    black: "#282a2e",
    red: "#a54242",
    green: "#8c9440",
    yellow: "#de935f",
    blue: "#5f819d",
    magenta: "#85678f",
    cyan: "#5e8d87",
    white: "#707880",
    brightBlack: "#373b41",
    brightRed: "#cc6666",
    brightGreen: "#b5bd68",
    brightYellow: "#f0c674",
    brightBlue: "#81a2be",
    brightMagenta: "#b294bb",
    brightCyan: "#8abeb7",
    brightWhite: "#c5c8c6",
  } satisfies IWTermTheme,
  "Rosé Pine": {
    foreground: "#e0def4",
    background: "#191724",
    cursor: "#524f67",
    black: "#26233a",
    red: "#eb6f92",
    green: "#31748f",
    yellow: "#f6c177",
    blue: "#9ccfd8",
    magenta: "#c4a7e7",
    cyan: "#ebbcba",
    white: "#e0def4",
    brightBlack: "#6e6a86",
    brightRed: "#eb6f92",
    brightGreen: "#31748f",
    brightYellow: "#f6c177",
    brightBlue: "#9ccfd8",
    brightMagenta: "#c4a7e7",
    brightCyan: "#ebbcba",
    brightWhite: "#e0def4",
  } satisfies IWTermTheme,
  Ubuntu: {
    foreground: "#eeeeec",
    background: "#300a24",
    cursor: "#eeeeec",
    black: "#2e3436",
    red: "#cc0000",
    green: "#4e9a06",
    yellow: "#c4a000",
    blue: "#3465a4",
    magenta: "#75507b",
    cyan: "#06989a",
    white: "#d3d7cf",
    brightBlack: "#555753",
    brightRed: "#ef2929",
    brightGreen: "#8ae234",
    brightYellow: "#fce94f",
    brightBlue: "#729fcf",
    brightMagenta: "#ad7fa8",
    brightCyan: "#34e2e2",
    brightWhite: "#eeeeec",
  } satisfies IWTermTheme,
  Dracula: {
    foreground: "#f8f8f2",
    background: "#282a36",
    cursor: "#f8f8f2",
    black: "#000000",
    red: "#ff5555",
    green: "#50fa7b",
    yellow: "#f1fa8c",
    blue: "#bd93f9",
    magenta: "#ff79c6",
    cyan: "#8be9fd",
    white: "#bbbbbb",
    brightBlack: "#555555",
    brightRed: "#ff5555",
    brightGreen: "#50fa7b",
    brightYellow: "#f1fa8c",
    brightBlue: "#caa9fa",
    brightMagenta: "#ff79c6",
    brightCyan: "#8be9fd",
    brightWhite: "#ffffff",
  } satisfies IWTermTheme,
  "GitHub Dark": {
    foreground: "#d1d5da",
    background: "#24292e",
    cursor: "#d1d5da",
    black: "#586069",
    red: "#ea4a5a",
    green: "#34d058",
    yellow: "#ffea7f",
    blue: "#2188ff",
    magenta: "#b392f0",
    cyan: "#39c5cf",
    white: "#d1d5da",
    brightBlack: "#959da5",
    brightRed: "#f97583",
    brightGreen: "#85e89d",
    brightYellow: "#ffea7f",
    brightBlue: "#79b8ff",
    brightMagenta: "#b392f0",
    brightCyan: "#56d4dd",
    brightWhite: "#fafbfc",
  } satisfies IWTermTheme,
  "Gruvbox Dark": {
    foreground: "#ebdbb2",
    background: "#282828",
    cursor: "#ebdbb2",
    black: "#282828",
    red: "#cc241d",
    green: "#98971a",
    yellow: "#d79921",
    blue: "#458588",
    magenta: "#b16286",
    cyan: "#689d6a",
    white: "#a89984",
    brightBlack: "#928374",
    brightRed: "#fb4934",
    brightGreen: "#b8bb26",
    brightYellow: "#fabd2f",
    brightBlue: "#83a598",
    brightMagenta: "#d3869b",
    brightCyan: "#8ec07c",
    brightWhite: "#ebdbb2",
  } satisfies IWTermTheme,
  "Solarized Dark": {
    foreground: "#839496",
    background: "#002b36",
    cursor: "#839496",
    black: "#073642",
    red: "#dc322f",
    green: "#859900",
    yellow: "#b58900",
    blue: "#268bd2",
    magenta: "#d33682",
    cyan: "#2aa198",
    white: "#eee8d5",
    brightBlack: "#002b36",
    brightRed: "#cb4b16",
    brightGreen: "#586e75",
    brightYellow: "#657b83",
    brightBlue: "#839496",
    brightMagenta: "#6c71c4",
    brightCyan: "#93a1a1",
    brightWhite: "#fdf6e3",
  } satisfies IWTermTheme,
  "Tokyo Night": {
    foreground: "#a9b1d6",
    background: "#1a1b26",
    cursor: "#a9b1d6",
    black: "#32344a",
    red: "#f7768e",
    green: "#9ece6a",
    yellow: "#e0af68",
    blue: "#7aa2f7",
    magenta: "#ad8ee6",
    cyan: "#449dab",
    white: "#787c99",
    brightBlack: "#444b6a",
    brightRed: "#ff7a93",
    brightGreen: "#b9f27c",
    brightYellow: "#ff9e64",
    brightBlue: "#7da6ff",
    brightMagenta: "#bb9af7",
    brightCyan: "#0db9d7",
    brightWhite: "#acb0d0",
  } satisfies IWTermTheme,
};

export type { ThemeName };

export const defaultTheme: ThemeName = "VS Code Dark";

export default themes;
