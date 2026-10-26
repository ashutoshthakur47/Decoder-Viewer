/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      // Graphite neutrals for the chrome; colour is reserved for what the decoders did with the log.
      colors: {
        canvas: "#0e0f11",
        surface: "#141518",
        raised: "#1b1d21",
        hover: "#23262b",
        line: "#2c2f35",
        "line-muted": "#1f2126",
        fg: "#ecebe8",
        "fg-soft": "#c9c8c4",
        "fg-muted": "#908f8a",
        "fg-subtle": "#64635f",
        ok: "#72d495", // decoded
        warn: "#e8b75a", // not decoded
        bad: "#f2826f", // broken decoder
        test: "#62c8da", // decoder run alone, outside the tree
      },
      fontFamily: {
        sans: ["IBM Plex Sans", "Segoe UI", "sans-serif"],
        mono: ["IBM Plex Mono", "Cascadia Code", "Consolas", "monospace"],
      },
      keyframes: {
        rise: { from: { opacity: "0", transform: "translateY(6px) scale(0.99)" }, to: { opacity: "1", transform: "none" } },
        fade: { from: { opacity: "0" }, to: { opacity: "1" } },
      },
      animation: {
        rise: "rise 160ms cubic-bezier(0.2, 0.8, 0.2, 1)",
        fade: "fade 120ms ease-out",
      },
    },
  },
  plugins: [],
};
