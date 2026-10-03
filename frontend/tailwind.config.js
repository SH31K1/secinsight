/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        ink: {
          950: "#0A0E14",
          900: "#0D1117",
          800: "#131A24",
          700: "#1B2432",
          600: "#283444",
        },
        signal: {
          500: "#6E62E5",
          400: "#8A80EC",
        },
        severity: {
          critical: "#C4374D",
          high: "#DB6B2C",
          medium: "#C9A227",
          low: "#3C7DD9",
          info: "#5B6472",
        },
      },
      fontFamily: {
        display: ["'Space Grotesk'", "sans-serif"],
        body: ["'Inter'", "sans-serif"],
        mono: ["'IBM Plex Mono'", "monospace"],
      },
      keyframes: {
        scanline: {
          "0%": { transform: "translateY(-100%)" },
          "100%": { transform: "translateY(2000%)" },
        },
      },
      animation: {
        scanline: "scanline 6s linear infinite",
      },
    },
  },
  plugins: [],
};
