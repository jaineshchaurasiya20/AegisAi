/** @type {import("tailwindcss").Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      colors: {
        navy: {
          950: "#070B14",
          900: "#0A101C",
          850: "#0D1422",
          800: "#111C30",
          700: "#182844",
          600: "#22385C",
        },
        slate: {
          850: "#151F32",
          950: "#090E17",
        },
        cyan: {
          DEFAULT: "#22D3EE",
          400: "#22D3EE",
          500: "#06B6D4",
          600: "#0891B2",
        },
        blue: {
          DEFAULT: "#3B82F6",
          400: "#60A5FA",
          500: "#3B82F6",
          600: "#2563EB",
        },
        emerald: {
          DEFAULT: "#22C55E",
          400: "#4ADE80",
          500: "#22C55E",
        },
        amber: {
          DEFAULT: "#F59E0B",
          400: "#FBBF24",
          500: "#F59E0B",
        },
        red: {
          DEFAULT: "#EF4444",
          400: "#F87171",
          500: "#EF4444",
          600: "#DC2626",
        },
        purple: {
          DEFAULT: "#8B5CF6",
          400: "#A78BFA",
          500: "#8B5CF6",
        }
      },
      fontFamily: {
        sans: ["'Plus Jakarta Sans'", "Inter", "-apple-system", "BlinkMacSystemFont", "Segoe UI", "Roboto", "sans-serif"],
        mono: ["'JetBrains Mono'", "SF Mono", "Fira Code", "monospace"],
      },
      boxShadow: {
        "glass": "0 8px 32px 0 rgba(0, 0, 0, 0.35)",
        "glass-elevated": "0 12px 40px 0 rgba(0, 0, 0, 0.45)",
        "glass-critical": "0 12px 40px -4px rgba(239, 68, 68, 0.25)",
        "cyan-glow": "0 0 20px -4px rgba(34, 211, 238, 0.35)",
        "subtle": "0 2px 10px rgba(0, 0, 0, 0.25)",
      },
      borderRadius: {
        "xs": "4px",
        "sm": "6px",
        "md": "8px",
        "lg": "12px",
        "xl": "14px",
        "2xl": "16px",
      }
    },
  },
  plugins: [],
};