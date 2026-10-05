/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'Segoe UI', 'sans-serif'],
        mono: ['ui-monospace', 'SFMono-Regular', 'Menlo', 'monospace'],
      },
      colors: {
        ink: { 950: '#070b14', 900: '#0b1220', 850: '#101a2e', 800: '#16233c', 700: '#1f3153', 600: '#2b4270' },
        accent: { DEFAULT: '#22d3ee', soft: '#0e7490' },
      },
      keyframes: {
        'fade-in': { '0%': { opacity: '0', transform: 'translateY(-4px)' }, '100%': { opacity: '1', transform: 'none' } },
        'pulse-ring': { '0%': { boxShadow: '0 0 0 0 rgba(239,68,68,.5)' }, '70%': { boxShadow: '0 0 0 10px rgba(239,68,68,0)' }, '100%': { boxShadow: '0 0 0 0 rgba(239,68,68,0)' } },
      },
      animation: { 'fade-in': 'fade-in .25s ease-out', 'pulse-ring': 'pulse-ring 1.6s ease-out 2' },
    },
  },
  plugins: [],
}
