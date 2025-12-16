import type { Config } from 'tailwindcss';

const config: Config = {
  content: [
    './app/**/*.{js,ts,jsx,tsx}',
    './components/**/*.{js,ts,jsx,tsx}'
  ],
  theme: {
    extend: {
      colors: {
        ink: '#0f172a',
        soft: '#111827',
        accent: '#3b82f6',
        glow: '#22d3ee'
      },
      boxShadow: {
        lift: '0 12px 30px -12px rgba(15, 23, 42, 0.25)'
      }
    },
  },
  plugins: [],
};

export default config;
