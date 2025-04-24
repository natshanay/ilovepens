/** @type {import('tailwindcss').Config} */
export default {
    content: [
      './src/pages/**/*.{js,ts,jsx,tsx,mdx}',
      './src/components/**/*.{js,ts,jsx,tsx,mdx}',
      './src/app/**/*.{js,ts,jsx,tsx,mdx}',
    ],
    theme: {
      extend: {
        backgroundImage:{
"home":'url(/images/nata.png)' 
        },
        colors: {
          background: 'url(--background)',
          foreground: 'var(--foreground)',
        },
      },
    },
    plugins: [],
    darkMode: 'class',
  };