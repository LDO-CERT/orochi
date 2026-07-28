/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    './orochi/templates/**/*.html',
    './orochi/website/templates/**/*.html',
    './orochi/users/templates/**/*.html',
    './orochi/**/*.py',
    './orochi/static/js/components.js',
  ],
  darkMode: 'class',
  theme: {
    extend: {},
  },
  plugins: [],
}
