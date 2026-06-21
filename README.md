# MlinziPesa demo

Working demo for the MlinziPesa proposal — SMS smishing scanner, forensic
ledger (hash chain), owner dashboard, and architecture diagrams. Built with
React + Vite.

## Run it locally

You need [Node.js](https://nodejs.org) installed (v18 or later).

```bash
npm install
npm run dev
```

Then open the URL it prints (usually `http://localhost:5173`) in your browser.

## Build for sharing

```bash
npm run build
```

This creates a `dist/` folder with a static site you can host anywhere
(GitHub Pages, Netlify, Vercel, or just zip and share the folder).

## Project structure

```
mlinzipesa-vscode/
├── index.html        entry HTML page
├── package.json       dependencies and scripts
├── vite.config.js     build tool config
└── src/
    ├── main.jsx        mounts the app into index.html
    └── App.jsx         the whole demo (all 4 tabs live here)
```

## Notes on the demo

- The SMS scanner uses pre-labeled sample messages, not a live NLP model.
- The ledger's hash chain uses a simple illustrative hash function, not a
  cryptographic one (like SHA-256). Good for showing the *concept* of an
  immutable chain in a presentation — not for production security.
- All data (transactions, alerts, stats) is hardcoded sample data for the demo.

To extend this into a real system, the natural next steps would be: swap the
sample SMS list for a real on-device NLP classifier, replace the simple hash
with SHA-256 (the browser's built-in `crypto.subtle.digest` can do this),
and connect the verification module to an actual mobile operator API sandbox.
