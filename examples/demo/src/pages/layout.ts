/**
 * Shared layout — navigation bar + footer for all pages.
 */

export type Page = 'home' | 'learn' | 'try' | 'privacy' | 'terms';

const GITHUB_URL = 'https://github.com/nobak-net/stellar-zklogin';

const githubIcon = `<a href="${GITHUB_URL}" target="_blank" class="nav-github" aria-label="GitHub">
  <svg width="20" height="20" viewBox="0 0 16 16" fill="currentColor">
    <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"/>
  </svg>
</a>`;

export function layout(opts: {
  title: string;
  activePage: Page;
  googleClientId?: string;
  headExtra?: string;
  bodyEnd?: string;
  bodyClass?: string;
  content: string;
}): string {
  const nav = (page: Page, href: string, label: string) =>
    `<a href="${href}" class="nav-link${opts.activePage === page ? ' active' : ''}">${label}</a>`;

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${opts.title} — Stellar ZK Login</title>
  <link rel="stylesheet" href="/radix-themes.css">
  <link rel="stylesheet" href="/style.css">
  ${opts.headExtra || ''}
</head>
<body class="radix-themes dark${opts.bodyClass ? ' ' + opts.bodyClass : ''}" data-is-root-theme="true" data-accent-color="sky" data-radius="medium" data-scaling="100%">
  <nav class="nav">
    <div class="nav-inner">
      <a href="/" class="nav-brand">Stellar ZK Login</a>
      <div class="nav-links">
        ${nav('home', '/', 'Home')}
        ${nav('learn', '/learn', 'Learn')}
        ${nav('try', '/try', 'Try It')}
        ${githubIcon}
      </div>
    </div>
  </nav>

  <main class="main">
    ${opts.content}
  </main>

  <footer class="site-footer">
    <div class="container">
      <p>
        <a href="${GITHUB_URL}" target="_blank">Source</a> &middot;
        Circuit: identity_attestation (2,295 constraints) &middot;
        Curve: BN254 &middot;
        Protocol: Groth16 &middot;
        Network: Soroban Testnet
      </p>
      <p style="margin-top: 0.5rem; font-size: 0.75rem;">
        <a href="/privacy">Privacy Policy</a> &middot;
        <a href="/terms">Terms of Service</a>
      </p>
    </div>
  </footer>

  ${opts.bodyEnd || ''}
</body>
</html>`;
}
