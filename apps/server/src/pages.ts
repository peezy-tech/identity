import type { SocialProviderName } from "./config";
import { HOSTED_WALLET_STATEMENT } from "./constants";

export function homePage(): string {
  return document(
    "peezy.tech identity",
    `
      <main>
        <p class="eyebrow">peezy.tech</p>
        <h1>One account across peezy.tech projects.</h1>
        <p class="lede">
          Sign in with a social account, an EVM wallet, or both. Wallets are
          credentials you can add; they are not required to have an account.
        </p>
        <div class="actions">
          <a class="primary" href="/sign-in">Sign in</a>
          <a href="/api/auth/.well-known/openid-configuration">OpenID configuration</a>
        </div>
      </main>
    `,
  );
}

export function accountPage(
  config: {
    privyAppId?: string;
    providers: SocialProviderName[];
  },
  nonce: string,
): string {
  const clientConfig = JSON.stringify({
    privyAppId: config.privyAppId ?? null,
    providers: config.providers,
  }).replaceAll("<", "\\u003c");
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="color-scheme" content="dark">
    <title>Account · peezy.tech</title>
    <style>
      :root { color-scheme: dark; font-family: Inter, ui-sans-serif, system-ui, sans-serif; }
      * { box-sizing: border-box; }
      body { min-height: 100vh; margin: 0; color: #f5f4ef; background: #0c0e0d; }
      body::before { content: ""; position: fixed; inset: 0; pointer-events: none;
        background: radial-gradient(circle at 82% 8%, rgba(185,242,124,.11), transparent 28rem); }
      button, a { font: inherit; }
      .account-shell { position: relative; width: min(74rem, calc(100vw - 2rem)); margin: 0 auto;
        padding: 2rem 0 5rem; }
      .account-nav { display: flex; justify-content: space-between; align-items: center;
        padding-bottom: 1.5rem; border-bottom: 1px solid #272b28; }
      .account-brand { color: #f5f4ef; font-weight: 760; letter-spacing: -.03em; text-decoration: none; }
      .account-kicker { color: #b9f27c; font: 700 .72rem/1 ui-monospace, monospace;
        letter-spacing: .14em; text-transform: uppercase; }
      .account-heading { max-width: 45rem; margin: 4.5rem 0 4rem; }
      .account-heading h1 { margin: .8rem 0 1rem; font-size: clamp(3.2rem, 8vw, 6.8rem);
        line-height: .88; letter-spacing: -.075em; }
      .account-heading p { max-width: 34rem; color: #aeb2ac; font-size: 1.05rem; line-height: 1.65; }
      #account-root { min-height: 24rem; }
      .account-loading { color: #8f948e; border-top: 1px solid #272b28; padding: 1.5rem 0; }
      @media (max-width: 640px) {
        .account-shell { width: min(100% - 1.25rem, 74rem); padding-top: 1.25rem; }
        .account-heading { margin: 3rem 0; }
      }
      @media (prefers-reduced-motion: no-preference) {
        .account-heading { animation: account-enter .45s ease-out both; }
        #account-root { animation: account-enter .45s .08s ease-out both; }
        @keyframes account-enter { from { opacity: 0; transform: translateY(10px); }
          to { opacity: 1; transform: translateY(0); } }
      }
    </style>
  </head>
  <body>
    <div class="account-shell">
      <nav class="account-nav" aria-label="Account navigation">
        <a class="account-brand" href="/">peezy.tech</a>
        <span class="account-kicker">Identity</span>
      </nav>
      <header class="account-heading">
        <span class="account-kicker">Account center</span>
        <h1>Your ways in.</h1>
        <p>Review your credentials, bring over a Lobby account, or consolidate duplicate peezy.tech identities.</p>
      </header>
      <div id="account-root"><p class="account-loading">Loading your identity…</p></div>
    </div>
    <script nonce="${nonce}">window.__PEEZY_ACCOUNT_CONFIG__ = ${clientConfig};</script>
    <script type="module" src="/assets/account-client.js"></script>
  </body>
</html>`;
}

export function signInPage(
  providers: SocialProviderName[],
  nonce: string,
): string {
  const socialButtons = providers
    .map(
      (provider) =>
        `<button type="button" data-provider="${provider}">Continue with ${providerLabel(provider)}</button>`,
    )
    .join("");
  const providersJson = JSON.stringify(providers).replaceAll("<", "\\u003c");
  const walletStatementJson = JSON.stringify(HOSTED_WALLET_STATEMENT);

  return document(
    "Sign in · peezy.tech",
    `
      <main>
        <p class="eyebrow">peezy.tech identity</p>
        <h1>Sign in</h1>
        <p class="lede">Use one identity across every peezy.tech project.</p>
        <div class="stack" id="social-providers">${socialButtons}</div>
        ${providers.length > 0 ? '<p class="divider"><span>or</span></p>' : ""}
        <button class="wallet" id="wallet" type="button">Continue with an EVM wallet</button>
        <button class="wallet" id="solana-wallet" type="button">Continue with a Solana wallet</button>
        <p class="status" id="status" role="status" aria-live="polite"></p>
        <p class="fine-print">
          A wallet is optional. Connecting one proves ownership and links it as
          a credential on your peezy.tech account.
        </p>
      </main>
      <script nonce="${nonce}">
        const providers = ${providersJson};
        const status = document.querySelector("#status");
        const oauthQuery = new URLSearchParams(location.search);
        const requestedReturn = oauthQuery.get("return_to");
        const safeReturn = requestedReturn && requestedReturn.startsWith("/") &&
          !requestedReturn.startsWith("//") ? requestedReturn : "/";
        const callbackURL = oauthQuery.has("client_id")
          ? location.origin + "/api/auth/oauth2/authorize" + location.search
          : location.origin + safeReturn;

        async function jsonRequest(path, body) {
          const response = await fetch(path, {
            method: "POST",
            credentials: "same-origin",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(body),
          });
          const data = await response.json().catch(() => ({}));
          if (!response.ok) {
            throw new Error(data.message || data.error?.message || "Sign-in failed");
          }
          return data;
        }

        async function socialSignIn(provider) {
          status.textContent = "Opening " + provider + "…";
          const result = await jsonRequest("/api/auth/sign-in/social", {
            callbackURL,
            provider,
          });
          if (!result.url) throw new Error("The provider did not return a redirect");
          location.assign(result.url);
        }

        for (const button of document.querySelectorAll("[data-provider]")) {
          button.addEventListener("click", () => {
            socialSignIn(button.dataset.provider).catch(showError);
          });
        }

        document.querySelector("#wallet").addEventListener("click", async () => {
          try {
            if (!window.ethereum) {
              throw new Error("No EVM wallet was detected in this browser");
            }
            status.textContent = "Requesting your wallet…";
            const [address] = await window.ethereum.request({
              method: "eth_requestAccounts",
            });
            const chainHex = await window.ethereum.request({ method: "eth_chainId" });
            const chainId = Number.parseInt(chainHex, 16);
            const nonceResult = await jsonRequest("/api/auth/siwe/nonce", {
              chainId,
              walletAddress: address,
            });
            const issuedAt = new Date().toISOString();
            const expirationTime = new Date(Date.now() + 10 * 60 * 1000).toISOString();
            const message =
              location.host + " wants you to sign in with your Ethereum account:\\n" +
              address + "\\n\\n" + ${walletStatementJson} + "\\n\\nURI: " +
              location.origin + "\\nVersion: 1\\nChain ID: " + chainId +
              "\\nNonce: " + nonceResult.nonce + "\\nIssued At: " + issuedAt +
              "\\nExpiration Time: " + expirationTime;
            const signature = await window.ethereum.request({
              method: "personal_sign",
              params: [message, address],
            });
            status.textContent = "Verifying your wallet…";
            await jsonRequest("/api/auth/siwe/verify", {
              chainId,
              message,
              signature,
              walletAddress: address,
            });
            location.assign(callbackURL);
          } catch (error) {
            showError(error);
          }
        });

        document.querySelector("#solana-wallet").addEventListener("click", async () => {
          try {
            if (!window.solana) {
              throw new Error("No Solana wallet was detected in this browser");
            }
            status.textContent = "Requesting your Solana wallet…";
            const connected = await window.solana.connect();
            const address = connected.publicKey.toString();
            const challenge = await jsonRequest("/api/auth/siws/challenge", {
              address,
            });
            const message = new TextEncoder().encode(challenge.message);
            const signed = await window.solana.signMessage(message);
            if (signed.signedMessage) {
              const exact = signed.signedMessage.length === message.length &&
                signed.signedMessage.every((byte, index) => byte === message[index]);
              if (!exact) throw new Error("The wallet changed the SIWS message before signing");
            }
            let binarySignature = "";
            for (const byte of signed.signature) {
              binarySignature += String.fromCharCode(byte);
            }
            status.textContent = "Verifying your Solana wallet…";
            await jsonRequest("/api/auth/siws/verify", {
              challengeId: challenge.challengeId,
              message: challenge.message,
              signature: btoa(binarySignature),
            });
            location.assign(callbackURL);
          } catch (error) {
            showError(error);
          }
        });

        function showError(error) {
          status.textContent =
            error instanceof Error ? error.message : "Sign-in failed";
        }

        const hintedProvider = new URLSearchParams(location.search).get("login_hint");
        if (hintedProvider && providers.includes(hintedProvider)) {
          socialSignIn(hintedProvider).catch(showError);
        }
      </script>
    `,
    nonce,
  );
}

export function consentPage(nonce: string): string {
  return document(
    "Authorize · peezy.tech",
    `
      <main>
        <p class="eyebrow">peezy.tech identity</p>
        <h1>Authorize this project?</h1>
        <p class="lede">
          The project is requesting the account details listed in the signed
          authorization request.
        </p>
        <div class="actions">
          <button class="primary" id="approve" type="button">Authorize</button>
          <button id="deny" type="button">Cancel</button>
        </div>
        <p class="status" id="status" role="status" aria-live="polite"></p>
      </main>
      <script nonce="${nonce}">
        const status = document.querySelector("#status");
        async function decide(accept) {
          status.textContent = accept ? "Authorizing…" : "Cancelling…";
          const query = new URLSearchParams(location.search);
          const response = await fetch("/api/auth/oauth2/consent", {
            method: "POST",
            credentials: "same-origin",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              accept,
              oauth_query: location.search.slice(1),
              scope: query.get("scope") || undefined,
            }),
          });
          const result = await response.json().catch(() => ({}));
          if (!response.ok || !result.url) {
            throw new Error(result.message || result.error?.message || "Authorization failed");
          }
          location.assign(result.url);
        }
        document.querySelector("#approve").addEventListener("click", () => {
          decide(true).catch((error) => { status.textContent = error.message; });
        });
        document.querySelector("#deny").addEventListener("click", () => {
          decide(false).catch((error) => { status.textContent = error.message; });
        });
      </script>
    `,
    nonce,
  );
}

export function linkSocialPage(
  provider: SocialProviderName,
  callbackUrl: string,
  nonce: string,
): string {
  const providerJson = JSON.stringify(provider);
  const callbackJson = JSON.stringify(callbackUrl).replaceAll("<", "\\u003c");
  return document(
    `Link ${providerLabel(provider)} · peezy.tech`,
    `
      <main>
        <p class="eyebrow">peezy.tech identity</p>
        <h1>Link ${providerLabel(provider)}</h1>
        <p class="lede">
          Continue to ${providerLabel(provider)} to add it as another way to
          sign in to your existing account.
        </p>
        <button class="primary" id="continue" type="button">Continue</button>
        <p class="status" id="status" role="status" aria-live="polite"></p>
      </main>
      <script nonce="${nonce}">
        const provider = ${providerJson};
        const callbackURL = ${callbackJson};
        const status = document.querySelector("#status");
        document.querySelector("#continue").addEventListener("click", async () => {
          try {
            status.textContent = "Opening " + provider + "…";
            const telegram = provider === "telegram";
            const response = await fetch(
              telegram ? "/api/auth/oauth2/link" : "/api/auth/link-social",
              {
                method: "POST",
                credentials: "same-origin",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(
                  telegram
                    ? { callbackURL, providerId: "telegram" }
                    : { callbackURL, provider }
                ),
              }
            );
            const result = await response.json().catch(() => ({}));
            if (!response.ok || !result.url) {
              throw new Error(result.message || result.error?.message || "Linking failed");
            }
            location.assign(result.url);
          } catch (error) {
            status.textContent =
              error instanceof Error ? error.message : "Linking failed";
          }
        });
      </script>
    `,
    nonce,
  );
}

function providerLabel(provider: SocialProviderName): string {
  if (provider === "github") return "GitHub";
  if (provider === "twitter") return "X";
  return `${provider[0]?.toUpperCase() ?? ""}${provider.slice(1)}`;
}

function document(title: string, body: string, nonce?: string): string {
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="color-scheme" content="dark">
    <title>${title}</title>
    <style>
      :root { color-scheme: dark; font-family: Inter, ui-sans-serif, system-ui, sans-serif; }
      * { box-sizing: border-box; }
      body {
        min-height: 100vh; margin: 0; display: grid; place-items: center;
        color: #f7f4ed; background:
          radial-gradient(circle at 12% 14%, #25302a 0, transparent 34rem),
          #0c0e0d;
      }
      main { width: min(35rem, calc(100vw - 2rem)); padding: 3rem 0; }
      .eyebrow { color: #b9f27c; font: 700 .76rem/1 ui-monospace, monospace;
        letter-spacing: .14em; text-transform: uppercase; }
      h1 { margin: .9rem 0 1rem; font-size: clamp(2.5rem, 8vw, 5rem);
        line-height: .94; letter-spacing: -.06em; }
      .lede { max-width: 32rem; color: #bbbdb7; font-size: 1.05rem; line-height: 1.6; }
      .stack { display: grid; gap: .7rem; margin-top: 2rem; }
      .actions { display: flex; flex-wrap: wrap; gap: .7rem; margin-top: 2rem; }
      button, a {
        border: 1px solid #343934; border-radius: 999px; padding: .85rem 1.2rem;
        color: inherit; background: #171a18; font: 650 .95rem/1 inherit;
        text-decoration: none; cursor: pointer; transition: border-color .15s, transform .15s;
      }
      button:hover, a:hover { border-color: #b9f27c; transform: translateY(-1px); }
      .primary { color: #10120f; border-color: #b9f27c; background: #b9f27c; }
      .wallet { width: 100%; }
      .divider { display: flex; align-items: center; gap: 1rem; color: #777c76;
        margin: 1.1rem 0; font-size: .8rem; }
      .divider::before, .divider::after { content: ""; height: 1px; background: #292d29; flex: 1; }
      .status { min-height: 1.5rem; color: #e5c36b; }
      .fine-print { color: #777c76; font-size: .8rem; line-height: 1.5; }
    </style>
  </head>
  <body>${body}</body>
</html>`;
}
