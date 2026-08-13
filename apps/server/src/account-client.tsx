import React, { useEffect, useState } from "react";
import { createRoot } from "react-dom/client";

import {
  isSignInCredential,
  linkedSocialProviders,
} from "./account-client-credentials";
import { selectEthereumAccount } from "./account-client-wallet";

type Provider = "apple" | "discord" | "github" | "telegram" | "twitter";
type AccountConfig = { providers: Provider[] };
type Credential = {
  address?: string;
  family?: "evm" | "solana";
  kind: "email" | "social" | "wallet" | "passkey";
  provider?: Provider;
  signInEnabled?: boolean;
  value?: string;
  verified?: boolean;
};
type Identity = {
  credentials: Credential[];
  user: {
    avatarUrl?: string;
    createdAt: string;
    displayName?: string;
    handle?: string;
    id: string;
    primaryEmail?: { value: string; verified: boolean };
  };
};
type MergePreview = {
  attemptId: string;
  source: {
    credentialCount: number;
    credentialKinds: string[];
    displayName?: string;
  };
};

declare global {
  interface Window {
    __PEEZY_ACCOUNT_CONFIG__: AccountConfig;
    solana?: InjectedSolanaProvider;
  }
}

type EthereumProvider = {
  request(input: { method: string; params?: unknown[] }): Promise<unknown>;
};
type SolanaSigner = {
  address: string;
  signMessage(input: { message: Uint8Array }): Promise<{
    signature: Uint8Array;
    signedMessage?: Uint8Array;
  }>;
};
type InjectedSolanaProvider = {
  connect(): Promise<{ publicKey: { toString(): string } }>;
  publicKey?: { toString(): string };
  signMessage(message: Uint8Array): Promise<{
    signature: Uint8Array;
    signedMessage?: Uint8Array;
  }>;
};
const ethereum = () =>
  (window as unknown as { ethereum?: EthereumProvider }).ethereum;

const config = window.__PEEZY_ACCOUNT_CONFIG__;

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : "Identity request failed";
}

function providerLabel(provider: Provider): string {
  return {
    apple: "Apple",
    discord: "Discord",
    github: "GitHub",
    telegram: "Telegram",
    twitter: "X",
  }[provider];
}

async function requestJson<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, {
    credentials: "same-origin",
    ...init,
    headers: { "Content-Type": "application/json", ...init?.headers },
  });
  const result = (await response.json().catch(() => ({}))) as {
    error?: { code?: string; message?: string };
  };
  if (!response.ok) {
    const error = new Error(
      result.error?.message ?? "Identity request failed",
    ) as Error & { code?: string };
    if (result.error?.code !== undefined) error.code = result.error.code;
    throw error;
  }
  return result as T;
}

function AccountApp() {
  const [identity, setIdentity] = useState<Identity | null>(null);
  const [identityError, setIdentityError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [notice, setNotice] = useState<string>("");
  const [mergePreview, setMergePreview] = useState<MergePreview | null>(null);
  const [profileHandle, setProfileHandle] = useState("");
  const [profileName, setProfileName] = useState("");

  async function refreshIdentity() {
    try {
      const nextIdentity = await requestJson<Identity>("/v1/me");
      setIdentity(nextIdentity);
      setIdentityError(null);
      setProfileHandle(nextIdentity.user.handle ?? "");
      setProfileName(nextIdentity.user.displayName ?? "");
    } catch (error) {
      setIdentityError(errorMessage(error));
      throw error;
    }
  }

  async function refresh() {
    await refreshIdentity();
  }

  useEffect(() => {
    refreshIdentity().catch(() => undefined);
    if (new URLSearchParams(location.search).get("merge") === "proof") {
      setBusy("merge-proof");
      requestJson<MergePreview>("/v1/account-merges/proofs", {
        method: "POST",
        body: "{}",
      })
        .then((preview) => {
          setMergePreview(preview);
          history.replaceState({}, "", "/account");
        })
        .catch((error: Error & { code?: string }) => {
          if (error.code === "reauth_required") {
            requestJson("/api/auth/sign-out", { method: "POST", body: "{}" })
              .catch(() => undefined)
              .finally(() =>
                location.assign(
                  "/sign-in?return_to=%2Faccount%3Fmerge%3Dproof",
                ),
              );
            return;
          }
          showError(error);
        })
        .finally(() => setBusy(null));
    }
  }, []);

  function showError(error: unknown) {
    setNotice(errorMessage(error));
  }

  async function saveProfile(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (identity === null) return;
    setBusy("profile");
    setNotice("");
    try {
      const nextIdentity = await requestJson<Identity>("/v1/account/profile", {
        method: "POST",
        body: JSON.stringify({
          displayName: profileName,
          ...(identity.user.handle === undefined
            ? { handle: profileHandle }
            : {}),
        }),
      });
      setIdentity(nextIdentity);
      setProfileHandle(nextIdentity.user.handle ?? "");
      setProfileName(nextIdentity.user.displayName ?? "");
      setNotice("Profile saved.");
      const returnTo = oidcReturnPath();
      if (nextIdentity.user.handle !== undefined && returnTo !== undefined) {
        location.assign(
          `/oidc/resume?return_to=${encodeURIComponent(returnTo)}`,
        );
      }
    } catch (error) {
      showError(error);
    } finally {
      setBusy(null);
    }
  }

  function oidcReturnPath(): string | undefined {
    const value = new URLSearchParams(location.search).get("return_to");
    if (value === null || !value.startsWith("/api/auth/oauth2/authorize?")) {
      return undefined;
    }
    return value;
  }

  async function signOut() {
    setBusy("sign-out");
    setNotice("");
    try {
      await requestJson("/api/auth/sign-out", {
        method: "POST",
        body: "{}",
      });
      location.replace("/sign-in?return_to=%2Faccount");
    } catch (error) {
      showError(error);
      setBusy(null);
    }
  }

  function linkSocial(provider: Provider) {
    const callback = `${location.origin}/account`;
    location.assign(
      `/link-social?provider=${provider}&callback_url=${encodeURIComponent(callback)}`,
    );
  }

  async function linkWallet() {
    const walletProvider = ethereum();
    if (!walletProvider)
      throw new Error("No EVM wallet was detected in this browser");
    const accounts = (await walletProvider.request({
      method: "eth_requestAccounts",
    })) as string[];
    const address = selectEthereumAccount(accounts);
    if (!address) {
      throw new Error("No wallet account was selected");
    }
    const chainHex = (await walletProvider.request({
      method: "eth_chainId",
    })) as string;
    const challenge = await requestJson<{
      challengeId: string;
      message: string;
    }>("/v1/account/wallet/challenges", {
      method: "POST",
      body: JSON.stringify({ address, chainId: Number.parseInt(chainHex, 16) }),
    });
    const signature = (await walletProvider.request({
      method: "personal_sign",
      params: [challenge.message, address],
    })) as string;
    await requestJson("/v1/account/wallet/verify", {
      method: "POST",
      body: JSON.stringify({ ...challenge, signature }),
    });
    await refresh();
    setNotice("Wallet verified and linked.");
  }

  async function linkSolanaWallet() {
    const wallet = await injectedSolanaSigner();
    const challenge = await requestJson<{
      challengeId: string;
      message: string;
    }>("/v1/account/wallet/challenges", {
      method: "POST",
      body: JSON.stringify({ address: wallet.address, family: "solana" }),
    });
    const message = new TextEncoder().encode(challenge.message);
    const signed = await wallet.signMessage({ message });
    requireExactSignedMessage(message, signed.signedMessage);
    await requestJson("/v1/account/wallet/verify", {
      method: "POST",
      body: JSON.stringify({
        ...challenge,
        signature: bytesToBase64(signed.signature),
      }),
    });
    await refresh();
    setNotice("Solana wallet verified and linked.");
  }

  function proveSocial(provider: Provider) {
    setBusy(`proof-${provider}`);
    requestJson<{ url?: string }>("/api/proof-auth/sign-in/social", {
      method: "POST",
      body: JSON.stringify({
        callbackURL: `${location.origin}/account?merge=proof`,
        provider,
      }),
    })
      .then((result) => {
        if (!result.url)
          throw new Error("Provider did not return an authentication URL");
        location.assign(result.url);
      })
      .catch(showError)
      .finally(() => setBusy(null));
  }

  async function proveWallet() {
    const walletProvider = ethereum();
    if (!walletProvider)
      throw new Error("No EVM wallet was detected in this browser");
    const [address] = (await walletProvider.request({
      method: "eth_requestAccounts",
    })) as string[];
    const chainHex = (await walletProvider.request({
      method: "eth_chainId",
    })) as string;
    const chainId = Number.parseInt(chainHex, 16);
    const nonce = await requestJson<{ nonce: string }>(
      "/api/proof-auth/siwe/nonce",
      {
        method: "POST",
        body: JSON.stringify({ chainId, walletAddress: address }),
      },
    );
    const issuedAt = new Date().toISOString();
    const expirationTime = new Date(Date.now() + 10 * 60_000).toISOString();
    const message = `${location.host} wants you to sign in with your Ethereum account:\n${address}\n\nSign in to peezy.tech identity.\n\nURI: ${location.origin}\nVersion: 1\nChain ID: ${chainId}\nNonce: ${nonce.nonce}\nIssued At: ${issuedAt}\nExpiration Time: ${expirationTime}`;
    const signature = (await walletProvider.request({
      method: "personal_sign",
      params: [message, address],
    })) as string;
    await requestJson("/api/proof-auth/siwe/verify", {
      method: "POST",
      body: JSON.stringify({
        chainId,
        message,
        signature,
        walletAddress: address,
      }),
    });
    location.assign("/account?merge=proof");
  }

  async function proveSolanaWallet() {
    const wallet = await injectedSolanaSigner();
    const challenge = await requestJson<{
      challengeId: string;
      message: string;
    }>("/api/proof-auth/siws/challenge", {
      method: "POST",
      body: JSON.stringify({ address: wallet.address }),
    });
    const message = new TextEncoder().encode(challenge.message);
    const signed = await wallet.signMessage({ message });
    requireExactSignedMessage(message, signed.signedMessage);
    await requestJson("/api/proof-auth/siws/verify", {
      method: "POST",
      body: JSON.stringify({
        ...challenge,
        signature: bytesToBase64(signed.signature),
      }),
    });
    location.assign("/account?merge=proof");
  }

  async function commitMerge() {
    if (!mergePreview) return;
    setBusy("merge-commit");
    try {
      await requestJson("/v1/account-merges/commit", {
        method: "POST",
        body: JSON.stringify({ attemptId: mergePreview.attemptId }),
      });
      location.assign("/sign-in?return_to=%2Faccount");
    } catch (error) {
      showError(error);
      setBusy(null);
    }
  }

  if (!identity) {
    if (identityError) {
      return (
        <>
          <style>{styles}</style>
          <section className="account-error" aria-live="polite">
            <strong>We could not load your peezy.tech account.</strong>
            <p>{identityError}</p>
            <div className="button-row">
              <button
                className="quiet"
                onClick={() => refreshIdentity().catch(() => undefined)}
              >
                Try again
              </button>
              <a
                className="quiet link-button"
                href="/sign-in?return_to=%2Faccount"
              >
                Sign in again
              </a>
            </div>
          </section>
        </>
      );
    }
    return (
      <>
        <style>{styles}</style>
        <p className="account-loading">Loading your peezy.tech account…</p>
      </>
    );
  }
  const linkedProviders = linkedSocialProviders(identity.credentials);
  const signInCredentials = identity.credentials.filter(isSignInCredential);
  return (
    <>
      <style>{styles}</style>
      {notice ? (
        <p className="notice" role="status" aria-live="polite">
          {notice}
        </p>
      ) : null}
      <section className="ledger" aria-labelledby="current-account">
        <div className="section-intro">
          <span>01</span>
          <div>
            <h2 id="current-account">Profile</h2>
            <p>This is the information attached to your peezy.tech account.</p>
          </div>
        </div>
        <div className="account-summary">
          <div className="avatar" aria-hidden="true">
            {identity.user.avatarUrl ? (
              <img alt="" src={identity.user.avatarUrl} />
            ) : (
              (identity.user.displayName ?? "P").slice(0, 1).toUpperCase()
            )}
          </div>
          <div>
            <strong>
              {identity.user.displayName ??
                identity.user.primaryEmail?.value ??
                "peezy.tech account"}
            </strong>
            <span>
              {identity.user.handle === undefined
                ? "Signed in to peezy.tech Identity"
                : `@${identity.user.handle}`}
            </span>
          </div>
        </div>
        <form className="profile-form" onSubmit={saveProfile}>
          <label htmlFor="display-name">Display name</label>
          <div className="field-row">
            <input
              id="display-name"
              maxLength={128}
              onChange={(event) => setProfileName(event.target.value)}
              required
              value={profileName}
            />
            <button
              className="save"
              disabled={busy !== null || profileName.trim().length === 0}
              type="submit"
            >
              {busy === "profile" ? "Saving…" : "Save profile"}
            </button>
          </div>
          <label htmlFor="peezy-handle">peezy.tech handle</label>
          <div className="field-row">
            <input
              autoCapitalize="none"
              autoCorrect="off"
              disabled={busy !== null || identity.user.handle !== undefined}
              id="peezy-handle"
              maxLength={32}
              minLength={3}
              onChange={(event) => setProfileHandle(event.target.value)}
              pattern="[a-z][a-z0-9-]{1,30}[a-z0-9]"
              placeholder="peezy"
              required={identity.user.handle === undefined}
              spellCheck={false}
              value={profileHandle}
            />
          </div>
          <small className="handle-note">
            {identity.user.handle === undefined
              ? "Your global handle becomes permanent when you save it. Jojo Build and other peezy.tech products may use it in profile URLs."
              : "Global handle · permanent · shared with connected peezy.tech products"}
          </small>
          <div className="profile-metadata">
            <div>
              <span>Email</span>
              <strong>
                {identity.user.primaryEmail?.value ?? "No email attached"}
              </strong>
              <small>
                {identity.user.primaryEmail
                  ? identity.user.primaryEmail.verified
                    ? "Verified · read only"
                    : "Unverified · read only"
                  : "Wallet-only account"}
              </small>
            </div>
            <div>
              <span>Account ID</span>
              <code>{identity.user.id}</code>
              <small>Stable across linked sign-in methods</small>
            </div>
          </div>
          <button
            className="sign-out"
            disabled={busy !== null}
            onClick={signOut}
            type="button"
          >
            Sign out of peezy.tech
          </button>
        </form>
      </section>

      <section className="ledger" aria-labelledby="sign-in-methods">
        <div className="section-intro">
          <span>02</span>
          <div>
            <h2 id="sign-in-methods">Sign-in methods</h2>
            <p>Every method below opens this same peezy.tech account.</p>
          </div>
        </div>
        <div className="credential-list">
          {signInCredentials.length > 0 ? (
            signInCredentials.map((credential, index) => (
              <div className="credential" key={`${credential.kind}-${index}`}>
                <span>
                  {credential.kind === "wallet" && credential.family
                    ? `${credential.family} wallet`
                    : credential.kind === "social" && credential.provider
                      ? providerLabel(credential.provider)
                      : credential.kind}
                </span>
                <strong>
                  {credential.address ??
                    credential.value ??
                    (credential.provider
                      ? `${providerLabel(credential.provider)} account`
                      : "credential")}
                </strong>
                <small>
                  {credential.kind === "wallet" &&
                  credential.signInEnabled === false
                    ? "Linked · sign-in disabled"
                    : "Can sign in"}
                </small>
              </div>
            ))
          ) : (
            <p className="credential-empty">No sign-in methods are linked.</p>
          )}
        </div>
        <div className="add-methods">
          <strong>Add another sign-in method</strong>
          <p className="muted">
            Linking another method gives you another way back into this account.
          </p>
          <div className="button-row">
            {config.providers.map((provider) => (
              <button
                className="quiet"
                disabled={busy !== null || linkedProviders.has(provider)}
                key={provider}
                onClick={() => linkSocial(provider)}
              >
                {linkedProviders.has(provider)
                  ? `${providerLabel(provider)} linked`
                  : `Link ${providerLabel(provider)}`}
              </button>
            ))}
            <button
              className="quiet"
              disabled={busy !== null}
              onClick={() => {
                setBusy("link-wallet");
                linkWallet()
                  .catch(showError)
                  .finally(() => setBusy(null));
              }}
            >
              Link EVM wallet
            </button>
            <button
              className="quiet"
              disabled={busy !== null}
              onClick={() => {
                setBusy("link-solana-wallet");
                linkSolanaWallet()
                  .catch(showError)
                  .finally(() => setBusy(null));
              }}
            >
              Link Solana wallet
            </button>
          </div>
        </div>
      </section>

      <section
        className="ledger danger-zone"
        aria-labelledby="consolidate-account"
      >
        <div className="section-intro">
          <span>03</span>
          <div>
            <h2 id="consolidate-account">Consolidate accounts</h2>
            <p>
              Advanced: prove a duplicate account, move its sign-in methods
              here, and permanently retire the duplicate.
            </p>
          </div>
        </div>
        {mergePreview ? (
          <div className="merge-preview">
            <p>
              <strong>{mergePreview.source.credentialCount} credentials</strong>{" "}
              will move from{" "}
              {mergePreview.source.displayName ?? "the proven account"}.
            </p>
            <p className="muted">
              Kinds: {mergePreview.source.credentialKinds.join(", ") || "none"}.
              You will be signed out everywhere.
            </p>
            <div className="button-row">
              <button
                className="danger"
                disabled={busy !== null}
                onClick={commitMerge}
              >
                Consolidate permanently
              </button>
              <button className="quiet" onClick={() => setMergePreview(null)}>
                Cancel
              </button>
            </div>
          </div>
        ) : (
          <div>
            <p className="muted">
              Choose a method attached to the duplicate account you want to
              retire.
            </p>
            <div className="button-row">
              {config.providers.map((provider) => (
                <button
                  className="quiet"
                  disabled={busy !== null || linkedProviders.has(provider)}
                  key={provider}
                  onClick={() => proveSocial(provider)}
                >
                  {linkedProviders.has(provider)
                    ? `${providerLabel(provider)} already linked`
                    : `Prove with ${providerLabel(provider)}`}
                </button>
              ))}
              <button
                className="quiet"
                disabled={busy !== null}
                onClick={() => {
                  setBusy("proof-wallet");
                  proveWallet()
                    .catch(showError)
                    .finally(() => setBusy(null));
                }}
              >
                Prove with EVM wallet
              </button>
              <button
                className="quiet"
                disabled={busy !== null}
                onClick={() => {
                  setBusy("proof-solana-wallet");
                  proveSolanaWallet()
                    .catch(showError)
                    .finally(() => setBusy(null));
                }}
              >
                Prove with Solana wallet
              </button>
            </div>
          </div>
        )}
      </section>
    </>
  );
}

const styles = `
  .ledger{border-top:1px solid #2b2f2c;padding:2.4rem 0 3.6rem}
  .section-intro{display:grid;grid-template-columns:3rem 1fr;gap:1rem;align-items:start}
  .section-intro>span{color:#b9f27c;font:700 .72rem/1 ui-monospace,monospace}
  .section-intro h2{font-size:clamp(1.55rem,3vw,2.35rem);letter-spacing:-.045em;margin:-.25rem 0 .4rem}
  .section-intro p,.muted{color:#969c96;line-height:1.55;margin:0}
  .account-loading{color:#b9f27c;padding:3rem 0}
  .account-error{border:1px solid #4c403b;background:#1d1b19;padding:1.25rem;margin:1.5rem 0}
  .account-error strong{font-size:1.05rem}
  .account-error p{color:#aaa49e;line-height:1.5;margin:.45rem 0 0}
  .account-summary{display:flex;align-items:center;gap:1rem;margin:2rem 0 1.5rem}
  .account-summary>div:last-child{display:flex;flex-direction:column;gap:.24rem}
  .account-summary strong{font-size:1.2rem;overflow-wrap:anywhere}
  .account-summary span{color:#b9f27c;font-size:.76rem;letter-spacing:.06em;text-transform:uppercase}
  .avatar{width:3.2rem;height:3.2rem;display:grid;place-items:center;flex:0 0 auto;border-radius:50%;background:#b9f27c;color:#11150f;font-size:1.25rem;font-weight:800;overflow:hidden}
  .avatar img{width:100%;height:100%;object-fit:cover}
  .profile-form{border-top:1px solid #272b28;padding-top:1.25rem}
  .profile-form>label,.add-methods>strong{display:block;margin-bottom:.55rem;font-size:.8rem;letter-spacing:.06em;text-transform:uppercase}
  .profile-form>label:not(:first-child){margin-top:1.1rem}
  .handle-note{display:block;margin-top:.55rem;color:#858b85;line-height:1.45}
  .field-row{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:.65rem}
  .field-row input{min-width:0;min-height:3rem;border:1px solid #393e3a;border-radius:.25rem;background:#171a18;color:#f5f4ef;padding:.7rem .85rem;font:inherit}
  .save,.sign-out{min-height:3rem;border-radius:.25rem;padding:.7rem 1rem;font:inherit;font-weight:750;cursor:pointer}
  .save{border:1px solid #b9f27c;background:#b9f27c;color:#11150f}
  .sign-out{border:1px solid #4a4f4a;background:transparent;color:#f5f4ef;margin-top:1.4rem}
  .profile-metadata{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:1rem;margin-top:1.25rem}
  .profile-metadata>div{display:flex;min-width:0;flex-direction:column;gap:.25rem;border-top:1px solid #272b28;padding-top:.85rem}
  .profile-metadata span,.credential>span{color:#858b85;font-size:.72rem;text-transform:uppercase;letter-spacing:.09em}
  .profile-metadata strong,.profile-metadata code,.credential strong{overflow-wrap:anywhere}
  .profile-metadata code{color:#c8cec8;font-size:.76rem}
  .profile-metadata small,.credential small{color:#747a74;line-height:1.4}
  .credential-list{display:grid;grid-template-columns:repeat(auto-fit,minmax(13rem,1fr));border-bottom:1px solid #272b28;margin-top:1.7rem}
  .credential{display:flex;flex-direction:column;gap:.35rem;padding:1rem 1rem 1rem 0;border-top:1px solid #272b28}
  .credential-empty{color:#969c96;margin:0;padding:1rem 0;border-top:1px solid #272b28}
  .add-methods{margin-top:1.7rem}
  .save:hover{background:#c8ff8b}
  button:disabled{opacity:.48;cursor:not-allowed}
  .button-row{display:flex;gap:.6rem;flex-wrap:wrap;margin-top:1.2rem}
  .quiet,.danger{min-height:2.75rem;border:1px solid #393e3a;background:transparent;color:#f5f4ef;border-radius:.25rem;padding:.72rem 1rem;font:inherit;cursor:pointer;text-decoration:none}
  .quiet:hover,.sign-out:hover{border-color:#b9f27c}
  .link-button{display:inline-flex;align-items:center}
  .danger{background:#ff795e;border-color:#ff795e;color:#160906;font-weight:750}
  .merge-preview{margin-top:1.8rem}
  .notice{margin:0 0 1rem;border:1px solid #5b4c45;border-radius:.25rem;background:#201d1a;color:#ffd0c5;padding:.8rem 1rem}
  .danger-zone{padding-bottom:1.5rem}
  button:focus-visible,a:focus-visible,input:focus-visible{outline:2px solid #b9f27c;outline-offset:3px}
  @media(max-width:640px){
    .ledger{padding:2rem 0 2.8rem}
    .section-intro{grid-template-columns:2rem 1fr}
    .field-row,.profile-metadata{grid-template-columns:1fr}
    .field-row .save,.sign-out,.button-row .quiet,.button-row .danger{width:100%}
  }
`;

async function injectedSolanaSigner(): Promise<SolanaSigner> {
  const provider = window.solana;
  if (!provider)
    throw new Error("No Solana wallet was detected in this browser");
  const connected = await provider.connect();
  const address = connected.publicKey.toString();
  return {
    address,
    signMessage: async ({ message }) => provider.signMessage(message),
  };
}

function bytesToBase64(value: Uint8Array): string {
  let binary = "";
  for (const byte of value) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function requireExactSignedMessage(requested: Uint8Array, signed?: Uint8Array) {
  if (
    signed !== undefined &&
    (signed.length !== requested.length ||
      signed.some((byte, index) => byte !== requested[index]))
  ) {
    throw new Error("The wallet changed the SIWS message before signing");
  }
}

const root = createRoot(document.getElementById("account-root")!);
root.render(<AccountApp />);
