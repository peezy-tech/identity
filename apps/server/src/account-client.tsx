import {
  getAccessToken,
  PrivyProvider,
  usePrivy,
  useWallets,
} from "@privy-io/react-auth";
import {
  toSolanaWalletConnectors,
  useWallets as useSolanaWallets,
} from "@privy-io/react-auth/solana";
import React, { useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";

import { selectEthereumAccount } from "./account-client-wallet";

type Provider = "apple" | "discord" | "github" | "telegram" | "twitter";
type AccountConfig = { privyAppId: string | null; providers: Provider[] };
type Credential = {
  address?: string;
  family?: "evm" | "solana";
  kind: "email" | "social" | "wallet" | "passkey";
  provider?: Provider;
  value?: string;
};
type Identity = {
  credentials: Credential[];
  user: { displayName?: string; id: string; primaryEmail?: { value: string } };
};
type MigrationIdentity = {
  chainType?: string;
  displayHint: string;
  disposition:
    | "already_linked"
    | "needs_reverification"
    | "legacy_only"
    | "conflict"
    | "linked";
  id: string;
  provider?: Provider;
  type: string;
  walletAddress?: string;
};
type Claim = {
  claimedAt: string;
  id: string;
  identities: MigrationIdentity[];
  privyUserHint: string;
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
  const [claims, setClaims] = useState<Claim[]>([]);
  const [busy, setBusy] = useState<string | null>(null);
  const [notice, setNotice] = useState<string>("");
  const [mergePreview, setMergePreview] = useState<MergePreview | null>(null);

  async function refresh() {
    const [nextIdentity, nextClaims] = await Promise.all([
      requestJson<Identity>("/v1/me"),
      requestJson<{ claims: Claim[] }>("/v1/migrations/privy/claims/current"),
    ]);
    setIdentity(nextIdentity);
    setClaims(nextClaims.claims);
  }

  useEffect(() => {
    refresh().catch(showError);
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
    setNotice(
      error instanceof Error ? error.message : "Identity request failed",
    );
  }

  async function linkWallet(
    addressHint?: string,
    selectedProvider?: EthereumProvider,
  ) {
    const walletProvider = selectedProvider ?? ethereum();
    if (!walletProvider)
      throw new Error("No EVM wallet was detected in this browser");
    const accounts = (await walletProvider.request({
      method: "eth_requestAccounts",
    })) as string[];
    const address = selectEthereumAccount(accounts, addressHint);
    if (!address) {
      throw new Error(
        addressHint === undefined
          ? "No wallet account was selected"
          : "Select the wallet attached to this Privy identity",
      );
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

  async function linkSolanaWallet(
    addressHint?: string,
    selectedWallet?: SolanaSigner,
  ) {
    const wallet = selectedWallet ?? (await injectedSolanaSigner());
    if (addressHint !== undefined && wallet.address !== addressHint) {
      throw new Error(
        "Select the Solana wallet attached to this Privy identity",
      );
    }
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

  function reverify(item: MigrationIdentity) {
    setNotice("");
    if (item.provider) {
      const callback = `${location.origin}/account`;
      location.assign(
        `/link-social?provider=${item.provider}&callback_url=${encodeURIComponent(callback)}`,
      );
    }
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

  if (!identity)
    return <p className="account-loading">Loading your identity…</p>;
  return (
    <>
      <style>{styles}</style>
      <section className="ledger" aria-labelledby="current-account">
        <div className="section-intro">
          <span>01</span>
          <div>
            <h2 id="current-account">Current account</h2>
            <p>This subject survives every migration and consolidation.</p>
          </div>
        </div>
        <div className="subject-line">
          <strong>
            {identity.user.displayName ??
              identity.user.primaryEmail?.value ??
              "peezy.tech account"}
          </strong>
          <code>{identity.user.id}</code>
        </div>
        <div className="credential-list">
          {identity.credentials.map((credential, index) => (
            <div className="credential" key={`${credential.kind}-${index}`}>
              <span>
                {credential.kind === "wallet" && credential.family
                  ? `${credential.family} wallet`
                  : credential.kind}
              </span>
              <strong>
                {credential.provider ??
                  credential.address ??
                  credential.value ??
                  "credential"}
              </strong>
            </div>
          ))}
        </div>
      </section>

      <section className="ledger" aria-labelledby="legacy-account">
        <div className="section-intro">
          <span>02</span>
          <div>
            <h2 id="legacy-account">Lobby history</h2>
            <p>
              A Privy login claims the complete legacy user and every identity
              attached to it.
            </p>
          </div>
        </div>
        {config.privyAppId ? (
          <PrivyMigration
            claims={claims}
            busy={busy}
            setBusy={setBusy}
            refresh={refresh}
            showError={showError}
            reverify={reverify}
            linkWallet={linkWallet}
            linkSolanaWallet={linkSolanaWallet}
          />
        ) : (
          <p className="muted">Migration is currently unavailable.</p>
        )}
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
              Prove a second account, move its credentials here, and permanently
              retire its subject.
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
              Choose how to prove the account you want to retire.
            </p>
            <div className="button-row">
              {config.providers.map((provider) => (
                <button
                  className="quiet"
                  disabled={busy !== null}
                  key={provider}
                  onClick={() => proveSocial(provider)}
                >
                  {provider}
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
                EVM wallet
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
                Solana wallet
              </button>
            </div>
          </div>
        )}
      </section>
      <p className="notice" role="status" aria-live="polite">
        {notice}
      </p>
    </>
  );
}

function PrivyMigration(props: {
  busy: string | null;
  claims: Claim[];
  refresh(): Promise<void>;
  reverify(item: MigrationIdentity): void;
  linkWallet(addressHint?: string, provider?: EthereumProvider): Promise<void>;
  linkSolanaWallet(addressHint?: string, wallet?: SolanaSigner): Promise<void>;
  setBusy(value: string | null): void;
  showError(error: unknown): void;
}) {
  const {
    authenticated,
    getAccessToken: hookGetAccessToken,
    login,
    logout,
    ready,
  } = usePrivy();
  const { wallets } = useWallets();
  const { wallets: solanaWallets } = useSolanaWallets();
  const [attempt, setAttempt] = useState<{
    attemptId: string;
    csrfToken: string;
  } | null>(null);
  const walletAddresses = useMemo(
    () =>
      new Set([
        ...wallets.map((wallet) => `evm:${wallet.address.toLowerCase()}`),
        ...solanaWallets.map((wallet) => `solana:${wallet.address}`),
      ]),
    [solanaWallets, wallets],
  );

  useEffect(() => {
    if (!ready || !authenticated || !attempt) return;
    props.setBusy("privy-claim");
    (async () => {
      const token = (await hookGetAccessToken()) ?? (await getAccessToken());
      if (!token) throw new Error("Privy did not return an access token");
      await requestJson("/v1/migrations/privy/claims", {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` },
        body: JSON.stringify(attempt),
      });
      setAttempt(null);
      await props.refresh();
    })()
      .catch(props.showError)
      .finally(() => props.setBusy(null));
  }, [authenticated, attempt, ready]);

  async function start() {
    props.setBusy("privy-login");
    try {
      const next = await requestJson<{ attemptId: string; csrfToken: string }>(
        "/v1/migrations/privy/attempts",
        { method: "POST", body: "{}" },
      );
      if (authenticated) await logout();
      setAttempt(next);
      login();
    } catch (error) {
      props.showError(error);
    } finally {
      props.setBusy(null);
    }
  }

  function verifyIdentity(item: MigrationIdentity) {
    if (item.provider) {
      props.reverify(item);
      return;
    }
    if (!item.walletAddress) return;
    if (item.type === "smart_wallet") {
      props.showError(
        new Error(
          "Privy smart-wallet migration requires a chain-scoped proof and is not available yet",
        ),
      );
      return;
    }
    props.setBusy(item.id);
    if (item.chainType === "solana") {
      const privyWallet = solanaWallets.find(
        (wallet) => wallet.address === item.walletAddress,
      );
      props
        .linkSolanaWallet(item.walletAddress, privyWallet)
        .catch(props.showError)
        .finally(() => props.setBusy(null));
      return;
    }
    const privyWallet = wallets.find(
      (wallet) =>
        wallet.address.toLowerCase() === item.walletAddress?.toLowerCase(),
    );
    if (privyWallet === undefined) {
      props.showError(
        new Error("Connect the Privy wallet attached to this identity"),
      );
      props.setBusy(null);
      return;
    }
    (async () => {
      const provider =
        (await privyWallet.getEthereumProvider()) as EthereumProvider;
      await props.linkWallet(item.walletAddress, provider);
    })()
      .catch(props.showError)
      .finally(() => props.setBusy(null));
  }

  return (
    <div>
      <button
        className="primary-action"
        disabled={!ready || props.busy !== null}
        onClick={start}
      >
        Migrate from Privy <span>↗</span>
      </button>
      {props.claims.map((claim) => (
        <div className="claim" key={claim.id}>
          <div className="claim-head">
            <strong>Privy {claim.privyUserHint}</strong>
            <time>{new Date(claim.claimedAt).toLocaleDateString()}</time>
          </div>
          {claim.identities.map((item) => (
            <div className="migration-row" key={item.id}>
              <div>
                <strong>{item.displayHint}</strong>
                <span>{item.type.replaceAll("_", " ")}</span>
              </div>
              <div className="disposition">
                <span data-state={item.disposition}>
                  {item.disposition.replaceAll("_", " ")}
                </span>
                {item.disposition === "needs_reverification" &&
                (item.provider || item.walletAddress) ? (
                  <button
                    className="text-button"
                    disabled={props.busy !== null}
                    onClick={() => verifyIdentity(item)}
                  >
                    {item.walletAddress &&
                    walletAddresses.has(
                      item.chainType === "solana"
                        ? `solana:${item.walletAddress}`
                        : `evm:${item.walletAddress.toLowerCase()}`,
                    )
                      ? "Sign with Privy wallet"
                      : "Verify"}
                  </button>
                ) : null}
              </div>
            </div>
          ))}
        </div>
      ))}
    </div>
  );
}

const styles = `
  .ledger{border-top:1px solid #2b2f2c;padding:2.2rem 0 3.4rem}.section-intro{display:grid;grid-template-columns:3rem 1fr;gap:1rem;align-items:start}.section-intro>span{color:#b9f27c;font:700 .72rem/1 ui-monospace,monospace}.section-intro h2{font-size:clamp(1.55rem,3vw,2.35rem);letter-spacing:-.045em;margin:-.25rem 0 .4rem}.section-intro p,.muted{color:#969c96;line-height:1.55;margin:0}.subject-line{display:flex;align-items:baseline;justify-content:space-between;gap:1rem;margin:2rem 0 1rem}.subject-line strong{font-size:1.2rem}.subject-line strong,.credential strong{overflow-wrap:anywhere}.subject-line code{color:#747a74;font-size:.72rem}.credential-list{display:grid;grid-template-columns:repeat(auto-fit,minmax(13rem,1fr));border-bottom:1px solid #272b28}.credential{display:flex;flex-direction:column;gap:.35rem;padding:1rem 0;border-top:1px solid #272b28}.credential span,.migration-row span{color:#858b85;font-size:.72rem;text-transform:uppercase;letter-spacing:.09em}.primary-action{width:100%;display:flex;justify-content:space-between;align-items:center;margin-top:2rem;padding:1.2rem 1.3rem;border:0;border-radius:.25rem;background:#b9f27c;color:#11150f;font-weight:790;cursor:pointer}.primary-action:hover{background:#c8ff8b}.primary-action:disabled,button:disabled{opacity:.48;cursor:not-allowed}.claim{margin-top:2rem}.claim-head,.migration-row{display:flex;justify-content:space-between;align-items:center;gap:1rem;border-top:1px solid #272b28;padding:1rem 0}.claim-head time{color:#747a74;font-size:.8rem}.migration-row>div:first-child{display:flex;flex-direction:column;gap:.25rem}.disposition{display:flex;align-items:center;gap:1rem;text-align:right}.disposition>[data-state]{color:#aab0aa}.disposition>[data-state=linked],.disposition>[data-state=already_linked]{color:#b9f27c}.disposition>[data-state=conflict]{color:#ff9a84}.button-row{display:flex;gap:.6rem;flex-wrap:wrap;margin-top:1.4rem}.quiet,.danger,.text-button{border:1px solid #393e3a;background:transparent;color:#f5f4ef;border-radius:.25rem;padding:.72rem 1rem;cursor:pointer}.quiet:hover,.text-button:hover{border-color:#b9f27c}.danger{background:#ff795e;border-color:#ff795e;color:#160906;font-weight:750}.text-button{padding:.35rem .55rem;font-size:.75rem}.merge-preview{margin-top:1.8rem}.notice{min-height:1.5rem;color:#ffd0c5}.danger-zone{padding-bottom:1.5rem}@media(max-width:640px){.section-intro{grid-template-columns:2rem 1fr}.subject-line,.migration-row{align-items:flex-start;flex-direction:column}.subject-line code{overflow-wrap:anywhere}.disposition{width:100%;justify-content:space-between;text-align:left}}
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

const solanaConnectors = toSolanaWalletConnectors({ shouldAutoConnect: false });

const root = createRoot(document.getElementById("account-root")!);
root.render(
  config.privyAppId ? (
    <PrivyProvider
      appId={config.privyAppId}
      config={{
        appearance: {
          theme: "dark",
          accentColor: "#B9F27C",
          walletChainType: "ethereum-and-solana",
        },
        externalWallets: { solana: { connectors: solanaConnectors } },
      }}
    >
      <AccountApp />
    </PrivyProvider>
  ) : (
    <AccountApp />
  ),
);
