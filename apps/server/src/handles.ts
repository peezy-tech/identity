import { PeezyHandleSchema } from "@peezy.tech/identity";

const RESERVED_HANDLES = new Set([
  "account",
  "admin",
  "api",
  "auth",
  "help",
  "identity",
  "login",
  "logout",
  "oauth",
  "openid",
  "root",
  "security",
  "settings",
  "support",
  "system",
  "www",
]);

export function parseAvailableHandle(value: string): string {
  const handle = PeezyHandleSchema.parse(value);
  if (RESERVED_HANDLES.has(handle)) {
    throw new ReservedHandleError();
  }
  return handle;
}

export class ReservedHandleError extends Error {
  constructor() {
    super("This peezy.tech handle is reserved");
    this.name = "ReservedHandleError";
  }
}
