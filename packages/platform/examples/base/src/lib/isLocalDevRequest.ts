import process from "node:process";
import type { NextApiRequest } from "next";

const LOOPBACK_ADDRESSES = new Set(["127.0.0.1", "::1", "::ffff:127.0.0.1"]);

function isLoopback(address: string | undefined): boolean {
  return !!address && LOOPBACK_ADDRESSES.has(address.trim());
}

function headerValues(value: string | string[] | undefined): string[] {
  if (!value) return [];
  const joined = Array.isArray(value) ? value.join(",") : value;
  return joined.split(",");
}

// The example app has no user authentication of its own, so routes that hand out stored
// cal.com tokens must only ever answer a developer's own browser on a `next dev` server.
export function isLocalDevRequest(req: NextApiRequest): boolean {
  if (process.env.NODE_ENV !== "development") {
    return false;
  }

  if (!isLoopback(req.socket?.remoteAddress)) {
    return false;
  }

  // Next.js fills x-forwarded-for with the socket address itself, but behind a local reverse
  // proxy the socket is loopback while these headers carry the real (remote) client address.
  const forwardedAddresses = [
    ...headerValues(req.headers["x-forwarded-for"]),
    ...headerValues(req.headers["x-real-ip"]),
  ];
  return forwardedAddresses.every(isLoopback);
}
