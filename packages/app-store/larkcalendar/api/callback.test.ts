import { createHmac } from "node:crypto";
import type { NextApiRequest, NextApiResponse } from "next";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@calcom/prisma", () => ({
  default: {
    credential: {
      findFirst: vi.fn(),
      create: vi.fn(),
      update: vi.fn(),
    },
    selectedCalendar: {
      create: vi.fn(),
    },
  },
}));

vi.mock("../lib/AppAccessToken", () => ({
  getAppAccessToken: vi.fn().mockResolvedValue("app-access-token"),
}));

import prisma from "@calcom/prisma";
import handler from "./callback";

const NEXTAUTH_SECRET = "test-nextauth-secret";

function buildState(userId: number) {
  const nonce = "nonce-123";
  const nonceHash = createHmac("sha256", NEXTAUTH_SECRET).update(`${nonce}:${userId}`).digest("hex");
  return JSON.stringify({ returnTo: "https://app.cal.com/apps/installed", nonce, nonceHash });
}

function buildRequest({ userId, state }: { userId?: number; state?: string }) {
  return {
    method: "GET",
    url: "/api/integrations/larkcalendar/callback",
    query: { code: "lark-auth-code", ...(state ? { state } : {}) },
    session: userId ? { user: { id: userId } } : null,
  } as unknown as NextApiRequest;
}

function buildResponse() {
  const res = {
    writableEnded: false,
    status: vi.fn(),
    json: vi.fn(),
    redirect: vi.fn(),
    setHeader: vi.fn(),
  };
  res.status.mockReturnValue(res);
  res.json.mockReturnValue(res);
  return res as unknown as NextApiResponse & typeof res;
}

function mockLarkApi() {
  const fetchMock = vi.fn(async (url: string) => {
    if (url.endsWith("/authen/v1/access_token")) {
      return new Response(
        JSON.stringify({
          code: 0,
          data: {
            access_token: "lark-access",
            refresh_token: "lark-refresh",
            expires_in: 7200,
            refresh_expires_in: 2592000,
          },
        }),
        { status: 200 }
      );
    }
    return new Response(JSON.stringify({}), { status: 404 });
  });
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

describe("larkcalendar OAuth callback", () => {
  beforeEach(() => {
    vi.stubEnv("NEXTAUTH_SECRET", NEXTAUTH_SECRET);
    vi.mocked(prisma.credential.findFirst).mockReset();
    vi.mocked(prisma.credential.create).mockReset();
    vi.mocked(prisma.credential.update).mockReset();
  });

  afterEach(() => {
    vi.unstubAllEnvs();
    vi.unstubAllGlobals();
  });

  it("rejects a request without a logged-in session and never touches credentials", async () => {
    const fetchMock = mockLarkApi();
    const res = buildResponse();

    await handler(buildRequest({ state: buildState(1) }), res);

    expect(res.status).toHaveBeenCalledWith(401);
    expect(fetchMock).not.toHaveBeenCalled();
    expect(prisma.credential.findFirst).not.toHaveBeenCalled();
    expect(prisma.credential.update).not.toHaveBeenCalled();
  });

  it("rejects a callback whose state is missing", async () => {
    const fetchMock = mockLarkApi();
    const res = buildResponse();

    await handler(buildRequest({ userId: 1 }), res);

    expect(res.status).toHaveBeenCalledWith(400);
    expect(fetchMock).not.toHaveBeenCalled();
    expect(prisma.credential.update).not.toHaveBeenCalled();
  });

  it("rejects a state nonce issued to a different user (login CSRF)", async () => {
    const fetchMock = mockLarkApi();
    const res = buildResponse();

    await handler(buildRequest({ userId: 1, state: buildState(2) }), res);

    expect(res.status).toHaveBeenCalledWith(400);
    expect(fetchMock).not.toHaveBeenCalled();
    expect(prisma.credential.update).not.toHaveBeenCalled();
  });

  it("scopes the credential lookup and update to the session user", async () => {
    mockLarkApi();
    vi.mocked(prisma.credential.findFirst).mockResolvedValue({ id: 42 } as never);
    const res = buildResponse();

    await handler(buildRequest({ userId: 7, state: buildState(7) }), res);

    expect(prisma.credential.findFirst).toHaveBeenCalledWith(
      expect.objectContaining({ where: { userId: 7, type: "lark_calendar" } })
    );
    expect(prisma.credential.update).toHaveBeenCalledWith(
      expect.objectContaining({
        where: { id: 42 },
        data: expect.objectContaining({ userId: 7 }),
      })
    );
    expect(res.redirect).toHaveBeenCalledTimes(1);
    expect(res.status).not.toHaveBeenCalled();
  });
});
