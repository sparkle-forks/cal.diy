// Next.js API route support: https://nextjs.org/docs/api-routes/introduction
import type { NextApiRequest, NextApiResponse } from "next";
import { isLocalDevRequest } from "../../lib/isLocalDevRequest";
import prisma from "../../lib/prismaClient";

export type Data = {
  users: {
    email: string;
    username: string;
    id: number | null;
    accessToken: string;
  }[];
};

// example endpoint to fetch managed users; it returns live access tokens, so it is restricted to local development
export default async function handler(req: NextApiRequest, res: NextApiResponse<Data>) {
  if (!isLocalDevRequest(req)) {
    return res.status(404).json({ users: [] });
  }

  const existingUsers = await prisma.user.findMany({
    orderBy: { createdAt: "desc" },
    select: { calcomUserId: true, email: true, calcomUsername: true, accessToken: true },
  });
  if (existingUsers && existingUsers.length) {
    return res.status(200).json({
      users: existingUsers.map((item) => ({
        id: item.calcomUserId,
        email: item.email,
        username: item.calcomUsername ?? "",
        accessToken: item.accessToken ?? "",
      })),
    });
  }
  return res.status(400).json({ users: [] });
}
