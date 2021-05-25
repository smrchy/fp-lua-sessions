import { Request, Response, NextFunction } from "express";
import * as JWT from "jsonwebtoken";
import RedisConnector from "./redis";
const cookie = require("cookie");
if (!process.env.FP_JWT_PUBLIC) {
	throw new Error("Please specify the env var JWT Public Key (FP_JWT_PUBLIC)");
}

if (!process.env.FP_REDIS_URL) {
	throw new Error("Please specify the env var Redis URL (FP_REDIS_URL)");
}

if (!process.env.FP_COOKIE_NAME) {
	throw new Error("Please specify the env var Cookie name (FP_COOKIE_NAME)");
}

const JWT_PUBLIC = Buffer.from(process.env.FP_JWT_PUBLIC as any, "base64").toString("utf-8")

const resolveAccessToken = async (token: string): Promise<IJwtData> => {
	return new Promise(async (resolve, reject) => {
		JWT.verify(token, JWT_PUBLIC as string, {
			algorithms: [ "ES512" ],
			audience: "authorization",
		}, (err, decoded) => {
			if (err != null) return reject(err);
			resolve(decoded as IJwtData);
		});
	});
}

export const resolveSession = async (req: Request, res: Response, next: NextFunction) => {
	try {
		let authtoken: string|null = null;

		if (req.headers.cookie) {
			const cookies = cookie.parse(req.headers.cookie);
			authtoken = cookies[process.env.FP_COOKIE_NAME as string]
		}
		// If we find an authorization header we take that token over the cookie!!!
		if (req.headers.authorization && req.headers.authorization.slice(0,7) === "Bearer ") {
			authtoken = req.headers.authorization.slice(7);
		}

		if (!authtoken) {
			next({
				error: `Invalid OAuth2 authorization / cookie (${process.env.FP_COOKIE_NAME}) provided`,
				status: 401
			});
			return;
		}

		const token = await resolveAccessToken(authtoken);
		RedisConnector.resolveToken(
			token.dscid,
			token.session,
			token.dscaid,
			req.get("user-agent") || "MISSING-USER-AGENT",
			1440,
			(err, resp) => {
				if (err) { next(err); return; }
				res.locals.session = resp;
				next()
			}
		);
	} catch (err) {
		next(err);
	}
}
