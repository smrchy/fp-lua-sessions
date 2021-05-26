import * as RedisInst from "redis";

/**
 * KEYS[1] `OAuth2:${dscid}:session:${session}`
 * KEYS[2] `OAuth2:${dscid}:session:${session}:groups`
 * KEYS[3] `OAuth2:${dscid}:session:${session}:roleName`
 * KEYS[4] `OAuth2:${dscid}:usage:byLastUse`
 * KEYS[5] `OAuth2:${dscid}:usage:session:${session}`
 *
 * ARGV[1] refresh ttl
 * ARGV[2] `${dscaid}:${session}` usage key
 * ARGV[3] UsageData
 */
const LUA_RESOLVE_TOKEN = `
	-- try to get session
	local data = redis.call("GET", KEYS[1])
	local groups = redis.call("SMEMBERS", KEYS[2])
	local roleNames = redis.call("SMEMBERS", KEYS[3])
	if data then
		-- update usage
		local usageData = cjson.decode(ARGV[3]);
		redis.call("ZADD", KEYS[4], usageData.lastUse, ARGV[2])
		redis.call("SET", KEYS[5], ARGV[3])
		-- refresh ttl, if it is set
		local ttl = redis.call("TTL", KEYS[1])
		if ttl then
			redis.call("EXPIRE", KEYS[1], ARGV[1])
			redis.call("EXPIRE", KEYS[2], ARGV[1])
			redis.call("EXPIRE", KEYS[3], ARGV[1])
			redis.call("EXPIRE", KEYS[5], ARGV[1])
		end
	end
	return { data, groups, roleNames }
`;

class RedisConnector {
	private redisPrefix;
	private redis;
	private lua_sha1_resolveToken = null;

	constructor(redisPrefix: string) {
		this.redisPrefix = redisPrefix;
		this.redis = RedisInst.createClient(process.env.FP_REDIS_URL as any);
	}

	private resolveTokenSha1 (cb) {
		if (this.lua_sha1_resolveToken) {
			cb(null, this.lua_sha1_resolveToken);
			return;
		}
		this.redis.script("LOAD", LUA_RESOLVE_TOKEN, (err, resp) => {
			if (err) {
				console.log("FATAL ERROR: FAILED TO LOAD LUA SCRIPT", err);
				process.exit(1);
			}
			this.lua_sha1_resolveToken = resp;
			cb(null, resp);
		})
	} 

	public resolveToken = (
		dscid: number,
		session: string,
		dscaid: number,
		ua: string,
		refreshTtl: number,
		cb: Function
	) => {
		this.resolveTokenSha1( (err, sha) => {
			if (err) { cb(err); return; }
			const usageData: IUsageData = {
				lastUse: Date.now(),
				ua: ua,
			};
			this.redis.evalsha(
				sha,
				5,
				// keys
				`${this.redisPrefix}:${dscid}:session:${session}`,
				`${this.redisPrefix}:${dscid}:session:${session}:groups`,
				`${this.redisPrefix}:${dscid}:session:${session}:roleNames`,
				`${this.redisPrefix}:${dscid}:usage:byLastUse`,
				`${this.redisPrefix}:${dscid}:usage:session:${session}`,
				// argv
				refreshTtl,
				`${dscaid}:${session}`,
				JSON.stringify(usageData),
				(err, result) => {
					if (err) { cb(err); return; }
					const o: IApiContextData = {
						data: result[0] != null ? JSON.parse(result[0]) : undefined,
						groups: result[1]?.map((id: string) => parseInt(id)) ?? [],
						roleNames: result[2] ?? []
					};
					if (!o.data) {
						cb({
							error: `No valid session found`,
							status: 401
						})
						return;
					}
					cb(null, o);
				}
			);
		});
	}
}

export default new RedisConnector("OAuth2:v2");
