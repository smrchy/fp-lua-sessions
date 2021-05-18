
interface IJwtData {
	session: string
	dscid: number;
	dscaid: number;
	exp: number;
}

interface IApiContextData {
	groups?: number[];
	roleNames?: string[];
	data: {
		sessionId?: string;
		ctxSeed?: number;
		dscid?: number;
		dsuid?: number;
		dscaid?: number;
		isSuperUser: boolean;
		permission?: unknown;
		moduleNames?: string[];
		allowedRpc?: string[];
		dsttidList?: number[];
		brand?: unknown;
		ghostDscaid?: number;
	};
}

interface IUsageData {
	/** Milliseconds */
	lastUse: number;
	/** User Agent */
	ua: string;
}