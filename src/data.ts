export enum DataType {
	// Client -> Server
	SIGNUP,
	LOGIN,
	CHALLENGE_SIGNED,
	SEND_MESSAGE,
	REQUEST_PUBKEY,

	// Server -> Client
	SIGNUP_FAIL,
	SIGNUP_SUCCESSFUL,
	LOGIN_FAIL,
	CHALLENGE,
	LOGIN_SUCCESSFUL,
	SEND_MESSAGE_SUCCESSFUL,
	RECEIVE_MESSAGE,
	PUBKEY,
}

export type Data =
	| {
		type: DataType.SIGNUP;
		data: {
			username: string;
			key: string;
		};
	}
	| {
		type: DataType.LOGIN;
		data: {
			username: string;
		};
	}
	| {
		type: DataType.CHALLENGE_SIGNED;
		data: {
			original: string;
			signed: string;
		};
	}
	| {
		type: DataType.SEND_MESSAGE;
		data: {
			username: string;
			data: string;
		};
	}
	| {
		type: DataType.REQUEST_PUBKEY;
		data: {
			username: string;
		};
	}
	| {
		type: DataType.SIGNUP_FAIL;
		data: {
			reason: string;
		};
	}
	| {
		type: DataType.SIGNUP_SUCCESSFUL;
	}
	| {
		type: DataType.LOGIN_FAIL;
		data: {
			reason: string;
		};
	}
	| {
		type: DataType.CHALLENGE;
		data: {
			challenge: string;
		};
	}
	| {
		type: DataType.LOGIN_SUCCESSFUL;
	}
	| {
		type: DataType.SEND_MESSAGE_SUCCESSFUL;
	}
	| {
		type: DataType.RECEIVE_MESSAGE;
		data: {
			username: string;
			data: string;
		};
	}
	| {
		type: DataType.PUBKEY;
		data: {
			username: string;
			key: string;
		};
	};
