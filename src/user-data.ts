import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

export interface UserData {
	chats: unknown[];
	friends: {
		friends: unknown[];
		requests: unknown[];
		sentRequests: unknown[];
	};
	settings: UserSettings;
}

export interface UserSettings {
	onlyLogCurrentChat: boolean;
	showTimestamps: boolean;
	showNotifications: boolean;
}

export function getUserDataPath(username: string): string {
	return join("chats", `${username}.json`);
}

export function loadUserData(username: string): UserData {
	let parsed: unknown;
	try {
		parsed = JSON.parse(readFileSync(getUserDataPath(username), "utf8"));
	} catch (error) {
		if (isNodeError(error) && error.code === "ENOENT") {
			return { ...emptyUserData(), friends: loadLegacyFriends(username) };
		}
		throw error;
	}

	if (Array.isArray(parsed)) {
		return { ...emptyUserData(), chats: parsed, friends: loadLegacyFriends(username) };
	}
	if (typeof parsed !== "object" || parsed === null) {
		throw new Error("User data must be a JSON object");
	}

	const chats = "chats" in parsed ? parsed.chats : [];
	const storedFriends = "friends" in parsed ? parsed.friends : undefined;
	const storedSettings = "settings" in parsed ? parsed.settings : undefined;
	if (!Array.isArray(chats)) {
		throw new Error("User data chats must be a JSON list");
	}

	if (storedFriends !== undefined && !isFriendData(storedFriends)) {
		throw new Error("User data friend list must contain friends, requests, and sentRequests lists");
	}
	const settings = parseUserSettings(storedSettings);

	return {
		chats,
		friends: storedFriends === undefined
			? loadLegacyFriends(username)
			: {
					friends: storedFriends.friends,
					requests: storedFriends.requests,
					sentRequests: storedFriends.sentRequests,
				},
		settings,
	};
}

function loadLegacyFriends(username: string): UserData["friends"] {
	try {
		const parsed: unknown = JSON.parse(readFileSync(join("friends", `${username}.json`), "utf8"));
		if (
			typeof parsed !== "object" ||
			!isFriendData(parsed)
		) {
			throw new Error("Legacy friend data must contain friends, requests, and sentRequests lists");
		}

		return {
			friends: parsed.friends,
			requests: parsed.requests,
			sentRequests: parsed.sentRequests,
		};
	} catch (error) {
		if (isNodeError(error) && error.code === "ENOENT") {
			return emptyUserData().friends;
		}
		throw error;
	}
}

function isFriendData(value: unknown): value is UserData["friends"] {
	return typeof value === "object" &&
		value !== null &&
		"friends" in value &&
		Array.isArray(value.friends) &&
		"requests" in value &&
		Array.isArray(value.requests) &&
		"sentRequests" in value &&
		Array.isArray(value.sentRequests);
}

export function saveUserData(username: string, userData: UserData): void {
	mkdirSync("chats", { recursive: true });
	writeFileSync(
		getUserDataPath(username),
		`${JSON.stringify(userData, null, 2)}\n`,
		"utf8",
	);
}

export function loadUserSettings(username: string): UserSettings {
	return loadUserData(username).settings;
}

export function saveUserSettings(username: string, settings: UserSettings): void {
	const userData = loadUserData(username);
	saveUserData(username, { ...userData, settings });
}

function emptyUserData(): UserData {
	return {
		chats: [],
		friends: { friends: [], requests: [], sentRequests: [] },
		settings: {
			onlyLogCurrentChat: false,
			showTimestamps: true,
			showNotifications: true,
		},
	};
}

function parseUserSettings(value: unknown): UserSettings {
	const defaults = emptyUserData().settings;
	if (value === undefined) {
		return defaults;
	}
	if (typeof value !== "object" || value === null) {
		throw new Error("User settings must be an object");
	}
	const storedSettings = value as Partial<Record<keyof UserSettings, unknown>>;
	const settings = { ...defaults };
	for (const key of Object.keys(defaults) as (keyof UserSettings)[]) {
		if (key in storedSettings) {
			const setting = storedSettings[key];
			if (typeof setting !== "boolean") {
				throw new Error(`User setting ${key} must be a boolean`);
			}
			settings[key] = setting;
		}
	}
	return settings;
}

function isNodeError(error: unknown): error is NodeJS.ErrnoException {
	return error instanceof Error && "code" in error;
}
