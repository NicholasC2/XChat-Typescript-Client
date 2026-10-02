import { isValidUsername } from "./chat.js";
import { loadUserData, saveUserData } from "./user-data.js";

export interface FriendList {
	friends: string[];
	requests: string[];
	sentRequests: string[];
}

export function loadFriends(username: string): FriendList {
	const parsed = loadUserData(username).friends;
	if (
		!parsed.friends.every(isUsername) ||
		!parsed.requests.every(isUsername) ||
		!parsed.sentRequests.every(isUsername)
	) {
		throw new Error("Invalid friend list data");
	}

	const friends = [...new Set(parsed.friends)];
	const requests = [...new Set(parsed.requests)].filter(
		(requester) => !friends.includes(requester),
	);
	const sentRequests = [...new Set(parsed.sentRequests)].filter(
		(recipient) => !friends.includes(recipient),
	);
	return { friends, requests, sentRequests };
}

export function saveFriends(username: string, friendList: FriendList): void {
	const userData = loadUserData(username);
	saveUserData(username, { ...userData, friends: friendList });
}

function isUsername(value: unknown): value is string {
	return typeof value === "string" && isValidUsername(value);
}
