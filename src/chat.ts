import { loadUserData, saveUserData } from "./user-data.js";

export type ChatKind = "dm" | "group";

export interface ChatMessage {
	id: string;
	sender: string;
	text: string;
	sentAt: string;
}

export class Chat {
	constructor(
		public id: string,
		public kind: ChatKind,
		public users: string[],
		public messages: ChatMessage[] = [],
	) {}

	addMessage(message: ChatMessage): void {
		if (!this.messages.some(({ id }) => id === message.id)) {
			this.messages.push(message);
		}
	}

	static fromJSON(value: unknown): Chat {
		if (
			typeof value !== "object" ||
			value === null ||
			!("id" in value) ||
			typeof value.id !== "string" ||
			!("kind" in value) ||
			(value.kind !== "dm" && value.kind !== "group") ||
			!("users" in value) ||
			!Array.isArray(value.users) ||
			!value.users.every((user: unknown) => typeof user === "string") ||
			!("messages" in value) ||
			!Array.isArray(value.messages)
		) {
			throw new Error("Invalid chat data in chat history");
		}

		const users = value.users as string[];
		if (
			users.length < (value.kind === "group" ? 3 : 2) ||
			new Set(users).size !== users.length ||
			users.some((user) => !isValidUsername(user))
		) {
			throw new Error("Invalid users in chat history");
		}

		const messages = value.messages.map((message: unknown): ChatMessage => {
			if (
				typeof message !== "object" ||
				message === null ||
				!("id" in message) ||
				typeof message.id !== "string" ||
				!("sender" in message) ||
				typeof message.sender !== "string" ||
				!("text" in message) ||
				typeof message.text !== "string" ||
				!("sentAt" in message) ||
				typeof message.sentAt !== "string" ||
				!users.includes(message.sender)
			) {
				throw new Error("Invalid message in chat history");
			}

			return {
				id: message.id,
				sender: message.sender,
				text: message.text,
				sentAt: message.sentAt,
			};
		});

		if (value.kind === "dm" && (users.length !== 2 || value.id !== directChatId(users))) {
			throw new Error("Invalid direct message chat in chat history");
		}

		return new Chat(value.id, value.kind, users, messages);
	}
}

export function normalizeUsername(username: string): string {
	return username.trim().toLowerCase();
}

export function isValidUsername(username: string): boolean {
	return /^[a-z0-9_]{3,32}$/.test(username);
}

export function directChatId(users: string[]): string {
	return `dm:${[...users].sort().join(":")}`;
}

export function loadChats(username: string): Chat[] {
	const chats = loadUserData(username).chats.map(Chat.fromJSON);
	if (chats.some((chat) => !chat.users.includes(username))) {
		throw new Error("Chat history contains a chat for another user");
	}
	if (new Set(chats.map(({ id }) => id)).size !== chats.length) {
		throw new Error("Chat history contains duplicate chats");
	}
	return chats;
}

export function saveChats(username: string, chats: Chat[]): void {
	const userData = loadUserData(username);
	saveUserData(username, { ...userData, chats });
}
