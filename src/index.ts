import { input, select } from "@inquirer/prompts";
import { generateKeyPairSync, randomUUID, subtle, webcrypto } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { WebSocket } from "ws";
import {
	Chat,
	directChatId,
	isValidUsername,
	loadChats,
	normalizeUsername,
	saveChats,
	type ChatKind,
	type ChatMessage,
} from "./chat.js";
import { Data, DataType } from "./data.js";
import { loadFriends, saveFriends, type FriendList } from "./friends.js";
import { loadUserSettings, saveUserSettings } from "./user-data.js";

const ws = new WebSocket("wss://chat.nicholasc.net/");

interface AccountKeys {
	signingKey: webcrypto.CryptoKey;
	decryptionKey: webcrypto.CryptoKey;
}

interface ClientState {
	username: string | undefined;
	privateKeys: AccountKeys | undefined;
	loggedIn: boolean;
	chats: Chat[];
	currentChat: Chat | null;
	friends: FriendList;
	onlyLogCurrentChat: boolean;
	showTimestamps: boolean;
	showNotifications: boolean;
}

interface PendingRequest {
	context: string;
	resolve: (response: ServerResponse) => void;
	reject: (error: Error) => void;
}

type ServerResponse = Data | { error: string };

type ChatEnvelope =
	| {
			kind: "chat_invite";
			chat: { id: string; kind: ChatKind; users: string[] };
	  }
	| {
			kind: "chat_message";
			chatId: string;
			message: ChatMessage;
	  }
	| {
			kind: "message_accepted";
			chatId: string;
			messageId: string;
	  }
	| {
			kind: "friend_request";
	  }
	| {
			kind: "friend_accepted";
	  }
	| {
			kind: "friend_removed";
	  };

const state: ClientState = {
	username: undefined,
	privateKeys: undefined,
	loggedIn: false,
	chats: [],
	currentChat: null,
	friends: { friends: [], requests: [], sentRequests: [] },
	onlyLogCurrentChat: false,
	showTimestamps: true,
	showNotifications: true,
};
const pendingRequests: PendingRequest[] = [];
const encryptionKeys = new Map<string, webcrypto.CryptoKey>();
const pendingChatInvitations = new Map<string, Chat>();
const pendingMessageAcceptances = new Map<
	string,
	{ chatId: string; resolve: (accepted: boolean) => void }
>();
const messageAcceptanceTimeoutMs = 15_000;

ws.on("message", (rawData) => {
	let message: unknown;
	try {
		message = JSON.parse(rawData.toString());
	} catch (error) {
		console.error("Received invalid server JSON", error);
		return;
	}

	if (isReceiveMessage(message)) {
		void handleIncomingMessage(message.data.username, message.data.data).catch((error: unknown) => {
			console.error("Could not process an incoming encrypted message.", error);
		});
		return;
	}

	const pending = pendingRequests.shift();
	if (!pending) {
		console.error("Received an unexpected server response", message);
		return;
	}

	if (isServerError(message)) {
		console.error(`${pending.context}: ${message.error}`);
		pending.resolve(message);
		return;
	}

	pending.resolve(message as Data);
});

ws.on("close", () => {
	for (const pending of pendingRequests.splice(0)) {
		pending.reject(new Error("Connection closed before the server replied"));
	}
	state.loggedIn = false;
});

ws.on("error", (error) => {
	console.error("WebSocket error", error);
});

function isServerError(message: unknown): message is { error: string } {
	return typeof message === "object" &&
		message !== null &&
		"error" in message &&
		typeof message.error === "string";
}

function isReceiveMessage(message: unknown): message is Extract<Data, { type: DataType.RECEIVE_MESSAGE }> {
	if (typeof message !== "object" || message === null || !("type" in message)) {
		return false;
	}
	if (message.type !== DataType.RECEIVE_MESSAGE || !("data" in message)) {
		return false;
	}
	const data: unknown = message.data;
	return typeof data === "object" &&
		data !== null &&
		"username" in data &&
		typeof data.username === "string" &&
		"data" in data &&
		typeof data.data === "string";
}

function sendRequest(request: Data, context: string): Promise<ServerResponse> {
	if (ws.readyState !== WebSocket.OPEN) {
		return Promise.reject(new Error("Not connected to the chat server"));
	}

	return new Promise((resolve, reject) => {
		pendingRequests.push({ context, resolve, reject });
		try {
			ws.send(JSON.stringify(request));
		} catch (error) {
			pendingRequests.pop();
			reject(error instanceof Error ? error : new Error(String(error)));
		}
	});
}

function isDataResponse<T extends DataType>(
	response: ServerResponse,
	type: T,
): response is Extract<Data, { type: T }> {
	return !isServerError(response) && response.type === type;
}

async function signIn(username: string, privateKeys: AccountKeys): Promise<boolean> {
	state.username = normalizeUsername(username);
	state.privateKeys = privateKeys;
	encryptionKeys.clear();

	const challengeResponse = await sendRequest({
		type: DataType.LOGIN,
		data: { username: state.username },
	}, "Login failed");

	if (!isDataResponse(challengeResponse, DataType.CHALLENGE)) {
		console.error("The server did not issue a login challenge.");
		return false;
	}

	const signature = await subtle.sign(
		{ name: "RSA-PSS", saltLength: 32 },
		privateKeys.signingKey,
		new TextEncoder().encode(challengeResponse.data.challenge),
	);

	const loginResponse = await sendRequest({
		type: DataType.CHALLENGE_SIGNED,
		data: {
			original: challengeResponse.data.challenge,
			signed: Buffer.from(signature).toString("base64"),
		},
	}, "Login failed");

	if (!isDataResponse(loginResponse, DataType.LOGIN_SUCCESSFUL)) {
		console.error("The server rejected the login.");
		return false;
	}

	state.loggedIn = true;
	state.chats = loadChats(state.username);
	state.currentChat = null;
	state.friends = loadFriends(state.username);
	const settings = loadUserSettings(state.username);
	state.onlyLogCurrentChat = settings.onlyLogCurrentChat;
	state.showTimestamps = settings.showTimestamps;
	state.showNotifications = settings.showNotifications;
	saveChats(state.username, state.chats);
	saveFriends(state.username, state.friends);
	return true;
}

async function getPrivateKey(): Promise<AccountKeys> {
	while (true) {
		const location = await input({
			message: "Private key location",
			default: "./private.key",
		});
		try {
			const keyData = readFileSync(location);
			const [signingKey, decryptionKey] = await Promise.all([
				subtle.importKey(
					"pkcs8",
					keyData,
					{ name: "RSA-PSS", hash: "SHA-256" },
					false,
					["sign"],
				),
				subtle.importKey(
					"pkcs8",
					keyData,
					{ name: "RSA-OAEP", hash: "SHA-256" },
					false,
					["decrypt"],
				),
			]);
			return { signingKey, decryptionKey };
		} catch (error) {
			console.error(`Could not load a compatible private key from ${location}.`, error);
		}
	}
}

async function createAccount(): Promise<void> {
	const username = normalizeUsername(await input({ message: "Username" }));
	if (!isValidUsername(username)) {
		console.error("Username must be 3-32 characters using only letters, numbers, or underscores.");
		return;
	}

	const { publicKey, privateKey } = generateKeyPairSync("rsa", {
		modulusLength: 2048,
	});
	const privateKeyDer = privateKey.export({ type: "pkcs8", format: "der" });
	const [signingKey, decryptionKey] = await Promise.all([
		subtle.importKey(
			"pkcs8",
			privateKeyDer,
			{ name: "RSA-PSS", hash: "SHA-256" },
			false,
			["sign"],
		),
		subtle.importKey(
			"pkcs8",
			privateKeyDer,
			{ name: "RSA-OAEP", hash: "SHA-256" },
			false,
			["decrypt"],
		),
	]);
	const privateKeyLocation = await input({
		message: "Save private key to",
		default: "./private.key",
	});
	writeFileSync(privateKeyLocation, privateKeyDer);

	const publicKeyBase64 = publicKey.export({ type: "spki", format: "der" }).toString("base64");
	const response = await sendRequest({
		type: DataType.SIGNUP,
		data: { username, key: publicKeyBase64 },
	}, "Sign up failed");

	if (isDataResponse(response, DataType.SIGNUP_SUCCESSFUL)) {
		await signIn(username, { signingKey, decryptionKey });
	}
}

async function signInPrompt(): Promise<void> {
	const username = normalizeUsername(await input({ message: "Username" }));
	if (!isValidUsername(username)) {
		console.error("Username must be 3-32 characters using only letters, numbers, or underscores.");
		return;
	}

	await signIn(username, await getPrivateKey());
}

function chatLabel(chat: Chat): string {
	if (chat.kind === "dm") {
		return `DM: ${chat.users.find((username) => username !== state.username)}`;
	}
	return `Group: ${chat.users.filter((username) => username !== state.username).join(", ")}`;
}

function canInteractWithChat(chat: Chat): boolean {
	const username = state.username;
	return !!username &&
		chat.users.includes(username) &&
		chat.users.every((user) => user === username || state.friends.friends.includes(user));
}

function clearUnavailableChats(): void {
	if (state.currentChat && !canInteractWithChat(state.currentChat)) {
		state.currentChat = null;
		if (state.showNotifications) {
			console.log("Selected chat cleared: a participant is no longer your friend.");
		}
	}
	for (const [key, chat] of pendingChatInvitations) {
		if (!canInteractWithChat(chat)) {
			pendingChatInvitations.delete(key);
		}
	}
}

async function getEncryptionKey(username: string): Promise<webcrypto.CryptoKey> {
	const cachedKey = encryptionKeys.get(username);
	if (cachedKey) {
		return cachedKey;
	}

	const response = await sendRequest({
		type: DataType.REQUEST_PUBKEY,
		data: { username },
	}, `Could not get ${username}'s public key`);
	if (
		!isDataResponse(response, DataType.PUBKEY) ||
		normalizeUsername(response.data.username) !== username
	) {
		throw new Error(`The server did not return a valid public key for ${username}.`);
	}

	const key = await subtle.importKey(
		"spki",
		Buffer.from(response.data.key, "base64"),
		{ name: "RSA-OAEP", hash: "SHA-256" },
		false,
		["encrypt"],
	);
	encryptionKeys.set(username, key);
	return key;
}

interface EncryptedEnvelope {
	version: 1;
	encryptedKey: string;
	iv: string;
	ciphertext: string;
}

async function encryptEnvelope(username: string, envelope: ChatEnvelope): Promise<string> {
	const publicKey = await getEncryptionKey(username);
	const aesKey = await subtle.generateKey(
		{ name: "AES-GCM", length: 256 },
		true,
		["encrypt"],
	);
	const rawAesKey = await subtle.exportKey("raw", aesKey);
	const iv = webcrypto.getRandomValues(new Uint8Array(12));
	const ciphertext = await subtle.encrypt(
		{ name: "AES-GCM", iv },
		aesKey,
		new TextEncoder().encode(JSON.stringify(envelope)),
	);
	const encryptedKey = await subtle.encrypt(
		{ name: "RSA-OAEP" },
		publicKey,
		rawAesKey,
	);
	const encryptedEnvelope: EncryptedEnvelope = {
		version: 1,
		encryptedKey: Buffer.from(encryptedKey).toString("base64"),
		iv: Buffer.from(iv).toString("base64"),
		ciphertext: Buffer.from(ciphertext).toString("base64"),
	};
	return JSON.stringify(encryptedEnvelope);
}

async function decryptEnvelope(raw: string): Promise<ChatEnvelope> {
	const privateKey = state.privateKeys?.decryptionKey;
	if (!privateKey) {
		throw new Error("No decryption key is available for the signed-in account.");
	}
	let encrypted: unknown;
	try {
		encrypted = JSON.parse(raw);
	} catch {
		throw new Error("Incoming message is not a valid encrypted envelope.");
	}
	if (
		typeof encrypted !== "object" ||
		encrypted === null ||
		!("version" in encrypted) ||
		encrypted.version !== 1 ||
		!("encryptedKey" in encrypted) ||
		typeof encrypted.encryptedKey !== "string" ||
		!("iv" in encrypted) ||
		typeof encrypted.iv !== "string" ||
		!("ciphertext" in encrypted) ||
		typeof encrypted.ciphertext !== "string"
	) {
		throw new Error("Incoming message has an unsupported encrypted envelope.");
	}

	const aesKeyBytes = await subtle.decrypt(
		{ name: "RSA-OAEP" },
		privateKey,
		Buffer.from(encrypted.encryptedKey, "base64"),
	);
	const aesKey = await subtle.importKey("raw", aesKeyBytes, { name: "AES-GCM" }, false, ["decrypt"]);
	const plaintext = await subtle.decrypt(
		{ name: "AES-GCM", iv: Buffer.from(encrypted.iv, "base64") },
		aesKey,
		Buffer.from(encrypted.ciphertext, "base64"),
	);
	const envelope = parseEnvelope(new TextDecoder("utf-8", { fatal: true }).decode(plaintext));
	if (!envelope) {
		throw new Error("Decrypted message has an invalid envelope.");
	}
	return envelope;
}

async function sendEnvelope(username: string, envelope: ChatEnvelope): Promise<boolean> {
	try {
		const encrypted = await encryptEnvelope(username, envelope);
		const response = await sendRequest({
			type: DataType.SEND_MESSAGE,
			data: { username, data: encrypted },
		}, `Message to ${username} was not delivered`);
		return isDataResponse(response, DataType.SEND_MESSAGE_SUCCESSFUL);
	} catch (error) {
		console.error(`Could not encrypt or send a message to ${username}.`, error);
		return false;
	}
}

async function sendChatMessage(chat: Chat, text: string): Promise<void> {
	const username = state.username;
	if (!username) {
		throw new Error("You must be signed in to send messages.");
	}
	if (!canInteractWithChat(chat)) {
		console.error("You must be friends with every chat participant to send messages.");
		return;
	}

	const message: ChatMessage = {
		id: randomUUID(),
		sender: username,
		text,
		sentAt: new Date().toISOString(),
	};

	const recipients = chat.users.filter((user) => user !== username);
	if (recipients.length === 0) {
		console.error("Cannot send a message without another chat participant.");
		return;
	}

	const unacceptedRecipients: string[] = [];
	for (const recipient of recipients) {
		if (!canInteractWithChat(chat)) {
			console.error("A chat participant is no longer your friend; the message was not sent to remaining participants.");
			return;
		}
		const invite: ChatEnvelope = {
			kind: "chat_invite",
			chat: { id: chat.id, kind: chat.kind, users: chat.users },
		};
		if (!await sendEnvelope(recipient, invite)) {
			unacceptedRecipients.push(recipient);
			continue;
		}
		if (!canInteractWithChat(chat)) {
			console.error("A chat participant is no longer your friend; the message was not sent.");
			return;
		}
		const accepted = await sendMessageAndWaitForAcceptance(recipient, {
			kind: "chat_message",
			chatId: chat.id,
			message,
		});
		if (!accepted) {
			unacceptedRecipients.push(recipient);
		}
	}

	if (unacceptedRecipients.length > 0) {
		console.error(
			`Message not saved: ${unacceptedRecipients.join(", ")} did not accept it. ` +
			"They may be offline or unable to accept the chat.",
		);
		return;
	}

	chat.addMessage(message);
	if (!state.chats.some(({ id }) => id === chat.id)) {
		state.chats.push(chat);
	}
	saveChats(username, state.chats);
}

function getAcceptanceKey(username: string, messageId: string): string {
	return `${username}:${messageId}`;
}

function getInvitationKey(username: string, chatId: string): string {
	return `${username}:${chatId}`;
}

async function sendMessageAndWaitForAcceptance(
	username: string,
	envelope: Extract<ChatEnvelope, { kind: "chat_message" }>,
): Promise<boolean> {
	const acceptanceKey = getAcceptanceKey(username, envelope.message.id);
	let timeout: ReturnType<typeof setTimeout> | undefined;

	const acceptancePromise = new Promise<boolean>((resolve) => {
		pendingMessageAcceptances.set(acceptanceKey, {
			chatId: envelope.chatId,
			resolve: (accepted) => {
			if (timeout) {
				clearTimeout(timeout);
			}
			resolve(accepted);
			},
		});
		timeout = setTimeout(() => {
			pendingMessageAcceptances.delete(acceptanceKey);
			resolve(false);
		}, messageAcceptanceTimeoutMs);
	});

	try {
		const delivered = await sendEnvelope(username, envelope);
		if (!delivered) {
			const pending = pendingMessageAcceptances.get(acceptanceKey);
			pendingMessageAcceptances.delete(acceptanceKey);
			pending?.resolve(false);
		}
		return await acceptancePromise;
	} catch (error) {
		const pending = pendingMessageAcceptances.get(acceptanceKey);
		pendingMessageAcceptances.delete(acceptanceKey);
		pending?.resolve(false);
		throw error;
	}
}

function parseEnvelope(raw: string): ChatEnvelope | null {
	let value: unknown;
	try {
		value = JSON.parse(raw);
	} catch {
		return null;
	}

	if (typeof value !== "object" || value === null || !("kind" in value)) {
		return null;
	}
	if (
		value.kind === "friend_request" ||
		value.kind === "friend_accepted" ||
		value.kind === "friend_removed"
	) {
		return { kind: value.kind };
	}
	if (
		value.kind === "chat_invite" &&
		"chat" in value &&
		typeof value.chat === "object" &&
		value.chat !== null &&
		"id" in value.chat &&
		typeof value.chat.id === "string" &&
		"kind" in value.chat &&
		(value.chat.kind === "dm" || value.chat.kind === "group") &&
		"users" in value.chat &&
		Array.isArray(value.chat.users) &&
		value.chat.users.every((user: unknown) => typeof user === "string")
	) {
		return {
			kind: "chat_invite",
			chat: {
				id: value.chat.id,
				kind: value.chat.kind,
				users: value.chat.users as string[],
			},
		};
	}
	if (
		value.kind === "chat_message" &&
		"chatId" in value &&
		typeof value.chatId === "string" &&
		"message" in value &&
		typeof value.message === "object" &&
		value.message !== null &&
		"id" in value.message &&
		typeof value.message.id === "string" &&
		"sender" in value.message &&
		typeof value.message.sender === "string" &&
		"text" in value.message &&
		typeof value.message.text === "string" &&
		"sentAt" in value.message &&
		typeof value.message.sentAt === "string"
	) {
		return {
			kind: "chat_message",
			chatId: value.chatId,
			message: {
				id: value.message.id,
				sender: value.message.sender,
				text: value.message.text,
				sentAt: value.message.sentAt,
			},
		};
	}
	if (
		value.kind === "message_accepted" &&
		"chatId" in value &&
		typeof value.chatId === "string" &&
		"messageId" in value &&
		typeof value.messageId === "string"
	) {
		return {
			kind: "message_accepted",
			chatId: value.chatId,
			messageId: value.messageId,
		};
	}
	return null;
}

async function handleIncomingMessage(sender: string, raw: string): Promise<void> {
	const username = state.username;
	if (!state.loggedIn || !username) {
		console.error("Ignored a message received while signed out.");
		return;
	}

	let envelope: ChatEnvelope;
	try {
		envelope = await decryptEnvelope(raw);
	} catch (error) {
		console.error(`Could not decrypt a message from ${sender}.`, error);
		return;
	}

	if (
		(envelope.kind === "chat_invite" ||
			envelope.kind === "chat_message" ||
			envelope.kind === "message_accepted") &&
		!state.friends.friends.includes(sender)
	) {
		console.error("Ignored chat message from a non-friend.");
		return;
	}

	if (envelope.kind === "message_accepted") {
		const acceptanceKey = getAcceptanceKey(sender, envelope.messageId);
		const pending = pendingMessageAcceptances.get(acceptanceKey);
		if (pending?.chatId === envelope.chatId) {
			pendingMessageAcceptances.delete(acceptanceKey);
			pending.resolve(true);
		}
		return;
	}

	if (envelope.kind === "friend_request") {
		if (!isValidUsername(sender) || sender === username) {
			console.error(`Ignored an invalid friend request from ${sender}.`);
			return;
		}
		if (state.friends.friends.includes(sender)) {
			void sendEnvelope(sender, { kind: "friend_accepted" });
			return;
		}
		if (!state.friends.requests.includes(sender)) {
			state.friends.requests.push(sender);
			saveFriends(username, state.friends);
			if (state.showNotifications) {
				console.log(`\nFriend request from ${sender}.`);
			}
		}
		return;
	}

	if (envelope.kind === "friend_accepted") {
		if (!isValidUsername(sender) || !state.friends.sentRequests.includes(sender)) {
			console.error(`Ignored an unexpected friend acceptance from ${sender}.`);
			return;
		}
		state.friends.sentRequests = state.friends.sentRequests.filter((user) => user !== sender);
		if (!state.friends.friends.includes(sender)) {
			state.friends.friends.push(sender);
		}
		saveFriends(username, state.friends);
		if (state.showNotifications) {
			console.log(`\n${sender} accepted your friend request.`);
		}
		return;
	}

	if (envelope.kind === "friend_removed") {
		state.friends.friends = state.friends.friends.filter((user) => user !== sender);
		state.friends.requests = state.friends.requests.filter((user) => user !== sender);
		state.friends.sentRequests = state.friends.sentRequests.filter((user) => user !== sender);
		saveFriends(username, state.friends);
		clearUnavailableChats();
		if (state.showNotifications) {
			console.log(`\n${sender} removed you from their friends.`);
		}
		return;
	}

	if (envelope.kind === "chat_invite") {
		const users = envelope.chat.users.map(normalizeUsername);
		if (
			sender === username ||
			!users.includes(username) ||
			!users.includes(sender) ||
			new Set(users).size !== users.length ||
			users.some((user) => !isValidUsername(user)) ||
			users.some((user) => user !== username && !state.friends.friends.includes(user)) ||
			(envelope.chat.kind === "dm" &&
				(users.length !== 2 || envelope.chat.id !== directChatId(users))) ||
			(envelope.chat.kind === "group" && users.length < 3)
		) {
			console.error(`Ignored an invalid chat invitation from ${sender}.`);
			return;
		}

		const existing = state.chats.find(({ id }) => id === envelope.chat.id);
		if (existing) {
			if (
				existing.kind !== envelope.chat.kind ||
				JSON.stringify([...existing.users].sort()) !== JSON.stringify([...users].sort())
			) {
				console.error(`Ignored a conflicting chat invitation from ${sender}.`);
			}
			return;
		}

		pendingChatInvitations.set(
			getInvitationKey(sender, envelope.chat.id),
			new Chat(envelope.chat.id, envelope.chat.kind, users),
		);
		return;
	}

	const chat = state.chats.find(({ id }) => id === envelope.chatId);
	const invitationKey = getInvitationKey(sender, envelope.chatId);
	const invitedChat = pendingChatInvitations.get(invitationKey);
	const acceptedChat = chat ?? invitedChat;
	if (
		!acceptedChat ||
		!acceptedChat.users.includes(username) ||
		!acceptedChat.users.includes(sender) ||
		envelope.message.sender !== sender ||
		!canInteractWithChat(acceptedChat)
	) {
		console.error(`Ignored a message from ${sender}: no matching chat exists or a participant is not your friend.`);
		return;
	}

	const updatedChat = new Chat(
		acceptedChat.id,
		acceptedChat.kind,
		acceptedChat.users,
		acceptedChat.messages,
	);
	updatedChat.addMessage(envelope.message);
	const updatedChats = chat
		? state.chats.map((item) => item.id === updatedChat.id ? updatedChat : item)
		: [...state.chats, updatedChat];
	try {
		saveChats(username, updatedChats);
	} catch (error) {
		console.error(`Could not save the accepted message from ${sender}.`, error);
		return;
	}

	state.chats = updatedChats;
	if (state.currentChat?.id === updatedChat.id) {
		state.currentChat = updatedChat;
	}
	pendingChatInvitations.delete(invitationKey);
	if (!state.onlyLogCurrentChat || state.currentChat?.id === updatedChat.id) {
		const timestamp = state.showTimestamps ? `[${envelope.message.sentAt}] ` : "";
		console.log(`\n${timestamp}${sender}: ${envelope.message.text}`);
	}
	void sendEnvelope(sender, {
		kind: "message_accepted",
		chatId: envelope.chatId,
		messageId: envelope.message.id,
	}).catch((error: unknown) => {
		console.error(`Could not confirm message acceptance to ${sender}.`, error);
	});
}

async function createDirectChat(): Promise<Chat | undefined> {
	const currentUser = state.username;
	if (!currentUser) {
		return undefined;
	}

	const otherUser = normalizeUsername(await input({ message: "Username to add" }));
	if (!isValidUsername(otherUser) || otherUser === currentUser) {
		console.error("Enter a valid username other than your own.");
		return undefined;
	}
	if (!state.friends.friends.includes(otherUser)) {
		console.error(`${otherUser} must be your friend before you can create a direct chat.`);
		return undefined;
	}

	let chat = state.chats.find(
		(candidate) =>
			candidate.kind === "dm" &&
			candidate.id === directChatId([currentUser, otherUser]),
	);
	if (!chat) {
		chat = new Chat(directChatId([currentUser, otherUser]), "dm", [currentUser, otherUser]);
		state.chats.push(chat);
	}
	return chat;
}

async function createGroupChat(): Promise<Chat | undefined> {
	const currentUser = state.username;
	if (!currentUser) {
		return undefined;
	}

	const enteredUsers = await input({
		message: "Group members (comma-separated usernames)",
	});
	const users = [...new Set([
		currentUser,
		...enteredUsers.split(",").map(normalizeUsername).filter(Boolean),
	])];
	if (users.length < 3 || users.some((user) => !isValidUsername(user))) {
		console.error("A group needs at least two other valid usernames.");
		return undefined;
	}
	const nonFriends = users.filter(
		(user) => user !== currentUser && !state.friends.friends.includes(user),
	);
	if (nonFriends.length > 0) {
		console.error(`Add these users as friends before creating the group: ${nonFriends.join(", ")}.`);
		return undefined;
	}

	const chat = new Chat(randomUUID(), "group", users);
	state.chats.push(chat);
	return chat;
}

function showChatList(): void {
	const availableChats = state.chats.filter(canInteractWithChat);
	if (availableChats.length === 0) {
		console.log("No chats. Use :chat create to start one.");
		return;
	}
	for (const [index, chat] of availableChats.entries()) {
		const selected = state.currentChat?.id === chat.id ? " *" : "";
		console.log(`${index + 1}. ${chatLabel(chat)} [${chat.kind}] (${chat.id})${selected}`);
	}
}

function showHelp(): void {
	console.log(`Commands:
  :chat create              Create a direct message or group chat
  :chat list                List your chats
  :chat goto <number|id>    Select a chat
  :chat goto null           Clear the selected chat
  :friend add <username>    Send a friend request (recipient must be online)
  :friend accept <username> Accept a friend request
  :friend reject <username> Reject a friend request
  :friend unadd <username>  Remove a friend
  :friend list              List friends and pending requests
  :settings                 Show client settings
  :settings log-current-chat <on|off>
                            Only print live messages for the selected chat
  :settings timestamps <on|off>
                            Show timestamps with messages
  :settings notifications <on|off>
                            Show friend and chat status notices
  :help                     Show this help
  :exit                     Exit the client

Type a message only after selecting a chat.`);
}

async function createChatFromCommand(): Promise<void> {
	const kind = await select({
		message: "What kind of chat?",
		choices: [
			{ name: "Direct message", value: "dm" },
			{ name: "Group chat", value: "group" },
		],
	});
	const chat = kind === "dm" ? await createDirectChat() : await createGroupChat();
	if (chat) {
		state.currentChat = chat;
	}
}

function goToChat(argument: string | undefined): void {
	if (!argument) {
		console.error("Usage: :chat goto <number|id|null>");
		showChatList();
		return;
	}
	if (argument.toLowerCase() === "null" || argument.toLowerCase() === "none") {
		state.currentChat = null;
		return;
	}

	const index = Number(argument);
	const availableChats = state.chats.filter(canInteractWithChat);
	const chat = Number.isInteger(index) && index > 0
		? availableChats[index - 1]
		: availableChats.find(({ id }) => id === argument);
	if (!chat) {
		console.error(`No chat matches "${argument}".`);
		return;
	}
	state.currentChat = chat;
	for (const message of chat.messages) {
		const timestamp = state.showTimestamps ? `[${message.sentAt}] ` : "";
		console.log(`${timestamp}${message.sender}: ${message.text}`);
	}
}

async function runChatCommand(args: string[]): Promise<void> {
	const [action, argument] = args;
	switch (action) {
		case "create":
			await createChatFromCommand();
			break;
		case "list":
			showChatList();
			break;
		case "goto":
			goToChat(argument);
			break;
		default:
			console.error("Usage: :chat <create|list|goto>");
			break;
	}
}

async function runFriendCommand(args: string[]): Promise<void> {
	const [action, rawUsername] = args;
	const currentUser = state.username;
	if (!currentUser) {
		console.error("Sign in before managing friends.");
		return;
	}

	if (action === "list") {
		console.log(`Friends: ${state.friends.friends.join(", ") || "(none)"}`);
		console.log(`Incoming requests: ${state.friends.requests.join(", ") || "(none)"}`);
		console.log(`Outgoing requests: ${state.friends.sentRequests.join(", ") || "(none)"}`);
		return;
	}
	if (!action || !["add", "accept", "reject", "unadd"].includes(action)) {
		console.error("Usage: :friend <add|accept|reject|unadd|list> [username]");
		return;
	}
	if (!rawUsername) {
		console.error(`Usage: :friend ${action} <username>`);
		return;
	}

	const username = normalizeUsername(rawUsername);
	if (!isValidUsername(username) || username === currentUser) {
		console.error("Enter a valid username other than your own.");
		return;
	}

	if (action === "add") {
		if (state.friends.friends.includes(username)) {
			console.log(`${username} is already a friend.`);
			return;
		}
		if (state.friends.sentRequests.includes(username)) {
			console.log(`You already sent a request to ${username}.`);
			return;
		}
		if (!await sendEnvelope(username, { kind: "friend_request" })) {
			console.error(`${username} must be online to receive your friend request.`);
			return;
		}
		state.friends.sentRequests.push(username);
		saveFriends(currentUser, state.friends);
		return;
	}

	if (action === "accept") {
		if (!state.friends.requests.includes(username)) {
			console.error(`There is no pending friend request from ${username}.`);
			return;
		}
		if (!await sendEnvelope(username, { kind: "friend_accepted" })) {
			console.error(`${username} must be online to confirm the friend request.`);
			return;
		}
		state.friends.requests = state.friends.requests.filter((user) => user !== username);
		if (!state.friends.friends.includes(username)) {
			state.friends.friends.push(username);
		}
		saveFriends(currentUser, state.friends);
		return;
	}

	if (action === "reject") {
		if (!state.friends.requests.includes(username)) {
			console.error(`There is no pending friend request from ${username}.`);
			return;
		}
		state.friends.requests = state.friends.requests.filter((user) => user !== username);
		saveFriends(currentUser, state.friends);
		return;
	}

	if (!state.friends.friends.includes(username)) {
		console.error(`${username} is not in your friends list.`);
		return;
	}
	state.friends.friends = state.friends.friends.filter((user) => user !== username);
	state.friends.requests = state.friends.requests.filter((user) => user !== username);
	state.friends.sentRequests = state.friends.sentRequests.filter((user) => user !== username);
	saveFriends(currentUser, state.friends);
	clearUnavailableChats();
	await sendEnvelope(username, { kind: "friend_removed" });
}

function runSettingsCommand(args: string[]): void {
	const [setting, value] = args;
	const username = state.username;
	if (!username) {
		console.error("Sign in before changing settings.");
		return;
	}
	if (!setting) {
		console.log(`log-current-chat: ${state.onlyLogCurrentChat ? "on" : "off"}`);
		console.log(`timestamps: ${state.showTimestamps ? "on" : "off"}`);
		console.log(`notifications: ${state.showNotifications ? "on" : "off"}`);
		return;
	}
	if (!value || (value !== "on" && value !== "off") || args.length !== 2) {
		console.error("Usage: :settings [log-current-chat|timestamps|notifications <on|off>]");
		return;
	}
	switch (setting) {
		case "log-current-chat":
			state.onlyLogCurrentChat = value === "on";
			break;
		case "timestamps":
			state.showTimestamps = value === "on";
			break;
		case "notifications":
			state.showNotifications = value === "on";
			break;
		default:
			console.error("Usage: :settings [log-current-chat|timestamps|notifications <on|off>]");
			return;
	}
	saveUserSettings(username, {
		onlyLogCurrentChat: state.onlyLogCurrentChat,
		showTimestamps: state.showTimestamps,
		showNotifications: state.showNotifications,
	});
}

async function runCommand(line: string): Promise<boolean> {
	const [command, ...args] = line.slice(1).trim().split(/\s+/);
	if (!command) {
		console.error("Enter a command after ':'. Use :help for commands.");
		return true;
	}
	switch (command.toLowerCase()) {
		case "help":
			showHelp();
			break;
		case "chat":
			await runChatCommand(args);
			break;
		case "friend":
			await runFriendCommand(args);
			break;
		case "settings":
			runSettingsCommand(args);
			break;
		case "exit":
			return false;
		default:
			console.error(`Unknown command: ${command}. Use :help.`);
			break;
	}
	return true;
}

async function runCommandShell(): Promise<void> {
	showHelp();
	while (state.loggedIn && ws.readyState === WebSocket.OPEN) {
		const chatLabelText = state.currentChat ? chatLabel(state.currentChat) : "null";
		const line = await input({ message: `[${chatLabelText}]>` });
		if (line.trim().startsWith(":")) {
			if (!await runCommand(line.trim())) {
				return;
			}
			continue;
		}
		if (!line.trim()) {
			continue;
		}
		if (!state.currentChat) {
			console.error("No chat selected; messages cannot be sent. Use :chat create or :chat goto.");
			continue;
		}
		await sendChatMessage(state.currentChat, line);
	}
}

async function main(): Promise<void> {
	await new Promise<void>((resolve, reject) => {
		ws.once("open", resolve);
		ws.once("error", reject);
	});
	while (ws.readyState === WebSocket.OPEN) {
		if (state.loggedIn) {
			await runCommandShell();
			if (state.loggedIn) {
				break;
			}
			continue;
		}

		const action = await select({
			message: "Choose an option",
			choices: [
				{ name: "Sign up", value: "signup" },
				{ name: "Sign in", value: "signin" },
				{ name: "Exit", value: "exit" },
			],
		});
		if (action === "exit") {
			break;
		}
		if (action === "signup") {
			await createAccount();
		} else {
			await signInPrompt();
		}
	}

	ws.close();
}

main().catch((error: unknown) => {
	if (error instanceof Error && error.name === "ExitPromptError") {
		ws.close();
		return;
	}
	console.error("Client stopped because of an error.", error);
	ws.close();
	process.exitCode = 1;
});
