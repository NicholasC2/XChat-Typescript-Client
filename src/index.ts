import { WebSocket } from "ws";
import { Data, DataType } from "./data.js";
import { input, select } from "@inquirer/prompts";
import { generateKeyPairSync } from "node:crypto";
import { writeFileSync } from "node:fs";

const ws = new WebSocket("wss://chat.nicholasc.net/");

ws.on("message", (data) => {
	const parsed: Data = JSON.parse(data.toString());

	switch (parsed.type) {
		case DataType.SIGNUP_SUCCESSFUL: {
			console.log("Sign up successful");
			break;
		}
	}
});

console.log("Connecting...");

ws.on("open", async () => {
	console.log("Connected");

    let running = true;

    while(running) {
        const answer = await select({
            message: "Choose an option",
            choices: [
                {
                    name: "Sign up",
                    value: "signup",
                },
                {
                    name: "Sign in",
                    value: "signin",
                },
                {
                    name: "Exit",
                    value: "exit",
                },
            ],
        });

        if (answer === "exit") {
            ws.close();
            running = false;
            process.exit()
        }

        if (answer === "signup") {
            const username = await input({
                message: "Username: ",
            });

            const { publicKey, privateKey } = generateKeyPairSync("rsa", {
                modulusLength: 2048,
            });

            const privateKeyDer = privateKey.export({
                type: "pkcs8",
                format: "der",
            });

            writeFileSync("./private.key", privateKeyDer);

            const publicKeyDer = publicKey.export({
                type: "spki",
                format: "der",
            });

            const publicKeyBase64 = publicKeyDer.toString("base64");

            ws.send(
                JSON.stringify({
                    type: DataType.SIGNUP,
                    data: {
                        username,
                        key: publicKeyBase64,
                    },
                } satisfies Data),
            );
        }

        if(answer == "signin") {
            
        }
    }
});
