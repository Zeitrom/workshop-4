import bodyParser from "body-parser";
import express from "express";
import { BASE_USER_PORT } from "../config";
import { Node } from "../registry/registry";
import { rsaEncrypt, createRandomSymmetricKey, exportSymKey, symEncrypt } from "../crypto";
import { BASE_ONION_ROUTER_PORT } from "../config";
import { REGISTRY_PORT } from "../config";

export type SendMessageBody = {
  message: string;
  destinationUserId: number;
};

export async function user(userId: number) {
  const _user = express();
  _user.use(express.json());
  _user.use(bodyParser.json());

  // TODO implement the status route
  _user.get("/status", (req, res) => {res.send("live")});
  
  let lastSentMessage: string | null = null;

 
  _user.get("/getLastSentMessage", (req, res) => {res.json({ result: lastSentMessage })});
  
  const lastReceivedMessages: { [userId: number]: string } = {};
  _user.post("/message", (req, res) => {
    const { message }: SendMessageBody = req.body;
    lastReceivedMessages[userId] = message;
    res.send("success");
  });

  _user.get("/getLastReceivedMessage", (req, res) => {
    if (lastReceivedMessages[userId] == null) {
      res.json({result: null});
    }
    else {
      res.json({ result: lastReceivedMessages[userId] });
    }
  });
  const server = _user.listen(BASE_USER_PORT + userId, () => {
    console.log(
      `User ${userId} is listening on port ${BASE_USER_PORT + userId}`
    );
  });

  let lastCircuit: Node[] = [];
  
  _user.get("/getLastCircuit", async  (req, res) => {
    res.json({ result: lastCircuit.map((node) => node.nodeId) });
  });

  _user.post("/sendMessage", async (req, res) => {
    const { message, destinationUserId } = req.body;
    
    let circuit: Node[] = [];

    const nodes = await fetch(`http://localhost:${REGISTRY_PORT}/getNodeRegistry`)
      .then((res) => res.json())
      .then((body: any) => body.nodes);

    while (circuit.length < 3) {
      const randomIndex = Math.floor(Math.random() * nodes.length);
      if (!circuit.includes(nodes[randomIndex])) {
        circuit.push(nodes[randomIndex]);
      }
    }

    lastSentMessage = message;
    let messageToSend = lastSentMessage;
    let destination = `${BASE_USER_PORT + destinationUserId}`.padStart(10, "0");
    
    const encryptedLayers = circuit.map(async (node) => {
      const symKey = await createRandomSymmetricKey();
      const messageToEncrypt = `${destination + messageToSend}`;
      destination = `${BASE_ONION_ROUTER_PORT + node.nodeId}`.padStart(10, "0");
      const encryptedMessage = await symEncrypt(symKey, messageToEncrypt);
      const encryptedSymKey = await rsaEncrypt(await exportSymKey(symKey), node.pubKey);
      return encryptedSymKey + encryptedMessage;
    });
    
    messageToSend = await Promise.all(encryptedLayers).then((layers) => layers.reduce((acc, layer) => acc + layer));
    

    circuit.reverse();

    lastCircuit = circuit;
    await fetch(`http://localhost:${BASE_ONION_ROUTER_PORT + circuit[0].nodeId}/message`, {
      method: "POST",
      body: JSON.stringify({ message: messageToSend }),
      headers: {
        "Content-Type": "application/json",
      },
    });

    res.send("success");
  });

  return server;
}
