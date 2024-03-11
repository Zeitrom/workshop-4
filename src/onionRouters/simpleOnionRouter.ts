import bodyParser from "body-parser";
import { generateRsaKeyPair, exportPubKey, exportPrvKey, importPrvKey, rsaDecrypt, symDecrypt } from "../crypto";
import { REGISTRY_PORT } from "../config";
import express from "express";

import { BASE_ONION_ROUTER_PORT } from "../config";

export async function simpleOnionRouter(nodeId: number) {
  const onionRouter = express();
  onionRouter.use(express.json());
  onionRouter.use(bodyParser.json());

  onionRouter.get("/status", (req, res) => {res.send("live");});

  let lastReceivedEncryptedMessage: string | null = null;
  let lastMessageDestination: number | null = null;

  onionRouter.get("/getLastReceivedEncryptedMessage", (req, res) => {res.json({ result: lastReceivedEncryptedMessage })});
  
  onionRouter.get("/getLastReceivedDecryptedMessage", (req , res) => {res.json({ result: lastReceivedEncryptedMessage })});
  
  onionRouter.get("/getLastMessageDestination", (req, res) => {res.json({ result: lastMessageDestination })});
 
  const keyPair = await generateRsaKeyPair();
  onionRouter.get("/getPublicKey", (req, res) => {
    res.json({ result: keyPair.publicKey });
  });

  const publicKey = await exportPubKey(keyPair.publicKey);
  onionRouter.get("/getPublicKey", (req, res) => {
    res.json({ result: publicKey });
  });

  const privateKey = await exportPrvKey(keyPair.privateKey);
  onionRouter.get("/getPrivateKey", (req, res) => {
    res.json({ result: privateKey });
  });

  let lastMessageSource: number | null = null;
  onionRouter.get("/getLastMessageSource", (req, res) => {
    res.json({ result: lastMessageSource });
  });

  const response = await fetch(`http://localhost:${REGISTRY_PORT}/registerNode`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      nodeId,
      pubKey: publicKey,
    }),
  });
  
  
  
  const server = onionRouter.listen(BASE_ONION_ROUTER_PORT + nodeId, () => {
    console.log(
      `Onion router ${nodeId} is listening on port ${
        BASE_ONION_ROUTER_PORT + nodeId
      }`
    );
  });

  return server;
}
