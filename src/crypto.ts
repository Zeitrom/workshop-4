import { webcrypto } from "crypto";

// #############
// ### Utils ###
// #############

// Function to convert ArrayBuffer to Base64 string
function arrayBufferToBase64(buffer: ArrayBuffer): string {
  return Buffer.from(buffer).toString("base64");
}

// Function to convert Base64 string to ArrayBuffer
function base64ToArrayBuffer(base64: string): ArrayBuffer {
  var buff = Buffer.from(base64, "base64");
  return buff.buffer.slice(buff.byteOffset, buff.byteOffset + buff.byteLength);
}

// ################
// ### RSA keys ###
// ################

// Generates a pair of private / public RSA keys
type GenerateRsaKeyPair = {
  publicKey: webcrypto.CryptoKey;
  privateKey: webcrypto.CryptoKey;
};
export async function generateRsaKeyPair(): Promise<GenerateRsaKeyPair> {
  // TODO implement this function using the crypto package to generate a public and private RSA key pair.
  //      the public key should be used for encryption and the private key for decryption. Make sure the
  //      keys are extractable.

  const keyPair = await crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 2048,
      publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
      hash: "SHA-256",
    },
    true,
    ["encrypt", "decrypt"]
  );
  return { publicKey: keyPair.publicKey, privateKey: keyPair.privateKey };

}

// Export a crypto public key to a base64 string format
export async function exportPubKey(key: webcrypto.CryptoKey): Promise<string> {
  // TODO implement this function to return a base64 string version of a public key

  const exportedKey = await webcrypto.subtle.exportKey("spki", key);
  const base64Key = arrayBufferToBase64(exportedKey);
  return base64Key;
}

// Export a crypto private key to a base64 string format
export async function exportPrvKey(
  key: webcrypto.CryptoKey | null
): Promise<string | null> {
  // TODO implement this function to return a base64 string version of a private key
  if (!key) {
    return null;
  }
  const exportedKey = await webcrypto.subtle.exportKey("pkcs8", key);
  const base64Key = arrayBufferToBase64(exportedKey);
  return base64Key;
}

// Import a base64 string public key to its native format
export async function importPubKey(
  strKey: string
): Promise<webcrypto.CryptoKey> {
  const arrayBufferKey = base64ToArrayBuffer(strKey);
  const importedKey = await webcrypto.subtle.importKey(
    "spki",
    arrayBufferKey,
    {
      name: "RSA-OAEP",
      hash: "SHA-256",
    },
    true,
    ["encrypt"]
  );
  return importedKey;
  return {} as any;
}

// Import a base64 string private key to its native format
export async function importPrvKey(
  strKey: string
): Promise<webcrypto.CryptoKey> {
  // TODO implement this function to go back from the result of the exportPrvKey function to it's native crypto key object
  const arrayBufferKey = base64ToArrayBuffer(strKey);
  const importedKey = await webcrypto.subtle.importKey(
    "pkcs8",
    arrayBufferKey,
    {
      name: "RSA-OAEP",
      hash: "SHA-256",
    },
    true,
    ["decrypt"]
  );
  return importedKey;
}

// Encrypt a message using an RSA public key
export async function rsaEncrypt(
  b64Data: string,
  strPublicKey: string
): Promise<string> {
  // TODO implement this function to encrypt a base64 encoded message with a public key
  // tip: use the provided base64ToArrayBuffer function

  const publicKey = await importPubKey(strPublicKey);
  const data = base64ToArrayBuffer(b64Data);
  const encryptedData = await webcrypto.subtle.encrypt(
    {
      name: "RSA-OAEP",
    },
    publicKey,
    data
  );
  const b64EncryptedData = arrayBufferToBase64(encryptedData);
  return b64EncryptedData;
}

// Decrypts a message using an RSA private key
export async function rsaDecrypt(
  data: string,
  privateKey: webcrypto.CryptoKey
): Promise<string> {
  // TODO implement this function to decrypt a base64 encoded message with a private key
  // tip: use the provided base64ToArrayBuffer function

  const arrayBufferData = base64ToArrayBuffer(data);
  const decryptedData = await webcrypto.subtle.decrypt(
    {
      name: "RSA-OAEP",
    },
    privateKey,
    arrayBufferData
  );
  const b64DecryptedData = arrayBufferToBase64(decryptedData);
  return b64DecryptedData;
}

// ######################
// ### Symmetric keys ###
// ######################

// Generates a random symmetric key
export async function createRandomSymmetricKey(): Promise<webcrypto.CryptoKey> {
  const key = await webcrypto.subtle.generateKey(
    {
      name: "AES-CBC",
      length: 256, // can be  128, 192, or 256
    },
    true, // whether the key is extractable (i.e. can be used in exportKey)
    ["encrypt", "decrypt"] // can be "encrypt", "decrypt", "wrapKey", or "unwrapKey"
  );
  return key;
}

// Export a crypto symmetric key to a base64 string format
export async function exportSymKey(key: webcrypto.CryptoKey): Promise<string> {
  // TODO implement this function to return a base64 string version of a symmetric key

  const exportedKey = await webcrypto.subtle.exportKey("raw", key);
  const base64Key = arrayBufferToBase64(exportedKey);
  return base64Key;
}

// Import a base64 string format to its crypto native format
export async function importSymKey(
  strKey: string
): Promise<webcrypto.CryptoKey> {
  // TODO implement this function to go back from the result of the exportSymKey function to it's native crypto key object

  const arrayBufferKey = base64ToArrayBuffer(strKey);
  const importedKey = await webcrypto.subtle.importKey(
    "raw",
    arrayBufferKey,
    {
      name: "AES-CBC",
      length: 256,
    },
    true,
    ["encrypt", "decrypt"]
  );
  return importedKey;
}

export async function symEncrypt(
  key: webcrypto.CryptoKey,
  data: string
): Promise<string> {
  // TODO implement this function to encrypt a base64 encoded message with a public key
  // tip: encode the data to a uin8array with TextEncoder
  const encoder = new TextEncoder();
  const encodedData = encoder.encode(data);
  const iv = webcrypto.getRandomValues(new Uint8Array(16));
  const encryptedData = await webcrypto.subtle.encrypt(
    { name: "AES-CBC", iv: iv },
    key,
    encodedData
  );
  // Prepend IV to the encrypted data before converting to base64
  const combinedData = new Uint8Array(iv.length + encryptedData.byteLength);
  combinedData.set(iv, 0);
  combinedData.set(new Uint8Array(encryptedData), iv.length);
  const base64EncryptedData = arrayBufferToBase64(combinedData.buffer);
  return base64EncryptedData;
}

// Decrypt a message using a symmetric key
export async function symDecrypt(
  strKey: string,
  encryptedData: string
): Promise<string> {
  // TODO implement this function to decrypt a base64 encoded message with a private key
  // tip: use the provided base64ToArrayBuffer function and use TextDecode to go back to a string format

  const key = await importSymKey(strKey);
  const arrayBufferEncryptedData = base64ToArrayBuffer(encryptedData);
  const iv = arrayBufferEncryptedData.slice(0, 16); // The IV is typically prepended to the encrypted data
  const actualEncryptedData = arrayBufferEncryptedData.slice(16);
  const decryptedData = await webcrypto.subtle.decrypt(
    {
      name: "AES-CBC",
      iv: iv,
    },
    key,
    actualEncryptedData
  );
  const decoder = new TextDecoder();
  const decryptedStr = decoder.decode(decryptedData);
  return decryptedStr; // return base64 string
}
