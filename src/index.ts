import crypto from "node:crypto";
import { sha256, getBytes, hexlify, toUtf8String } from "ethers";
import * as sigFormatter from "ecdsa-sig-formatter";
import base64url from "base64url";

// Types

interface KeyPair {
  publicKey: string;
  privateKey: string;
}

interface SignatureFormats {
  der: {
    base64: string;
    hex: string;
  };
  jose: string;
  components: {
    r: string;
    s: string;
  };
}

interface DecryptionResult {
  plaintext: string;
  plaintextHex: string;
}

// Constants
const CANDIDATE_KEYS: readonly string[] = [
  "68544020247570407220244063724074",
  "54684020247570407220244063724074",
  "54684020247570407220244063727440",
] as const;

const TARGET_HASH: string = "f28fe539655fd6f7275a09b7c3508a3f81573fc42827ce34ddf1ec8d5c2421c3";

const IV_HEX: string = "656e6372797074696f6e496e74566563";

const CIPHERTEXT_HEX: string = "876b4e970c3516f333bcf5f16d546a87aaeea5588ead29d213557efc1903997e";

// Utility functions
const addHexPrefix = (hex: string): `0x${string}` => {
  return (hex.startsWith("0x") ? hex : `0x${hex}`) as `0x${string}`;
};

const validateBufferLength = (buffer: Buffer, expectedLength: number, name: string): void => {
  if (buffer.length !== expectedLength) {
    throw new Error(`${name} must be ${expectedLength} bytes, got ${buffer.length}`);
  }
};

// Find symmetric key
const findCorrectSymmetricKey = (candidates: readonly string[], targetHash: string): string | null => {
  for (const candidate of candidates) {
    try {
      const keyBytes: Uint8Array = getBytes(addHexPrefix(candidate));
      const hash: string = sha256(keyBytes).slice(2);
      
      if (hash === targetHash) {
        return candidate;
      }
    } catch (error) {
      console.error(`Error processing candidate ${candidate}:`, error);
    }
  }
  
  return null;
};

// AES decryption
const decryptAES128CBC = (keyHex: string, ivHex: string, ciphertextHex: string): DecryptionResult => {
  const key: Uint8Array = getBytes(addHexPrefix(keyHex));
  const iv: Uint8Array = getBytes(addHexPrefix(ivHex));
  const ciphertext: Uint8Array = getBytes(addHexPrefix(ciphertextHex));

  validateBufferLength(Buffer.from(key), 16, "AES-128 key");
  validateBufferLength(Buffer.from(iv), 16, "CBC IV");

  try {
    const decipher = crypto.createDecipheriv("aes-128-cbc", key, iv);
    const updateResult = decipher.update(ciphertext as any);
    const finalResult = decipher.final();
    const plaintext = new Uint8Array([...updateResult, ...finalResult]);

    const plaintextStr: string = toUtf8String(plaintext as any);
    const plaintextHex: string = hexlify(plaintext as any);

    return {
      plaintext: plaintextStr,
      plaintextHex: plaintextHex
    };
  } catch (error) {
    throw new Error(`Decryption failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
};

// Generate ECDSA keys
const generateECDSAKeyPair = (): KeyPair => {
  try {
    const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", {
      namedCurve: "P-256",
      publicKeyEncoding: { 
        type: "spki", 
        format: "pem" 
      },
      privateKeyEncoding: { 
        type: "pkcs8", 
        format: "pem" 
      },
    });

    return { publicKey, privateKey };
  } catch (error) {
    throw new Error(`Key generation failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
};

// Digital signatures
const createSignature = (data: Uint8Array, privateKey: string): SignatureFormats => {
  try {
    const signer = crypto.createSign("SHA256");
    signer.update(data);
    signer.end();
    const signatureDer: Buffer = signer.sign(privateKey);

    const signatureDerBase64: string = signatureDer.toString("base64");
    const signatureDerHex: string = hexlify(signatureDer as any);

    const joseSignature: string = sigFormatter.derToJose(signatureDer, "ES256");

    const rs: Uint8Array = base64url.toBuffer(joseSignature) as Uint8Array;
    const rHex: string = hexlify(rs.subarray(0, 32) as any);
    const sHex: string = hexlify(rs.subarray(32, 64) as any);

    return {
      der: {
        base64: signatureDerBase64,
        hex: signatureDerHex
      },
      jose: joseSignature,
      components: {
        r: rHex,
        s: sHex
      }
    };
  } catch (error) {
    throw new Error(`Signature creation failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
};

const verifySignature = (data: Uint8Array, signature: Buffer, publicKey: string): boolean => {
  try {
    const verifier = crypto.createVerify("SHA256");
    verifier.update(data);
    verifier.end();
    const isValid: boolean = verifier.verify(publicKey, signature as any);

    return isValid;
  } catch (error) {
    console.error(`Verification failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    return false;
  }
};

// Main execution
const main = (): void => {
  try {
    const correctKey: string | null = findCorrectSymmetricKey(CANDIDATE_KEYS, TARGET_HASH);
    
    if (!correctKey) {
      console.error("No matching key found.");
      process.exit(1);
    }

    console.log(`Key found: ${correctKey}`);
    console.log(`ASCII: ${Buffer.from(getBytes(addHexPrefix(correctKey))).toString("utf8")}`);

    const decryptionResult: DecryptionResult = decryptAES128CBC(correctKey, IV_HEX, CIPHERTEXT_HEX);
    console.log(`Decrypted: ${decryptionResult.plaintext}`);

    const keyPair: KeyPair = generateECDSAKeyPair();
    const plaintextBuffer: Uint8Array = new TextEncoder().encode(decryptionResult.plaintext);
    const signatureFormats: SignatureFormats = createSignature(plaintextBuffer, keyPair.privateKey);

    const isSignatureValid: boolean = verifySignature(
      plaintextBuffer, 
      Buffer.from(signatureFormats.der.base64, 'base64'), 
      keyPair.publicKey
    );

    console.log(`Signature valid: ${isSignatureValid}`);

  } catch (error) {
    console.error("Error:", error instanceof Error ? error.message : 'Unknown error');
    process.exit(1);
  }
};

// Run the main function
main();
