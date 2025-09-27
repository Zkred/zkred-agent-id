/**
 * zkred-agent-id
 * Main entry point for the package
 */
import bs58 from "bs58";
import crc from "crc";
import { ethers } from "ethers";
import identityRegistryABI from "./contracts/IndentityRegistry.json";
import {
  AMOY_RPC_URL,
  IDENTITY_REGISTRY_AMOY,
  HEDERA_RPC_URL,
  IDENTITY_REGISTRY_HEDERA,
  X402_API_URL,
  OG_RPC_URL,
  IDENTITY_REGISTRY_OG,
} from "./config";
import axios from "axios";
// @ts-ignore
import { withPaymentInterceptor, decodeXPaymentResponse } from "x402-axios";
import { Hex } from "viem";
import { privateKeyToAccount } from "viem/accounts";

const TYPES = {
  AgentRegistration: [
    { name: "agent", type: "address" },
    { name: "did", type: "string" },
    { name: "description", type: "string" },
    { name: "serviceEndpoint", type: "string" },
    { name: "nonce", type: "uint256" },
    { name: "expiry", type: "uint256" },
  ],
};

function setRpcUrl(chainId: 80002 | 296 | 16602, rpcUrl: string = "") {
  if (!rpcUrl) {
    if (chainId === 80002) {
      rpcUrl = AMOY_RPC_URL;
    }
    if (chainId === 296) {
      rpcUrl = HEDERA_RPC_URL;
    }
    if (chainId === 16602) {
      rpcUrl = OG_RPC_URL;
    }
  }
  return rpcUrl;
}

function handleError(err: any) {
  let errorMessage = "Unknown error";
  // Check for ethers specific error structure
  if (err.reason) {
    errorMessage = err.reason;
  } else if (err.error && err.error.message) {
    errorMessage = err.error.message;
  } else if (err.message) {
    errorMessage = err.message;
  } else if (err.revert && err.revert.args && err.revert.args.length > 0) {
    errorMessage = err.revert.args[0];
  }
  throw new Error(errorMessage);
}

function generateChallenge(length = 10) {
  const chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  let result = "";
  for (let i = 0; i < length; i++) {
    const randomIndex = Math.floor(Math.random() * chars.length);
    result += chars[randomIndex];
  }
  return result;
}

/**
 * Generate Privado ID DID from Ethereum address
 * @param ethAddress Ethereum address (0x-prefixed, 20 bytes)
 * @param chain "polygon"
 * @param network "amoy" | "main" | etc.
 * @returns DID string
 */
function generateDID(
  ethAddress: string,
  chain: string,
  network: string
): string {
  // Normalize address
  const addrBytes = Buffer.from(ethAddress.replace(/^0x/, ""), "hex");
  if (addrBytes.length !== 20) {
    throw new Error("Ethereum address must be 20 bytes");
  }

  // Step 1: idType (2 bytes)
  const idType = Buffer.from([0x0d, 0x01]); // standard for iden3

  // Step 2: zero padding (7 bytes)
  const zeroPadding = Buffer.alloc(7, 0);

  // Step 3: assemble first 29 bytes
  const base = Buffer.concat([idType, zeroPadding, addrBytes]); // 29 bytes

  // Step 4: checksum (CRC16, 2 bytes LE)
  const checksumVal = crc.crc16xmodem(base);
  const checksum = Buffer.alloc(2);
  checksum.writeUInt16LE(checksumVal);

  // Step 5: final 31 bytes
  const fullBytes = Buffer.concat([base, checksum]);

  // Step 6: Base58 encode
  const base58Id = bs58.encode(fullBytes);

  // Step 7: Assemble DID
  return `did:iden3:${chain}:${network}:${base58Id}`;
}

/**
 * Decode public key from did:iden3 DID
 * @param didFull - Full DID string, e.g. "did:iden3:polygon:amoy:x6x5sor7zpyT5mmpg4fADaR47NADVbohtww4ppWZF"
 * @returns Ethereum public key (hex) or null if not Ethereum-controlled
 */
function getETHPublicKeyFromDID(didFull: string): string | null {
  try {
    // Extract Base58 part
    const parts = didFull.split(":");
    if (parts.length < 5) throw new Error("Invalid DID format");
    const base58Id = parts[4];

    // Decode Base58 to bytes
    const decodedBytes = bs58.decode(base58Id);

    if (decodedBytes.length !== 31) {
      throw new Error("Unexpected decoded length, must be 31 bytes");
    }

    // Split fields according to spec
    const idType = decodedBytes.slice(0, 2); // 2 bytes
    const zeroPadding = decodedBytes.slice(2, 9); // 7 bytes
    const ethBytes = decodedBytes.slice(9, 29); // 20 bytes
    const checksum = decodedBytes.slice(29, 31); // 2 bytes

    // Check if it's Ethereum-controlled DID (zero padding)
    const isEthereumControlled = zeroPadding.every((b) => b === 0);

    if (!isEthereumControlled) {
      console.warn(
        "This DID is NOT Ethereum-controlled, genesis state is non-zero"
      );
      return null;
    }

    // Convert ETH address bytes to hex string
    const ethAddress = "0x" + Buffer.from(ethBytes).toString("hex");
    return ethAddress;
  } catch (err) {
    console.error("Error decoding DID:", err);
    return null;
  }
}

/**
 * Register agent to central Registry
 * @param privateKey  - privateKey of wallet to register
 * @param description - Description of the agent
 * @param chainId - Chain Id
 * @param serviceEndpoint - Service endpoint URL
 * @param rpcUrl - RPC url for the chain
 */
async function createIdentity(
  privateKey: string,
  description: string,
  chainId: 80002 | 296 | 16602,
  serviceEndpoint: string,
  rpcUrl: string = ""
) {
  try {
    // set rpcUrl if not provided based on chainId
    rpcUrl = setRpcUrl(chainId, rpcUrl);

    // Generate public key from privateKey using ethers
    if (!/^0x[0-9a-fA-F]{64}$/.test(privateKey)) {
      throw new Error("Private key must be a 0x-prefixed 64-hex string");
    }

    const publicKey = ethers.computeAddress(privateKey);
    // Generate signer
    const provider = new ethers.JsonRpcProvider(rpcUrl as string);
    const signer = new ethers.Wallet(privateKey, provider);

    // Decide registry contract based on chain
    let REGISTRY_CONTRACT = IDENTITY_REGISTRY_AMOY;
    if (chainId === 296) REGISTRY_CONTRACT = IDENTITY_REGISTRY_HEDERA;
    if (chainId === 16602) REGISTRY_CONTRACT = IDENTITY_REGISTRY_OG;
    const registry = new ethers.Contract(
      REGISTRY_CONTRACT,
      identityRegistryABI.abi,
      signer
    );
    const registrationFee = ethers.parseEther("0.01");

    let agentDetails;
    try {
      agentDetails = await registry.getAgentByAddress(publicKey);
    } catch (err: any) {
      console.log("Error ==> ", err?.message);
    }

    if (agentDetails?.length) {
      throw new Error("Agent already registered");
    }

    const did = generateDID(publicKey, "privado", "main");
    const tx = await registry.registerAgent(did, description, serviceEndpoint, {
      value: registrationFee,
    });

    await tx.wait();

    await new Promise((resolve) => setTimeout(resolve, 5000));
    const agent = await registry.getAgentByAddress(publicKey);

    return {
      txHash: tx.hash,
      did,
      description,
      serviceEndpoint,
      agentId: BigInt(agent[1]),
    };
  } catch (err: any) {
    handleError(err);
  }
}

/**
 * Validate agent registration
 * @param did
 * @param chainId
 * @param rpcUrl
 * @returns
 */
async function validateAgent(
  did: string,
  chainId: 80002 | 296 | 16602,
  rpcUrl: string = ""
) {
  try {
    rpcUrl = setRpcUrl(chainId, rpcUrl);

    // Decide registry contract based on chain
    let REGISTRY_CONTRACT = IDENTITY_REGISTRY_AMOY;
    if (chainId === 296) REGISTRY_CONTRACT = IDENTITY_REGISTRY_HEDERA;
    if (chainId === 16602) REGISTRY_CONTRACT = IDENTITY_REGISTRY_OG;

    const ethAddress = getETHPublicKeyFromDID(did);
    const provider = new ethers.JsonRpcProvider(rpcUrl as string);
    const registry = new ethers.Contract(
      REGISTRY_CONTRACT,
      identityRegistryABI.abi,
      provider
    );
    const agentDetails = await registry.getAgentByAddress(ethAddress);
    return {
      did: agentDetails[0],
      agentId: Number(agentDetails[1]),
      description: agentDetails[2],
      serviceEndPoint: agentDetails[3],
    };
  } catch (err: any) {
    handleError(err);
  }
}

async function registerAgentByUSDC(
  privateKey: string,
  description: string,
  chainId: 80002 | 296 | 16602,
  serviceEndpoint: string,
  rpcUrl: string = ""
) {
  return new Promise(async (resolve, reject) => {
    try {
      rpcUrl = setRpcUrl(chainId, rpcUrl);

      // crate signature
      const provider = new ethers.JsonRpcProvider(rpcUrl as string);
      const signer = new ethers.Wallet(privateKey, provider);
      const did = generateDID(signer.address, "polygon", "amoy");

      let REGISTRY_CONTRACT = IDENTITY_REGISTRY_AMOY;
      if (chainId === 296) REGISTRY_CONTRACT = IDENTITY_REGISTRY_HEDERA;
      if (chainId === 16602) REGISTRY_CONTRACT = IDENTITY_REGISTRY_OG;

      const registry = new ethers.Contract(
        REGISTRY_CONTRACT,
        identityRegistryABI.abi,
        signer
      );
      // Get current nonce
      const nonce = await registry.nonces(signer.address);

      const request = {
        agent: signer.address.toLowerCase(),
        did: did,
        description: description,
        serviceEndpoint: serviceEndpoint,
        nonce: BigInt(nonce),
        expiry: BigInt(Math.floor(Date.now() / 1000) + 1800),
      };

      const sigBody = {
        agent: signer.address.toLowerCase(),
        did: did,
        description: description,
        serviceEndpoint: serviceEndpoint,
        nonce: Number(nonce),
        expiry: Math.floor(Date.now() / 1000) + 1800,
      };

      const DOMAIN = {
        name: "AgentRegistry",
        version: "1",
        chainId: chainId,
        verifyingContract: (REGISTRY_CONTRACT as string).toLowerCase(),
      };

      const signature = await signer.signTypedData(DOMAIN, TYPES, request);

      // TODO :: call x402 api and in response we'll get txHash and agentId
      const account = privateKeyToAccount(privateKey as Hex);
      const api = withPaymentInterceptor(
        axios.create({
          baseURL: X402_API_URL,
        }),
        account
      );

      const x402Payload = {
        chainId,
        address: signer.address,
        signatureBody: sigBody,
        signature,
      };

      api
        .post("/register", x402Payload)
        .then(async (response: any) => {
          await decodeXPaymentResponse(response.headers["x-payment-response"]);
          resolve({
            txHash: response?.data?.data?.hash,
            did,
            description,
            serviceEndpoint,
            agentId: response?.data?.data?.agentId,
          });
        })
        .catch(async (error: any) => {
          console.log(
            "Initial error received (expected with withPaymentInterceptor):"
          );

          // Check if this is a payment-related error from the interceptor
          if (error.response?.headers?.["x-payment-request"]) {
            console.log(
              "Payment request detected, interceptor should handle this automatically"
            );
            // The interceptor will automatically handle this and retry
            // Don't reject the promise here, just log and wait
            return; // Important: don't reject the promise
          }
          // If it's a different error, log it and reject
          console.error("Unexpected error:", error?.message);
          reject(error);
        });
    } catch (err: any) {
      console.error("Error in registerAgentByUSDC:", err);
      reject(err);
    }
  });
}

/**
 * Generate private key
 * @returns
 */
function generatePrivateKey() {
  const wallet = ethers.Wallet.createRandom();
  return wallet.privateKey;
}

/**
 * initiate handshake between two agents
 * @param initiatorChainId
 * @param initiatorDid
 * @param receiverChainId
 * @param receiverDid
 * @param initiatorRpcUrl
 * @param receiverRpcUrl
 * @returns
 */
async function initiateHandshake(
  initiatorDid: string,
  initiatorChainId: 80002 | 296 | 16602,
  receiverDid: string,
  receiverChainId: 80002 | 296 | 16602,
  initiatorRpcUrl: string = "",
  receiverRpcUrl: string = ""
) {
  const sessionId = Date.now();
  initiatorRpcUrl = setRpcUrl(initiatorChainId, initiatorRpcUrl);
  receiverRpcUrl = setRpcUrl(receiverChainId, receiverRpcUrl);

  const initiatorAgent = await validateAgent(
    initiatorDid,
    initiatorChainId,
    initiatorRpcUrl
  );

  if (!initiatorAgent) {
    throw new Error("Initiator agent not found");
  }
  // Get service endpoint of receiver
  const receiverAgent = await validateAgent(
    receiverDid,
    receiverChainId,
    receiverRpcUrl
  );

  if (!receiverAgent) {
    throw new Error("Receiver agent not found");
  }

  // Call receiver agent's /initiate url
  try {
    const response = await axios.post(
      `${receiverAgent?.serviceEndPoint}/initiate`,
      {
        sessionId,
        initiatorDid,
        initiatorChainId,
      }
    );

    return {
      sessionId,
      receiverAgentCallbackEndPoint: `${receiverAgent?.serviceEndPoint}/callback`,
      challenge: response?.data?.data?.challenge,
    };
  } catch (err) {
    throw err;
  }
}

/**
 *
 * @param privateKey
 * @param sessionId
 * @param receiverAgentCallbackEndPoint
 * @param challenge
 * @returns
 */
async function copmleteHandshake(
  privateKey: string,
  sessionId: string,
  receiverAgentCallbackEndPoint: string,
  challenge: string
) {
  const message = JSON.stringify({
    sessionId,
    challenge,
  });

  const wallet = new ethers.Wallet(privateKey);
  const signature = await wallet.signMessage(message);

  // call service endpoint of receiver with signature
  try {
    const response = await axios.post(receiverAgentCallbackEndPoint, {
      sessionId,
      challenge,
      signature,
    });

    if (
      response?.data?.data?.sessionId === sessionId &&
      response?.data?.data?.status === "handshake_completed"
    ) {
      return true;
    }
  } catch (err) {
    return false;
  }
}

/**
 *
 * @param sessionId
 * @param challenge
 * @param signature
 * @param did
 * @returns
 */
function verifySignature(
  sessionId: string,
  challenge: string,
  signature: string,
  did: string
) {
  const message = JSON.stringify({
    sessionId,
    challenge,
  });
  const recoveredAddress = ethers.verifyMessage(message, signature);
  const derivedAddress = getETHPublicKeyFromDID(did);

  return recoveredAddress?.toLowerCase() === derivedAddress?.toLowerCase();
}

// Export all public functions and types
export default {
  generateDID,
  getETHPublicKeyFromDID,
  createIdentity,
  validateAgent,
  registerAgentByUSDC,
  generatePrivateKey,
  generateChallenge,
  verifySignature,
  copmleteHandshake,
  initiateHandshake,
};
