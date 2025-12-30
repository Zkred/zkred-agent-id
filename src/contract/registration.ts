/**
 * Agent registration functions for Identity Registry
 */
import { ethers } from "ethers";
import { SupportedChainId, RegistrationResult } from "../types";
import { getRegistryContract, getSigner } from "./registry";
import { generateDID } from "../utils/did";
import { handleError } from "../utils/errors";

/**
 * Extract agentId from transaction receipt by parsing Registered event
 */
function extractAgentIdFromReceipt(
  receipt: ethers.TransactionReceipt,
  registry: ethers.Contract
): number {
  if (!receipt || !receipt.logs) {
    throw new Error("Invalid transaction receipt");
  }

  // Find the Registered event
  for (const log of receipt.logs) {
    try {
      const parsed = registry.interface.parseLog(log);
      if (parsed && parsed.name === "Registered") {
        return Number(parsed.args.agentId);
      }
    } catch {
      // Continue to next log
      continue;
    }
  }

  throw new Error("Could not find Registered event in transaction receipt");
}

/**
 * Register agent with optional token URI, DID metadata, and A2A endpoint
 * @param privateKey - Private key of the wallet to register
 * @param chainId - Chain ID
 * @param tokenURI - Optional token URI string
 * @param addDid - If true, calculate DID from public key using "privado:main" and add to metadata
 * @param a2aEndpoint - Optional A2A endpoint URL to add as metadata
 * @param rpcUrl - Optional RPC URL override
 * @returns Registration result with txHash, agentId, and optionally tokenURI and did
 */
export async function register(
  privateKey: string,
  chainId: SupportedChainId,
  tokenURI?: string,
  addDid?: boolean,
  a2aEndpoint?: string,
  rpcUrl?: string
): Promise<RegistrationResult> {
  try {
    const shouldAddDid = addDid || false;
    const signer = getSigner(privateKey, chainId, rpcUrl);
    const registry = getRegistryContract(chainId, signer, rpcUrl);

    // Check if already registered by checking balance
    const publicKey = signer.address;
    try {
      const balance = await registry.balanceOf(publicKey);
      if (Number(balance) > 0) {
        throw new Error("Agent already registered");
      }
    } catch (err: any) {
      if (err.message?.includes("already registered")) {
        throw err;
      }
      // If balanceOf fails for other reasons, continue with registration
    }

    // Validate A2A endpoint if provided
    if (a2aEndpoint) {
      try {
        new URL(a2aEndpoint);
      } catch {
        throw new Error("Invalid A2A endpoint URL format");
      }
    }

    let tx: ethers.TransactionResponse;
    let did: string | undefined;

    // Generate DID if addDid is true
    if (shouldAddDid) {
      did = generateDID(publicKey);
    }

    // Build metadata array if needed
    const hasMetadata = shouldAddDid || a2aEndpoint;
    const metadata: Array<{ key: string; value: Uint8Array }> = [];

    if (shouldAddDid && did) {
      metadata.push({
        key: "did",
        value: ethers.toUtf8Bytes(did),
      });
    }

    if (a2aEndpoint) {
      metadata.push({
        key: "a2a_endpoint",
        value: ethers.toUtf8Bytes(a2aEndpoint),
      });
    }

    // Determine which register function to call based on provided options
    if (hasMetadata) {
      // Register with tokenURI and metadata
      const finalTokenURI = tokenURI || "";
      tx = await registry.register(finalTokenURI, metadata);
    } else if (tokenURI) {
      // Register with tokenURI only
      tx = await registry.register(tokenURI);
    } else {
      // Simple registration (no tokenURI, no metadata)
      tx = await registry.register();
    }

    const receipt = await tx.wait();
    if (!receipt) {
      throw new Error("Transaction receipt is null");
    }

    // Extract agentId from Registered event
    const agentId = extractAgentIdFromReceipt(receipt, registry);

    const result: RegistrationResult = {
      txHash: tx.hash,
      agentId,
    };

    // Add optional fields
    if (tokenURI) {
      result.tokenURI = tokenURI;
    }

    if (did) {
      result.did = did;
    }

    return result;
  } catch (err: any) {
    handleError(err);
  }
}
