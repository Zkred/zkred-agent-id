/**
 * Metadata management functions for Identity Registry
 */
import { ethers } from "ethers";
import { SupportedChainId, MetadataEntry } from "../types";
import { getRegistryContract, getSigner } from "./registry";
import { handleError } from "../utils/errors";

/**
 * Set metadata for an agent
 * @param privateKey - Private key of the agent owner
 * @param agentId - Agent ID (token ID)
 * @param key - Metadata key
 * @param value - Metadata value (string or bytes)
 * @param chainId - Chain ID
 * @param rpcUrl - Optional RPC URL override
 * @returns Transaction hash
 */
export async function setMetadata(
  privateKey: string,
  agentId: number,
  key: string,
  value: string | Uint8Array,
  chainId: SupportedChainId,
  rpcUrl?: string
): Promise<string> {
  try {
    const signer = getSigner(privateKey, chainId, rpcUrl);
    const registry = getRegistryContract(chainId, signer, rpcUrl);

    // Convert value to bytes - ethers handles the conversion automatically
    // For strings, convert to UTF-8 bytes; for Uint8Array, use as-is
    const valueBytes =
      typeof value === "string" ? ethers.toUtf8Bytes(value) : value;

    const tx = await registry.setMetadata(agentId, key, valueBytes);
    await tx.wait();

    return tx.hash;
  } catch (err: any) {
    handleError(err);
  }
}

/**
 * Add or append DID as metadata
 * @param privateKey - Private key of the agent owner
 * @param agentId - Agent ID (token ID)
 * @param did - DID to add as metadata
 * @param chainId - Chain ID
 * @param rpcUrl - Optional RPC URL override
 * @returns Transaction hash
 */
export async function addDIDAsMetadata(
  privateKey: string,
  agentId: number,
  did: string,
  chainId: SupportedChainId,
  rpcUrl?: string
): Promise<string> {
  return setMetadata(privateKey, agentId, "did", did, chainId, rpcUrl);
}

/**
 * Add or update agent-to-agent (a2a) endpoint as metadata
 * @param privateKey - Private key of the agent owner
 * @param agentId - Agent ID (token ID)
 * @param endpoint - A2A endpoint URL (e.g., "https://agent.example.com/a2a")
 * @param chainId - Chain ID
 * @param rpcUrl - Optional RPC URL override
 * @returns Transaction hash
 */
export async function addA2AEndpoint(
  privateKey: string,
  agentId: number,
  endpoint: string,
  chainId: SupportedChainId,
  rpcUrl?: string
): Promise<string> {
  // Validate URL format
  try {
    new URL(endpoint);
  } catch {
    throw new Error("Invalid endpoint URL format");
  }

  return setMetadata(
    privateKey,
    agentId,
    "a2a_endpoint",
    endpoint,
    chainId,
    rpcUrl
  );
}

/**
 * Set multiple metadata entries for an agent
 * @param privateKey - Private key of the agent owner
 * @param agentId - Agent ID (token ID)
 * @param metadata - Array of metadata entries
 * @param chainId - Chain ID
 * @param rpcUrl - Optional RPC URL override
 * @returns Transaction hash
 */
export async function setMultipleMetadata(
  privateKey: string,
  agentId: number,
  metadata: MetadataEntry[],
  chainId: SupportedChainId,
  rpcUrl?: string
): Promise<string> {
  try {
    const signer = getSigner(privateKey, chainId, rpcUrl);
    const registry = getRegistryContract(chainId, signer, rpcUrl);

    // Set each metadata entry in a batch
    const txs = await Promise.all(
      metadata.map((entry) => {
        const valueBytes =
          typeof entry.value === "string"
            ? ethers.toUtf8Bytes(entry.value)
            : entry.value;
        return registry.setMetadata(agentId, entry.key, valueBytes);
      })
    );

    // Wait for all transactions
    await Promise.all(txs.map((tx) => tx.wait()));

    // Return the hash of the last transaction
    return txs[txs.length - 1].hash;
  } catch (err: any) {
    handleError(err);
  }
}

/**
 * Update the token URI for an agent
 * @param privateKey - Private key of the agent owner
 * @param agentId - Agent ID (token ID)
 * @param newTokenURI - New token URI string
 * @param chainId - Chain ID
 * @param rpcUrl - Optional RPC URL override
 * @returns Transaction hash
 */
export async function updateTokenURI(
  privateKey: string,
  agentId: number,
  newTokenURI: string,
  chainId: SupportedChainId,
  rpcUrl?: string
): Promise<string> {
  try {
    const signer = getSigner(privateKey, chainId, rpcUrl);
    const registry = getRegistryContract(chainId, signer, rpcUrl);

    const tx = await registry.setAgentUri(agentId, newTokenURI);
    await tx.wait();

    return tx.hash;
  } catch (err: any) {
    handleError(err);
  }
}
