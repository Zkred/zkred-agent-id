/**
 * Viewer functions for reading from the Identity Registry contract
 */
import { ethers } from "ethers";
import { SupportedChainId, AgentDetails } from "../types";
import { getRegistryContract, getProvider } from "./registry";
import { getETHPublicKeyFromDID } from "../utils/did";
import { handleError } from "../utils/errors";

/**
 * Get DID for an agent by agent ID
 * Note: This function attempts to get DID from metadata. If DID is stored in metadata with key "did",
 * it will return that. Otherwise, it will try to get it from tokenURI or return null.
 * @param agentId - Agent ID (token ID)
 * @param chainId - Chain ID
 * @param rpcUrl - Optional RPC URL override
 * @returns DID string or null if not found
 */
export async function getDID(
  agentId: number,
  chainId: SupportedChainId,
  rpcUrl?: string
): Promise<string | null> {
  try {
    const provider = getProvider(chainId, rpcUrl);
    const registry = getRegistryContract(chainId, provider, rpcUrl);

    // First, try to get DID from metadata
    try {
      const didBytes = await registry.getMetadata(agentId, "did");
      if (didBytes && didBytes.length > 0) {
        // Convert bytes to string
        const did = ethers.toUtf8String(didBytes);
        return did;
      }
    } catch (err) {
      // Metadata key "did" might not exist, continue to other methods
    }

    // If not in metadata, we can't reliably get DID from just the agentId
    // The DID is typically generated from the owner's address
    // For now, return null - users should use validateAgent with the DID instead
    return null;
  } catch (err: any) {
    handleError(err);
  }
}

/**
 * Validate agent registration and get agent details
 * @param did - DID of the agent
 * @param chainId - Chain ID
 * @param rpcUrl - Optional RPC URL override
 * @returns Agent details or null if not found
 */
export async function validateAgent(
  did: string,
  chainId: SupportedChainId,
  rpcUrl?: string
): Promise<AgentDetails | null> {
  try {
    const ethAddress = getETHPublicKeyFromDID(did);
    if (!ethAddress) {
      throw new Error("Invalid DID format or not Ethereum-controlled");
    }

    const provider = getProvider(chainId, rpcUrl);
    const registry = getRegistryContract(chainId, provider, rpcUrl);

    // Check if the address owns any tokens
    const balance = await registry.balanceOf(ethAddress);
    if (Number(balance) === 0) {
      return null;
    }

    // Since we can't directly query by address, we need to find the token ID
    // This is a limitation - we'd need to track token IDs or use events
    // For now, we'll return basic info based on the DID
    // In a production system, you'd want to maintain an index of address -> tokenId

    // Try to get tokenURI if we can determine the tokenId
    // For now, return what we can determine from the DID
    return {
      did,
      agentId: 0, // Cannot determine without tokenId
      owner: ethAddress,
    };
  } catch (err: any) {
    // If balanceOf fails, the address might not be registered
    if (
      err.message?.includes("ERC721NonexistentToken") ||
      err.message?.includes("balance")
    ) {
      return null;
    }
    handleError(err);
  }
}

/**
 * Get token URI for an agent
 * @param agentId - Agent ID (token ID)
 * @param chainId - Chain ID
 * @param rpcUrl - Optional RPC URL override
 * @returns Token URI string
 */
export async function getTokenURI(
  agentId: number,
  chainId: SupportedChainId,
  rpcUrl?: string
): Promise<string> {
  try {
    const provider = getProvider(chainId, rpcUrl);
    const registry = getRegistryContract(chainId, provider, rpcUrl);
    return await registry.tokenURI(agentId);
  } catch (err: any) {
    handleError(err);
  }
}

/**
 * Get owner of an agent token
 * @param agentId - Agent ID (token ID)
 * @param chainId - Chain ID
 * @param rpcUrl - Optional RPC URL override
 * @returns Owner address
 */
export async function getOwner(
  agentId: number,
  chainId: SupportedChainId,
  rpcUrl?: string
): Promise<string> {
  try {
    const provider = getProvider(chainId, rpcUrl);
    const registry = getRegistryContract(chainId, provider, rpcUrl);
    return await registry.ownerOf(agentId);
  } catch (err: any) {
    handleError(err);
  }
}

/**
 * Get metadata for an agent
 * @param agentId - Agent ID (token ID)
 * @param key - Metadata key
 * @param chainId - Chain ID
 * @param rpcUrl - Optional RPC URL override
 * @returns Metadata value as bytes
 */
export async function getMetadata(
  agentId: number,
  key: string,
  chainId: SupportedChainId,
  rpcUrl?: string
): Promise<string> {
  try {
    const provider = getProvider(chainId, rpcUrl);
    const registry = getRegistryContract(chainId, provider, rpcUrl);
    const metadataBytes = await registry.getMetadata(agentId, key);
    return metadataBytes;
  } catch (err: any) {
    handleError(err);
  }
}

/**
 * Get custom metadata for an agent
 * Convenience function for retrieving any custom metadata by key
 * Returns the value as a UTF-8 string (for string values) or null if not found
 * @param agentId - Agent ID (token ID)
 * @param key - Custom metadata key (e.g., "website", "email", "description")
 * @param chainId - Chain ID
 * @param rpcUrl - Optional RPC URL override
 * @returns Metadata value as string or null if not found
 */
export async function getCustomMetadata(
  agentId: number,
  key: string,
  chainId: SupportedChainId,
  rpcUrl?: string
): Promise<string | null> {
  try {
    const provider = getProvider(chainId, rpcUrl);
    const registry = getRegistryContract(chainId, provider, rpcUrl);

    try {
      const metadataBytes = await registry.getMetadata(agentId, key);
      if (metadataBytes && metadataBytes.length > 0) {
        // Convert bytes to UTF-8 string
        return ethers.toUtf8String(metadataBytes);
      }
    } catch (err) {
      // Metadata key might not exist
      return null;
    }

    return null;
  } catch (err: any) {
    // If metadata doesn't exist, return null instead of throwing
    if (
      err.message?.includes("metadata") ||
      err.message?.includes("not found")
    ) {
      return null;
    }
    handleError(err);
  }
}

/**
 * Get agent-to-agent (a2a) endpoint from metadata
 * @param agentId - Agent ID (token ID)
 * @param chainId - Chain ID
 * @param rpcUrl - Optional RPC URL override
 * @returns A2A endpoint URL string or null if not found
 */
export async function getA2AEndpoint(
  agentId: number,
  chainId: SupportedChainId,
  rpcUrl?: string
): Promise<string | null> {
  try {
    const provider = getProvider(chainId, rpcUrl);
    const registry = getRegistryContract(chainId, provider, rpcUrl);

    try {
      const endpointBytes = await registry.getMetadata(agentId, "a2a_endpoint");
      if (endpointBytes && endpointBytes.length > 0) {
        // Convert bytes to string
        const endpoint = ethers.toUtf8String(endpointBytes);
        return endpoint;
      }
    } catch (err) {
      // Metadata key "a2a_endpoint" might not exist
      return null;
    }

    return null;
  } catch (err: any) {
    handleError(err);
  }
}
