/**
 * Registry contract utilities
 */
import { ethers } from "ethers";
import { SupportedChainId } from "../types";
import { getRpcUrl, getRegistryAddress } from "../config/chains";
import identityRegistryABI from "../contracts/IndentityRegistry.json";

/**
 * Get a contract instance for the Identity Registry
 * @param chainId - Chain ID
 * @param signerOrProvider - Signer or provider instance
 * @param rpcUrl - Optional RPC URL override
 * @returns Contract instance
 */
export function getRegistryContract(
  chainId: SupportedChainId,
  signerOrProvider: ethers.Signer | ethers.Provider,
  rpcUrl?: string
): ethers.Contract {
  const registryAddress = getRegistryAddress(chainId);
  return new ethers.Contract(
    registryAddress,
    identityRegistryABI.abi,
    signerOrProvider
  );
}

/**
 * Get a provider for a chain
 * @param chainId - Chain ID
 * @param rpcUrl - Optional RPC URL override
 * @returns Provider instance
 */
export function getProvider(
  chainId: SupportedChainId,
  rpcUrl?: string
): ethers.JsonRpcProvider {
  const url = getRpcUrl(chainId, rpcUrl);
  return new ethers.JsonRpcProvider(url);
}

/**
 * Get a signer from private key
 * @param privateKey - Private key (0x-prefixed, 64 hex chars)
 * @param chainId - Chain ID
 * @param rpcUrl - Optional RPC URL override
 * @returns Signer instance
 */
export function getSigner(
  privateKey: string,
  chainId: SupportedChainId,
  rpcUrl?: string
): ethers.Wallet {
  if (!/^0x[0-9a-fA-F]{64}$/.test(privateKey)) {
    throw new Error("Private key must be a 0x-prefixed 64-hex string");
  }

  const provider = getProvider(chainId, rpcUrl);
  return new ethers.Wallet(privateKey, provider);
}

/**
 * Get the contract version
 * Useful for proxy contracts to check which implementation version is active
 * @param chainId - Chain ID
 * @param rpcUrl - Optional RPC URL override
 * @returns Contract version string
 */
export async function getContractVersion(
  chainId: SupportedChainId,
  rpcUrl?: string
): Promise<string> {
  try {
    const provider = getProvider(chainId, rpcUrl);
    const registry = getRegistryContract(chainId, provider, rpcUrl);
    return await registry.getVersion();
  } catch (err: any) {
    throw new Error(`Failed to get contract version: ${err.message}`);
  }
}
