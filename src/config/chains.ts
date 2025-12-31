/**
 * Chain configuration for all supported networks
 */
import { ChainConfig, SupportedChainId } from "../types";

export const CHAIN_CONFIGS: Record<SupportedChainId, ChainConfig> = {
  80002: {
    name: "polygon-amoy",
    chainId: 80002,
    rpcUrl: "https://rpc-amoy.polygon.technology",
    identityRegistryV1: "0x304eEa4f6f32e3a7B270DBf292D5f4eeeFe55873",
    identityRegistryProxy: "0xb75eB3D776711E87240E5ff6DA7B81e12fd37f83",
  },
  11155111: {
    name: "sepolia",
    chainId: 11155111,
    rpcUrl: "https://ethereum-sepolia-rpc.publicnode.com",
    identityRegistryV1: "0x5fcDB5665F62fAf9DD3121BBd21ddAD17694ED2E",
    identityRegistryProxy: "0x1CceBD36C61ee36629073f297682AE63E7eAEC84",
  },
  296: {
    name: "hedera-testnet",
    chainId: 296,
    rpcUrl: "https://testnet.hashio.io/api",
    identityRegistryV1: "0x266cd7890184A012692803422532370a867739EA",
    identityRegistryProxy: "0x5c282DA873A9f87C702d39CfdF12cAe2deC9eFD2",
  },
  324705682: {
    name: "skale-base-sepolia",
    chainId: 324705682,
    rpcUrl:
      "https://base-sepolia-testnet.skalenodes.com/v1/jubilant-horrible-ancha",
    identityRegistryV1: "0x0bD4BeBeB972f5C12faC137f85463B87bf5A2885",
    identityRegistryProxy: "0xF90bf1e2147b109bE3506C9Ec4F8cC2CEBdd7022",
  },
  421614: {
    name: "arbitrum-sepolia",
    chainId: 421614,
    rpcUrl: "https://endpoints.omniatech.io/v1/arbitrum/sepolia/public",
    identityRegistryV1: "0xFbFe1BDFe13624B153B9590d7a19c4E4A53B1D04",
    identityRegistryProxy: "0x9CBa4f02F33A9e79052d422B3C9526B407d96A93",
  },
  84532: {
    name: "base-sepolia",
    chainId: 84532,
    rpcUrl: "https://base-sepolia-public.nodies.app",
    identityRegistryV1: "0x1355A5EB488769448fAEF3652E8F77Ec58Eb8C44",
    identityRegistryProxy: "0xFbFe1BDFe13624B153B9590d7a19c4E4A53B1D04",
  },
};

/**
 * Get chain configuration by chain ID
 */
export function getChainConfig(chainId: SupportedChainId): ChainConfig {
  const config = CHAIN_CONFIGS[chainId];
  if (!config) {
    throw new Error(`Unsupported chain ID: ${chainId}`);
  }
  return config;
}

/**
 * Get RPC URL for a chain, with optional override
 */
export function getRpcUrl(
  chainId: SupportedChainId,
  overrideRpcUrl?: string
): string {
  if (overrideRpcUrl) {
    return overrideRpcUrl;
  }
  return getChainConfig(chainId).rpcUrl;
}

/**
 * Get registry contract address for a chain
 * Always returns the proxy contract address
 */
export function getRegistryAddress(chainId: SupportedChainId): string {
  const config = getChainConfig(chainId);
  return config.identityRegistryProxy;
}
