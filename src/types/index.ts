/**
 * Type definitions for zkred-agent-id SDK
 */

export type SupportedChainId =
  | 80002 // Polygon Amoy
  | 11155111 // Sepolia
  | 296 // Hedera Testnet
  | 84532 // Base Sepolia
  | 421614 // Arbitrum Sepolia
  | 324705682; // Skale Base Sepolia

export interface ChainConfig {
  name: string;
  chainId: SupportedChainId;
  rpcUrl: string;
  identityRegistryV1: string;
  identityRegistryProxy: string;
}

export interface MetadataEntry {
  key: string;
  value: string | Uint8Array;
}

export interface RegistrationResult {
  txHash: string;
  agentId: number;
  did?: string;
  tokenURI?: string;
}

export interface AgentDetails {
  did: string;
  agentId: number;
  description?: string;
  serviceEndPoint?: string;
  owner?: string;
  tokenURI?: string;
}

export interface HandshakeInitiationResult {
  sessionId: number;
  receiverAgentCallbackEndPoint: string;
  challenge: string;
}
