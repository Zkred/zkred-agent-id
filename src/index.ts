/**
 * zkred-agent-id
 * Main entry point for the SDK
 */

// General utilities
export { generateDID, getETHPublicKeyFromDID } from "./utils/did";

export { generatePrivateKey, generateChallenge } from "./utils/crypto";

export { verifySignature } from "./utils/signature";

export { initiateHandshake, completeHandshake } from "./utils/handshake";

// Contract functions - Registration
export { register } from "./contract/registration";

// Contract functions - Metadata
export {
  setMetadata,
  addDIDAsMetadata,
  addA2AEndpoint,
  setMultipleMetadata,
  updateTokenURI,
} from "./contract/metadata";

// Contract functions - Viewer
export {
  getDID,
  getA2AEndpoint,
  validateAgent,
  getTokenURI,
  getOwner,
  getMetadata,
} from "./contract/viewer";

// Contract utilities
export {
  getRegistryContract,
  getProvider,
  getSigner,
  getContractVersion,
} from "./contract/registry";

// Config
export {
  getChainConfig,
  getRpcUrl,
  getRegistryAddress,
  CHAIN_CONFIGS,
} from "./config/chains";

// Types
export type {
  SupportedChainId,
  ChainConfig,
  MetadataEntry,
  RegistrationResult,
  AgentDetails,
  HandshakeInitiationResult,
} from "./types";
