# zkred-agent-id

A comprehensive SDK for agent identification and management on multiple blockchain networks. This package provides utilities for registering agents, managing metadata, and facilitating agent-to-agent communication using ERC 8004 Identity Registry contracts.

## Installation

```bash
npm install @zkred/agent-id
```

## Supported Networks

The SDK supports the following blockchain networks:

- **Polygon Amoy** (Chain ID: 80002)
- **Sepolia** (Chain ID: 11155111)
- **Hedera Testnet** (Chain ID: 296)
- **Base Sepolia** (Chain ID: 84532)
- **Arbitrum Sepolia** (Chain ID: 421614)
- **Skale Base Sepolia** (Chain ID: 324705682)

## Quick Start

```typescript
import {
  generatePrivateKey,
  register,
  generateDID,
  getDID,
  addA2AEndpoint,
  getA2AEndpoint,
} from "@zkred/agent-id";

// Generate a new private key
const privateKey = generatePrivateKey();

// Register an agent with token URI, DID, and A2A endpoint
const result = await register(
  privateKey,
  80002, // Polygon Amoy
  "https://example.com/token.json", // token URI
  true, // add DID
  "https://agent.example.com/a2a" // A2A endpoint
);

console.log(`Agent registered! ID: ${result.agentId}, DID: ${result.did}`);

// Generate DID from address
const did = generateDID("0x1234...");
console.log(`DID: ${did}`); // did:iden3:privado:main:...

// Get agent's A2A endpoint
const endpoint = await getA2AEndpoint(result.agentId, 80002);
console.log(`A2A Endpoint: ${endpoint}`);
```

## API Reference

### Identity Registry Functions

#### Registration

#### `register(privateKey, chainId, tokenURI?, addDid?, a2aEndpoint?, rpcUrl?)`

Registers an agent on the Identity Registry contract. Supports multiple registration modes.

- **Parameters**:
  - `privateKey`: Private key of the wallet to register
  - `chainId`: Chain ID (see Supported Networks)
  - `tokenURI`: (Optional) Token URI string
  - `addDid`: (Optional) If true, calculates DID from public key and adds to metadata
  - `a2aEndpoint`: (Optional) A2A endpoint URL to add as metadata
  - `rpcUrl`: (Optional) RPC URL override
- **Returns**: `RegistrationResult` with `txHash`, `agentId`, and optionally `tokenURI` and `did`

**Examples:**

```typescript
// Simple registration
const result1 = await register(privateKey, 80002);

// With token URI
const result2 = await register(
  privateKey,
  80002,
  "https://example.com/token.json"
);

// With DID
const result3 = await register(privateKey, 80002, undefined, true);

// With token URI, DID, and A2A endpoint
const result4 = await register(
  privateKey,
  80002,
  "https://example.com/token.json",
  true,
  "https://agent.example.com/a2a"
);
```

### Metadata Management

#### `setMetadata(privateKey, agentId, key, value, chainId, rpcUrl?)`

Sets metadata for an agent. Use this for any custom key-value pairs.

- **Parameters**:
  - `privateKey`: Private key of the agent owner
  - `agentId`: Agent ID (token ID)
  - `key`: Metadata key (e.g., "website", "email", "description")
  - `value`: Metadata value (string or Uint8Array)
  - `chainId`: Chain ID
  - `rpcUrl`: (Optional) RPC URL override
- **Returns**: Transaction hash

```typescript
// Add custom metadata
await setMetadata(privateKey, agentId, "website", "https://myagent.com", 80002);

await setMetadata(privateKey, agentId, "email", "agent@example.com", 80002);
```

#### `addDIDAsMetadata(privateKey, agentId, did, chainId, rpcUrl?)`

Adds or updates DID as metadata.

- **Parameters**:
  - `privateKey`: Private key of the agent owner
  - `agentId`: Agent ID (token ID)
  - `did`: DID string
  - `chainId`: Chain ID
  - `rpcUrl`: (Optional) RPC URL override
- **Returns**: Transaction hash

#### `addA2AEndpoint(privateKey, agentId, endpoint, chainId, rpcUrl?)`

Adds or updates agent-to-agent (a2a) endpoint as metadata.

- **Parameters**:
  - `privateKey`: Private key of the agent owner
  - `agentId`: Agent ID (token ID)
  - `endpoint`: A2A endpoint URL (e.g., "https://agent.example.com/a2a")
  - `chainId`: Chain ID
  - `rpcUrl`: (Optional) RPC URL override
- **Returns**: Transaction hash

```typescript
await addA2AEndpoint(
  privateKey,
  agentId,
  "https://agent.example.com/a2a",
  80002
);
```

#### `setMultipleMetadata(privateKey, agentId, metadata, chainId, rpcUrl?)`

Sets multiple metadata entries for an agent in a batch.

- **Parameters**:
  - `privateKey`: Private key of the agent owner
  - `agentId`: Agent ID (token ID)
  - `metadata`: Array of `MetadataEntry` objects with `key` and `value`
  - `chainId`: Chain ID
  - `rpcUrl`: (Optional) RPC URL override
- **Returns**: Transaction hash

```typescript
await setMultipleMetadata(
  privateKey,
  agentId,
  [
    { key: "website", value: "https://myagent.com" },
    { key: "email", value: "agent@example.com" },
  ],
  80002
);
```

#### `updateTokenURI(privateKey, agentId, newTokenURI, chainId, rpcUrl?)`

Updates the token URI for an agent.

- **Parameters**:
  - `privateKey`: Private key of the agent owner
  - `agentId`: Agent ID (token ID)
  - `newTokenURI`: New token URI string
  - `chainId`: Chain ID
  - `rpcUrl`: (Optional) RPC URL override
- **Returns**: Transaction hash

#### Viewer Functions

#### `getDID(agentId, chainId, rpcUrl?)`

Gets DID for an agent by agent ID from metadata.

- **Parameters**:
  - `agentId`: Agent ID (token ID)
  - `chainId`: Chain ID
  - `rpcUrl`: (Optional) RPC URL override
- **Returns**: DID string or null if not found

#### `getA2AEndpoint(agentId, chainId, rpcUrl?)`

Gets agent-to-agent (a2a) endpoint from metadata.

- **Parameters**:
  - `agentId`: Agent ID (token ID)
  - `chainId`: Chain ID
  - `rpcUrl`: (Optional) RPC URL override
- **Returns**: A2A endpoint URL string or null if not found

#### `getCustomMetadata(agentId, key, chainId, rpcUrl?)`

Gets custom metadata for an agent by key. Returns the value as a UTF-8 string.

- **Parameters**:
  - `agentId`: Agent ID (token ID)
  - `key`: Custom metadata key
  - `chainId`: Chain ID
  - `rpcUrl`: (Optional) RPC URL override
- **Returns**: Metadata value as string or null if not found

```typescript
const website = await getCustomMetadata(agentId, "website", 80002);
const email = await getCustomMetadata(agentId, "email", 80002);
```

#### `getMetadata(agentId, key, chainId, rpcUrl?)`

Gets raw metadata bytes for an agent by key.

- **Parameters**:
  - `agentId`: Agent ID (token ID)
  - `key`: Metadata key
  - `chainId`: Chain ID
  - `rpcUrl`: (Optional) RPC URL override
- **Returns**: Metadata value as bytes

#### `getTokenURI(agentId, chainId, rpcUrl?)`

Gets token URI for an agent.

- **Parameters**:
  - `agentId`: Agent ID (token ID)
  - `chainId`: Chain ID
  - `rpcUrl`: (Optional) RPC URL override
- **Returns**: Token URI string

#### `getOwner(agentId, chainId, rpcUrl?)`

Gets owner address of an agent token.

- **Parameters**:
  - `agentId`: Agent ID (token ID)
  - `chainId`: Chain ID
  - `rpcUrl`: (Optional) RPC URL override
- **Returns**: Owner address

#### `validateAgent(did, chainId, rpcUrl?)`

Validates agent registration and gets agent details.

- **Parameters**:
  - `did`: DID of the agent
  - `chainId`: Chain ID
  - `rpcUrl`: (Optional) RPC URL override
- **Returns**: `AgentDetails` object or null if not found

### General Utilities

#### `generateDID(ethAddress)`

Generates a Privado ID DID from an Ethereum address. Always uses "privado:main" format.

- **Parameters**:
  - `ethAddress`: Ethereum address (0x-prefixed, 20 bytes)
- **Returns**: DID string in format `did:iden3:privado:main:base58Id`

```typescript
const did = generateDID("0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb");
// Returns: did:iden3:privado:main:...
```

#### `getETHPublicKeyFromDID(didFull)`

Extracts the Ethereum public key from a DID.

- **Parameters**:
  - `didFull`: Full DID string
- **Returns**: Ethereum public key (hex) or null if not Ethereum-controlled

```typescript
const address = getETHPublicKeyFromDID("did:iden3:privado:main:...");
```

#### `generatePrivateKey()`

Generates a new random Ethereum private key.

- **Returns**: Private key string (0x-prefixed, 64 hex chars)

```typescript
const privateKey = generatePrivateKey();
```

#### `generateChallenge(length?)`

Generates a random challenge string for authentication.

- **Parameters**:
  - `length`: (Optional) Length of challenge, default is 10
- **Returns**: Random string

```typescript
const challenge = generateChallenge(16);
```

### Handshake Functions

#### `initiateHandshake(initiatorDid, initiatorChainId, receiverDid, receiverChainId, initiatorRpcUrl?, receiverRpcUrl?)`

Initiates a handshake between two agents.

- **Parameters**:
  - `initiatorDid`: DID of the initiating agent
  - `initiatorChainId`: Chain ID of the initiator
  - `receiverDid`: DID of the receiving agent
  - `receiverChainId`: Chain ID of the receiver
  - `initiatorRpcUrl`: (Optional) RPC URL for initiator chain
  - `receiverRpcUrl`: (Optional) RPC URL for receiver chain
- **Returns**: `HandshakeInitiationResult` with `sessionId`, `receiverAgentCallbackEndPoint`, and `challenge`

```typescript
const handshake = await initiateHandshake(
  initiatorDid,
  80002,
  receiverDid,
  11155111
);
```

#### `completeHandshake(privateKey, sessionId, receiverAgentCallbackEndPoint, challenge)`

Completes a handshake by signing the challenge and sending to receiver.

- **Parameters**:
  - `privateKey`: Private key for signing
  - `sessionId`: Session ID from handshake initiation
  - `receiverAgentCallbackEndPoint`: Callback endpoint of receiver
  - `challenge`: Challenge to sign
- **Returns**: Boolean indicating success

```typescript
const success = await completeHandshake(
  privateKey,
  handshake.sessionId,
  handshake.receiverAgentCallbackEndPoint,
  handshake.challenge
);
```

#### `verifySignature(sessionId, challenge, signature, did)`

Verifies a signature from a handshake.

- **Parameters**:
  - `sessionId`: Session ID
  - `challenge`: Challenge that was signed
  - `signature`: Signature to verify
  - `did`: DID of the signer
- **Returns**: Boolean indicating if signature is valid

### Contract Utilities

#### `getContractVersion(chainId, rpcUrl?)`

Gets the contract version. Useful for proxy contracts to check which implementation version is active.

- **Parameters**:
  - `chainId`: Chain ID
  - `rpcUrl`: (Optional) RPC URL override
- **Returns**: Contract version string

```typescript
const version = await getContractVersion(80002);
console.log(`Contract version: ${version}`);
```

#### `getRegistryContract(chainId, signerOrProvider, rpcUrl?)`

Gets a contract instance for the Identity Registry.

- **Parameters**:
  - `chainId`: Chain ID
  - `signerOrProvider`: Signer or provider instance
  - `rpcUrl`: (Optional) RPC URL override
- **Returns**: Contract instance

#### `getProvider(chainId, rpcUrl?)`

Gets a provider for a chain.

- **Parameters**:
  - `chainId`: Chain ID
  - `rpcUrl`: (Optional) RPC URL override
- **Returns**: Provider instance

#### `getSigner(privateKey, chainId, rpcUrl?)`

Gets a signer from private key.

- **Parameters**:
  - `privateKey`: Private key (0x-prefixed, 64 hex chars)
  - `chainId`: Chain ID
  - `rpcUrl`: (Optional) RPC URL override
- **Returns**: Signer instance

### Configuration

#### `getChainConfig(chainId)`

Gets chain configuration by chain ID.

- **Parameters**:
  - `chainId`: Chain ID
- **Returns**: `ChainConfig` object

#### `getRpcUrl(chainId, overrideRpcUrl?)`

Gets RPC URL for a chain, with optional override.

- **Parameters**:
  - `chainId`: Chain ID
  - `overrideRpcUrl`: (Optional) RPC URL override
- **Returns**: RPC URL string

#### `getRegistryAddress(chainId)`

Gets registry contract address for a chain. Prefers proxy address if available, falls back to V1.

- **Parameters**:
  - `chainId`: Chain ID
- **Returns**: Registry contract address

## Type Definitions

```typescript
type SupportedChainId =
  | 80002 // Polygon Amoy
  | 11155111 // Sepolia
  | 296 // Hedera Testnet
  | 84532 // Base Sepolia
  | 421614 // Arbitrum Sepolia
  | 324705682; // Skale Base Sepolia

interface RegistrationResult {
  txHash: string;
  agentId: number;
  did?: string;
  tokenURI?: string;
}

interface AgentDetails {
  did: string;
  agentId: number;
  description?: string;
  serviceEndPoint?: string;
  owner?: string;
  tokenURI?: string;
}

interface MetadataEntry {
  key: string;
  value: string | Uint8Array;
}

interface HandshakeInitiationResult {
  sessionId: number;
  receiverAgentCallbackEndPoint: string;
  challenge: string;
}
```

## Complete Example

```typescript
import {
  generatePrivateKey,
  register,
  setMetadata,
  getCustomMetadata,
  getA2AEndpoint,
  getContractVersion,
} from "@zkred/agent-id";

async function main() {
  // Generate a new agent
  const privateKey = generatePrivateKey();
  const chainId = 80002; // Polygon Amoy

  // Register agent with all features
  const registration = await register(
    privateKey,
    chainId,
    "https://example.com/token.json", // token URI
    true, // add DID
    "https://agent.example.com/a2a" // A2A endpoint
  );

  console.log(`Agent registered!`);
  console.log(`Agent ID: ${registration.agentId}`);
  console.log(`DID: ${registration.did}`);
  console.log(`Transaction: ${registration.txHash}`);

  // Add custom metadata
  await setMetadata(
    privateKey,
    registration.agentId,
    "website",
    "https://myagent.com",
    chainId
  );

  await setMetadata(
    privateKey,
    registration.agentId,
    "email",
    "agent@example.com",
    chainId
  );

  // Retrieve metadata
  const website = await getCustomMetadata(
    registration.agentId,
    "website",
    chainId
  );
  const a2aEndpoint = await getA2AEndpoint(registration.agentId, chainId);

  console.log(`Website: ${website}`);
  console.log(`A2A Endpoint: ${a2aEndpoint}`);

  // Check contract version
  const version = await getContractVersion(chainId);
  console.log(`Contract version: ${version}`);
}

main();
```

## License

MIT

## Repository

https://github.com/Zkred/zkred-agent-id
