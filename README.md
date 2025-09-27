# zkred-agent-id

A package for agent identification and management.

## Installation

```bash
npm install @zkred/agent-id
```

## Usage

```javascript
import zkredAgentId from "@zkred/agent-id";

// Generate a new private key
const privateKey = zkredAgentId.generatePrivateKey();

// Create an agent identity
const identity = await zkredAgentId.createIdentity(
  privateKey,
  "My Agent Description",
  80002, // Polygon Amoy testnet
  "https://my-agent-service.com"
);
```

## API Reference

### Core Functions

#### `generateDID(ethAddress, chain, network)`

Generates a Decentralized Identifier (DID) from an Ethereum address.

- **Parameters**:
  - `ethAddress`: Ethereum address (0x-prefixed, 20 bytes)
  - `chain`: Chain name (e.g., "polygon", "privado")
  - `network`: Network name (e.g., "amoy", "main")
- **Returns**: DID string in the format `did:iden3:chain:network:base58Id`

#### `getETHPublicKeyFromDID(didFull)`

Extracts the Ethereum public key from a DID.

- **Parameters**:
  - `didFull`: Full DID string (e.g., "did:iden3:polygon:amoy:x6x5sor7zpyT5mmpg4fADaR47NADVbohtww4ppWZF")
- **Returns**: Ethereum public key (hex) or null if not Ethereum-controlled

#### `createIdentity(privateKey, description, chainId, serviceEndpoint, rpcUrl)`

Registers an agent to the central Registry using native token payment.

- **Parameters**:
  - `privateKey`: Private key of wallet to register
  - `description`: Description of the agent
  - `chainId`: Chain ID (80002 for Polygon Amoy, 296 for Hedera, 16602 for OG)
  - `serviceEndpoint`: Service endpoint URL
  - `rpcUrl`: (Optional) RPC URL for the chain
- **Returns**: Object containing transaction hash, DID, description, service endpoint, and agent ID

#### `validateAgent(did, chainId, rpcUrl)`

Validates an agent's registration.

- **Parameters**:
  - `did`: DID of the agent
  - `chainId`: Chain ID
  - `rpcUrl`: (Optional) RPC URL
- **Returns**: Agent details including DID, agent ID, description, and service endpoint

#### `registerAgentByUSDC(privateKey, description, chainId, serviceEndpoint, rpcUrl)`

Registers an agent using USDC payment via x402 payment interceptor.

- **Parameters**:
  - `privateKey`: Private key of wallet to register
  - `description`: Description of the agent
  - `chainId`: Chain ID
  - `serviceEndpoint`: Service endpoint URL
  - `rpcUrl`: (Optional) RPC URL
- **Returns**: Promise resolving to agent details

### Handshake Functions

#### `initiateHandshake(initiatorDid, initiatorChainId, receiverDid, receiverChainId, initiatorRpcUrl, receiverRpcUrl)`

Initiates a handshake between two agents.

- **Parameters**:
  - `initiatorDid`: DID of the initiating agent
  - `initiatorChainId`: Chain ID of the initiator
  - `receiverDid`: DID of the receiving agent
  - `receiverChainId`: Chain ID of the receiver
  - `initiatorRpcUrl`: (Optional) RPC URL for initiator chain
  - `receiverRpcUrl`: (Optional) RPC URL for receiver chain
- **Returns**: Session details including session ID, callback endpoint, and challenge

#### `copmleteHandshake(privateKey, sessionId, receiverAgentCallbackEndPoint, challenge)`

Completes a handshake by signing the challenge.

- **Parameters**:
  - `privateKey`: Private key for signing
  - `sessionId`: Session ID from initiate handshake
  - `receiverAgentCallbackEndPoint`: Callback endpoint of receiver
  - `challenge`: Challenge to sign
- **Returns**: Boolean indicating success

#### `verifySignature(sessionId, challenge, signature, did)`

Verifies a signature from a handshake.

- **Parameters**:
  - `sessionId`: Session ID
  - `challenge`: Challenge that was signed
  - `signature`: Signature to verify
  - `did`: DID of the signer
- **Returns**: Boolean indicating if signature is valid

### Utility Functions

#### `generatePrivateKey()`

Generates a new random Ethereum private key.

- **Returns**: Private key string

#### `generateChallenge(length)`

Generates a random challenge string for authentication.

- **Parameters**:
  - `length`: (Optional) Length of challenge, default is 10
- **Returns**: Random string

## Supported Networks

- Polygon Amoy (Chain ID: 80002)
- Hedera (Chain ID: 296)
- OG (Chain ID: 16602)
