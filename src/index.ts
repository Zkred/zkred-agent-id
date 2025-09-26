/**
* zkred-agent-id
* Main entry point for the package
*/
import bs58 from "bs58";
import crc from "crc";
import { ethers } from "ethers";
import identityRegistryABI from "./contracts/IndentityRegistry.json";
import dotenv from "dotenv";
dotenv.config();

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
  chainId: 80002 | 296,
  serviceEndpoint: string,
  rpcUrl: string = ''
) {
  try {
    // set rpcUrl if not provided based on chainId
    if (!rpcUrl) {
      if (chainId === 80002) {
        rpcUrl = process.env.AMOY_RPC_URL as string
      }
      if (chainId === 296) {
        rpcUrl = process.env.HEDERA_RPC_URL as string
      }
    }
    
    // Generate public key from privateKey using ethers
    if (!/^0x[0-9a-fA-F]{64}$/.test(privateKey)) {
      throw new Error('Private key must be a 0x-prefixed 64-hex string');
    }
    
    const publicKey = ethers.computeAddress(privateKey);
    // Generate signer
    const provider = new ethers.JsonRpcProvider(rpcUrl as string);
    const signer = new ethers.Wallet(privateKey, provider);
    
    // Decide registry contract based on chain
    let REGISTRY_CONTRACT = process.env.IDENTITY_REGISTRY_AMOY;
    if (chainId === 296) REGISTRY_CONTRACT = process.env.IDENTITY_REGISTRY_HEDERA;
    
    const registry = new ethers.Contract(REGISTRY_CONTRACT as string, identityRegistryABI.abi, signer);
    const registrationFee = ethers.parseEther("0.01");
    
    const agentDetails = await registry.getAgentByAddress(publicKey);

    const availableBalance = await provider.getBalance(publicKey);
    const balanceInEther = ethers.formatEther(availableBalance);

    if (+balanceInEther < registrationFee) {
      throw new Error("Insufficient balance to cover registration fee");
    }

    if (agentDetails?.length) {
      throw new Error("Agent already registered");
    }

    const did = generateDID(publicKey, "polygon", "amoy");
    const tx = await registry.registerAgent(did, description, serviceEndpoint, {
      value: registrationFee,
    });
    
    await tx.wait();
    
    return {
      txHash: tx.hash,
      did,
      description,
      serviceEndpoint,
      agentId: Number(agentDetails[1])
    }
  } catch (err: any) {
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
  chainId: 80002 | 296,
  rpcUrl: string = ''
) {
  try {
    if (!rpcUrl) {
      if (chainId === 80002) {
        rpcUrl = process.env.AMOY_RPC_URL as string
      }
      if (chainId === 296) {
        rpcUrl = process.env.HEDERA_RPC_URL as string
      }
    }
    
    // Decide registry contract based on chain
    let REGISTRY_CONTRACT = process.env.IDENTITY_REGISTRY_AMOY;
    if (chainId === 296) REGISTRY_CONTRACT = process.env.IDENTITY_REGISTRY_HEDERA;
    
    const ethAddress = getETHPublicKeyFromDID(did);
    
    const provider = new ethers.JsonRpcProvider(rpcUrl as string);
    const registry = new ethers.Contract(REGISTRY_CONTRACT as string, identityRegistryABI.abi, provider);
    const agentDetails = await registry.getAgentByAddress(ethAddress);
    return {
      did: agentDetails[0],
      agentId: Number(agentDetails[1]),
      description: agentDetails[2],
      serviceEndPoint: agentDetails[3]
    };
  } catch (err: any) {
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
}
// Export all public functions and types
export default {
  generateDID,
  getETHPublicKeyFromDID,
  createIdentity,
  validateAgent
};