/**
* zkred-agent-id
* Main entry point for the package
*/
import bs58 from "bs58";
import crc from "crc";

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

// Export all public functions and types
export default {
  generateDID,
  getETHPublicKeyFromDID
};
