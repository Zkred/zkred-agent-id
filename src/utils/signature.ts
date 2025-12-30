/**
 * Signature verification utilities
 */
import { ethers } from "ethers";
import { getETHPublicKeyFromDID } from "./did";

/**
 * Verify a signature against a DID
 * @param sessionId - Session ID
 * @param challenge - Challenge string
 * @param signature - Signature to verify
 * @param did - DID to verify against
 * @returns true if signature is valid, false otherwise
 */
export function verifySignature(
  sessionId: string | number,
  challenge: string,
  signature: string,
  did: string
): boolean {
  const message = JSON.stringify({
    sessionId,
    challenge,
  });

  try {
    const recoveredAddress = ethers.verifyMessage(message, signature);
    const derivedAddress = getETHPublicKeyFromDID(did);

    if (!derivedAddress) {
      return false;
    }

    return recoveredAddress?.toLowerCase() === derivedAddress?.toLowerCase();
  } catch (err) {
    console.error("Error verifying signature:", err);
    return false;
  }
}
