/**
 * Cryptographic utilities
 */
import { ethers } from "ethers";

/**
 * Generate a random private key
 * @returns Private key as hex string (0x-prefixed, 64 hex chars)
 */
export function generatePrivateKey(): string {
  const wallet = ethers.Wallet.createRandom();
  return wallet.privateKey;
}

/**
 * Generate a random challenge string
 * @param length - Length of the challenge string (default: 10)
 * @returns Random challenge string
 */
export function generateChallenge(length: number = 10): string {
  const chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  let result = "";
  for (let i = 0; i < length; i++) {
    const randomIndex = Math.floor(Math.random() * chars.length);
    result += chars[randomIndex];
  }
  return result;
}
