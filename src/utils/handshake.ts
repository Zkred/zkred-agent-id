/**
 * Handshake utilities for agent-to-agent communication
 */
import axios from "axios";
import { ethers } from "ethers";
import { SupportedChainId } from "../types";
import { getRpcUrl } from "../config/chains";
import { validateAgent } from "../contract/viewer";

export interface HandshakeInitiationResult {
  sessionId: number;
  receiverAgentCallbackEndPoint: string;
  challenge: string;
}

/**
 * Initiate handshake between two agents
 * @param initiatorDid - DID of the initiating agent
 * @param initiatorChainId - Chain ID of the initiating agent
 * @param receiverDid - DID of the receiving agent
 * @param receiverChainId - Chain ID of the receiving agent
 * @param initiatorRpcUrl - Optional RPC URL override for initiator chain
 * @param receiverRpcUrl - Optional RPC URL override for receiver chain
 * @returns Handshake initiation result with session ID, callback endpoint, and challenge
 */
export async function initiateHandshake(
  initiatorDid: string,
  initiatorChainId: SupportedChainId,
  receiverDid: string,
  receiverChainId: SupportedChainId,
  initiatorRpcUrl?: string,
  receiverRpcUrl?: string
): Promise<HandshakeInitiationResult> {
  const sessionId = Date.now();
  const initiatorRpc = getRpcUrl(initiatorChainId, initiatorRpcUrl);
  const receiverRpc = getRpcUrl(receiverChainId, receiverRpcUrl);

  // Validate initiator agent
  const initiatorAgent = await validateAgent(
    initiatorDid,
    initiatorChainId,
    initiatorRpc
  );

  if (!initiatorAgent) {
    throw new Error("Initiator agent not found");
  }

  // Validate receiver agent and get service endpoint
  const receiverAgent = await validateAgent(
    receiverDid,
    receiverChainId,
    receiverRpc
  );

  if (!receiverAgent) {
    throw new Error("Receiver agent not found");
  }

  if (!receiverAgent.serviceEndPoint) {
    throw new Error("Receiver agent does not have a service endpoint");
  }

  // Call receiver agent's /initiate endpoint
  try {
    const response = await axios.post(
      `${receiverAgent.serviceEndPoint}/initiate`,
      {
        sessionId,
        initiatorDid,
        initiatorChainId,
      }
    );

    return {
      sessionId,
      receiverAgentCallbackEndPoint: `${receiverAgent.serviceEndPoint}/callback`,
      challenge: response?.data?.data?.challenge,
    };
  } catch (err: any) {
    throw new Error(
      `Failed to initiate handshake: ${err.message || "Unknown error"}`
    );
  }
}

/**
 * Complete handshake by signing challenge and sending to receiver
 * @param privateKey - Private key of the initiating agent
 * @param sessionId - Session ID from handshake initiation
 * @param receiverAgentCallbackEndPoint - Callback endpoint from handshake initiation
 * @param challenge - Challenge string from handshake initiation
 * @returns true if handshake completed successfully, false otherwise
 */
export async function completeHandshake(
  privateKey: string,
  sessionId: string | number,
  receiverAgentCallbackEndPoint: string,
  challenge: string
): Promise<boolean> {
  const message = JSON.stringify({
    sessionId,
    challenge,
  });

  const wallet = new ethers.Wallet(privateKey);
  const signature = await wallet.signMessage(message);

  // Call service endpoint of receiver with signature
  try {
    const response = await axios.post(receiverAgentCallbackEndPoint, {
      sessionId,
      challenge,
      signature,
    });

    if (
      response?.data?.data?.sessionId === sessionId &&
      response?.data?.data?.status === "handshake_completed"
    ) {
      return true;
    }
    return false;
  } catch (err) {
    console.error("Error completing handshake:", err);
    return false;
  }
}
