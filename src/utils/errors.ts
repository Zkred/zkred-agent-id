/**
 * Error handling utilities
 */

export function handleError(err: any): never {
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
