/**
 * Calculates the Shannon Entropy of a string.
 * Higher entropy means the string is more "random" and less predictable,
 * which is a strong indicator of an auto-generated API Key or Secret.
 */
export function calculateShannonEntropy(str: string): number {
  if (!str || str.length === 0) return 0;

  const charCounts: Record<string, number> = {};
  for (let i = 0; i < str.length; i++) {
    const char = str[i];
    charCounts[char] = (charCounts[char] || 0) + 1;
  }

  let entropy = 0;
  for (const char in charCounts) {
    const p = charCounts[char] / str.length;
    entropy -= p * Math.log2(p);
  }

  return entropy;
}

/**
 * Basic heuristic to check if a string is likely a base64 encoded payload.
 * It attempts to decode and checks if the output is printable text.
 */
export function isSuspiciousBase64(str: string): string | null {
  // Regex to match a potential base64 string (minimum 16 chars to avoid noise)
  const base64Regex = /^(?:[A-Za-z0-9+/_-]{4}){4,}(?:[A-Za-z0-9+/_-]{2}==|[A-Za-z0-9+/_-]{3}=)?$/;

  if (base64Regex.test(str)) {
    try {
      const normalized = str.replace(/-/g, "+").replace(/_/g, "/");
      const decoded = Buffer.from(normalized, "base64").toString("utf8");
      // If the decoded string contains common injection phrases, return it
      const lowerDecoded = decoded.toLowerCase();
      if (
        lowerDecoded.includes("ignore previous") ||
        lowerDecoded.includes("ignore all prior") ||
        lowerDecoded.includes("system prompt") ||
        lowerDecoded.includes("developer message") ||
        lowerDecoded.includes("exfiltrate") ||
        lowerDecoded.includes("send the token")
      ) {
        return decoded;
      }
    } catch (_e) {
      // Not valid base64
    }
  }
  return null;
}
