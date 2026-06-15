/**
 * Phantom Payload Evasion Detector
 * Cleans invisible characters and detects malicious Right-To-Left Overrides
 */

// Zero-Width Spaces and formatting characters used to evade simple Regex
const INVISIBLE_CHARS_REGEX = /[\u200B-\u200D\uFEFF]/g;

// Bidirectional Overrides used to spoof file extensions or words (e.g. RLO)
const BIDI_OVERRIDES_REGEX = /[\u202E\u202B\u202D\u202A\u202C]/g;

// Basic Cyrillic Homoglyphs that look like Latin characters
const HOMOGLYPH_MAP: Record<string, string> = {
  а: "a",
  с: "c",
  е: "e",
  о: "o",
  р: "p",
  х: "x",
  у: "y",
};

export function detectPhantomEvasion(str: string): {
  hasInvisibleChars: boolean;
  hasBidiOverride: boolean;
  cleanText: string;
} {
  const normalized = str.normalize("NFKC");
  const hasInvisibleChars = normalized.search(INVISIBLE_CHARS_REGEX) >= 0;
  const hasBidiOverride = normalized.search(BIDI_OVERRIDES_REGEX) >= 0;

  // Clean invisible and bidi chars
  let cleanText = normalized.replace(INVISIBLE_CHARS_REGEX, "");
  cleanText = cleanText.replace(BIDI_OVERRIDES_REGEX, "");

  // Normalize simple Homoglyphs
  cleanText = cleanText
    .split("")
    .map((char) => HOMOGLYPH_MAP[char] || char)
    .join("");

  return {
    hasInvisibleChars,
    hasBidiOverride,
    cleanText,
  };
}
