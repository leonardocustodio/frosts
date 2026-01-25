import { ed448 } from "@noble/curves/ed448";
import { Ed448Shake256 } from "./src/index.js";

console.log("Testing Ed448Shake256 ciphersuite...\n");

// First verify the noble-curves generator
const noblG = ed448.ExtendedPoint.BASE.toRawBytes();
console.log("1. Noble-curves generator:");
console.log("   Length:", noblG.length);
console.log("   Hex:", Array.from(noblG).map(b => b.toString(16).padStart(2, "0")).join(""));

// Now get the ciphersuite generator
const csG = Ed448Shake256.generator();
console.log("\n2. Ed448Shake256.generator():");
console.log("   Length:", csG.length);
console.log("   Hex:", Array.from(csG).map(b => b.toString(16).padStart(2, "0")).join(""));

// Check if they match
const match = noblG.length === csG.length && noblG.every((b, i) => b === csG[i]);
console.log("\n3. Generators match:", match);

// Try to deserialize the ciphersuite generator with noble-curves
console.log("\n4. Trying to deserialize ciphersuite generator with noble-curves...");
try {
  const reconstructed = ed448.ExtendedPoint.fromHex(csG);
  console.log("   Success!");
  console.log("   Matches BASE:", reconstructed.equals(ed448.ExtendedPoint.BASE));
} catch (e) {
  console.error("   FAILED:", e);
}

// Now test scalarRandom and see the scalar format
const rng = {
  fill(buffer: Uint8Array): void {
    crypto.getRandomValues(buffer);
  },
};

console.log("\n5. Generate random scalar...");
const scalar = Ed448Shake256.scalarRandom(rng);
console.log("   Length:", scalar.length);
console.log("   First 10 bytes:", Array.from(scalar.slice(0, 10)).map(b => b.toString(16).padStart(2, "0")).join(" "));

// Check if the scalar is valid for noble-curves
console.log("\n6. Convert scalar to BigInt...");
let sBig = 0n;
for (let i = scalar.length - 1; i >= 0; i--) {
  sBig = (sBig << 8n) | BigInt(scalar[i]);
}
console.log("   Scalar BigInt:", sBig.toString().slice(0, 40) + "...");

// Try to multiply with noble-curves directly
console.log("\n7. Multiply with noble-curves directly...");
try {
  const result = ed448.ExtendedPoint.BASE.multiply(sBig);
  console.log("   Success!");
  console.log("   Result bytes:", result.toRawBytes().slice(0, 10));
} catch (e) {
  console.error("   FAILED:", e);
}

// Now try with the ciphersuite
console.log("\n8. Multiply with ciphersuite.elementMul...");
try {
  const result = Ed448Shake256.elementMul(csG, scalar);
  console.log("   Success!");
  console.log("   Result bytes:", result.slice(0, 10));
} catch (e) {
  console.error("   FAILED:", e);
}
