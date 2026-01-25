import { p256 } from "@noble/curves/p256";

const ProjectivePoint = p256.ProjectivePoint;

console.log("Testing P256 identity point...\n");

// Check what identity looks like
const identity = ProjectivePoint.ZERO;
console.log("Identity x:", identity.px);
console.log("Identity y:", identity.py);
console.log("Identity z:", identity.pz);

try {
  const identityBytes = identity.toRawBytes(true);
  console.log("\nIdentity compressed bytes:", identityBytes.length, "bytes");
  console.log("Hex:", Array.from(identityBytes).map(b => b.toString(16).padStart(2, "0")).join(""));
} catch (e: any) {
  console.log("\nError serializing identity:", e.message);
}

// Try to decode 33 zero bytes
const zeroBytes = new Uint8Array(33);
console.log("\nTrying to decode 33 zero bytes...");
try {
  const decoded = ProjectivePoint.fromHex(zeroBytes);
  console.log("Success! Decoded as identity:", decoded.equals(ProjectivePoint.ZERO));
} catch (e: any) {
  console.log("Error:", e.message);
}

// Try adding identity to a point
console.log("\nTrying to add identity to generator...");
try {
  const gen = ProjectivePoint.BASE;
  const result = gen.add(identity);
  console.log("gen + identity equals gen:", result.equals(gen));
} catch (e: any) {
  console.log("Error:", e.message);
}

// What does identity.toRawBytes produce with false (uncompressed)?
try {
  const uncompressed = identity.toRawBytes(false);
  console.log("\nIdentity uncompressed bytes:", uncompressed.length, "bytes");
  console.log("Hex:", Array.from(uncompressed).map(b => b.toString(16).padStart(2, "0")).join(""));
} catch (e: any) {
  console.log("\nError serializing identity uncompressed:", e.message);
}

// Try using toHex
try {
  const hex = identity.toHex(true);
  console.log("\nIdentity toHex(true):", hex);
} catch (e: any) {
  console.log("\nError in identity.toHex(true):", e.message);
}
