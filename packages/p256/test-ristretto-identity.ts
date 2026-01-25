import { RistrettoPoint } from "@noble/curves/ed25519";

console.log("Testing Ristretto255 identity point...\n");

// Check what identity looks like
const identity = RistrettoPoint.ZERO;
console.log("Testing RistrettoPoint.ZERO...");

try {
  const identityBytes = identity.toRawBytes();
  console.log("\nIdentity bytes:", identityBytes.length, "bytes");
  console.log("Hex:", Array.from(identityBytes).map(b => b.toString(16).padStart(2, "0")).join(""));
  
  // Try to decode it back
  const decoded = RistrettoPoint.fromHex(identityBytes);
  console.log("Decoded equals ZERO:", decoded.equals(RistrettoPoint.ZERO));
  
  // Try adding to generator
  const gen = RistrettoPoint.BASE;
  const result = decoded.add(gen);
  console.log("ZERO + BASE equals BASE:", result.equals(gen));
} catch (e: any) {
  console.log("\nError serializing/deserializing identity:", e.message);
}
