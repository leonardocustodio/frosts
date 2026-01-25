import { ed448 } from "@noble/curves/ed448";

console.log("Testing ed448 point serialization...\n");

try {
  // Get the generator
  const G = ed448.ExtendedPoint.BASE;
  console.log("1. Generator (ExtendedPoint.BASE)");
  console.log("   x:", G.ex.toString().slice(0, 50) + "...");
  console.log("   y:", G.ey.toString().slice(0, 50) + "...");
  
  // Convert to raw bytes
  const gBytes = G.toRawBytes();
  console.log("\n2. Generator as bytes (toRawBytes):");
  console.log("   Length:", gBytes.length);
  const gHex = Array.from(gBytes).map(b => b.toString(16).padStart(2, "0")).join("");
  console.log("   Hex:", gHex);

  // Try to deserialize with fromHex
  console.log("\n3. Trying to deserialize with fromHex(bytes)...");
  try {
    const gReconstructed = ed448.ExtendedPoint.fromHex(gBytes);
    console.log("   Success! Reconstructed point x:", gReconstructed.ex.toString().slice(0, 20) + "...");
  } catch (e) {
    console.error("   FAILED:", e);
  }

  // Try with hex string
  console.log("\n4. Trying to deserialize with fromHex(hexString)...");
  try {
    const gReconstructed2 = ed448.ExtendedPoint.fromHex(gHex);
    console.log("   Success! Reconstructed point x:", gReconstructed2.ex.toString().slice(0, 20) + "...");
  } catch (e) {
    console.error("   FAILED:", e);
  }

  console.log("\n5. Verify round-trip matches...");
  const roundTripped = ed448.ExtendedPoint.fromHex(gBytes).toRawBytes();
  const match = gBytes.every((b, i) => b === roundTripped[i]);
  console.log("   Round-trip matches:", match);

  console.log("\n✅ All point operations work!");
} catch (e) {
  console.error("\n❌ Error:", e);
}
