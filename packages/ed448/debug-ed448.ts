import { ed448 } from "@noble/curves/ed448";

// Test basic ed448 operations
console.log("Testing Ed448 from @noble/curves...\n");

try {
  // Get the generator point
  const G = ed448.ExtendedPoint.BASE;
  console.log("Generator G:", G.toRawBytes().slice(0, 10), "... (57 bytes)");
  console.log("G bytes length:", G.toRawBytes().length);

  // Create a scalar (use a simple value)
  const scalar = BigInt(5);
  console.log("\nScalar:", scalar);

  // Test multiplication of generator by scalar
  console.log("\nTesting G.multiply(5)...");
  const result = G.multiply(scalar);
  console.log("Result:", result.toRawBytes().slice(0, 10), "...");
  console.log("Result length:", result.toRawBytes().length);

  // Test with a random scalar as bytes
  const scalarBytes = new Uint8Array(57);
  scalarBytes[0] = 42; // small value
  const scalarBigInt = scalarBytes.reduce((acc, byte, i) => acc + (BigInt(byte) << (BigInt(i) * 8n)), 0n);
  console.log("\nTesting with scalar from bytes:", scalarBigInt);
  const result2 = G.multiply(scalarBigInt);
  console.log("Result2:", result2.toRawBytes().slice(0, 10), "...");

  // Now test deserializing a point and multiplying
  console.log("\nTesting point deserialization and multiplication...");
  const gBytes = G.toRawBytes();
  const gReconstructed = ed448.ExtendedPoint.fromHex(gBytes);
  console.log("Reconstructed G:", gReconstructed.toRawBytes().slice(0, 10), "...");

  const result3 = gReconstructed.multiply(scalar);
  console.log("Result3 (G * 5):", result3.toRawBytes().slice(0, 10), "...");

  console.log("\n✅ All basic ed448 operations work!");
} catch (e) {
  console.error("\n❌ Error:", e);
}
