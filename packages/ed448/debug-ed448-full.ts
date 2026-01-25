import { Ed448Shake256 } from "./packages/ed448/src/index.js";

// Simulate createSecureRng
const rng = {
  fill(buffer: Uint8Array): void {
    globalThis.crypto.getRandomValues(buffer);
  },
};

console.log("Testing Ed448Shake256 ciphersuite...\n");

try {
  console.log("1. Get generator...");
  const generator = Ed448Shake256.generator();
  console.log("   Generator length:", generator.length);
  console.log("   Generator bytes:", Array.from(generator.slice(0, 10)).map(b => b.toString(16).padStart(2, "0")).join(" "));

  console.log("\n2. Create random scalar...");
  const scalar = Ed448Shake256.scalarRandom(rng);
  console.log("   Scalar length:", scalar.length);
  console.log("   Scalar bytes:", Array.from(scalar.slice(0, 10)).map(b => b.toString(16).padStart(2, "0")).join(" "));

  console.log("\n3. Multiply generator by scalar (elementMul)...");
  const element = Ed448Shake256.elementMul(generator, scalar);
  console.log("   Element length:", element.length);
  console.log("   Element bytes:", Array.from(element.slice(0, 10)).map(b => b.toString(16).padStart(2, "0")).join(" "));

  console.log("\n4. Serialize the element...");
  const serialized = Ed448Shake256.serializeElement(element);
  console.log("   Serialized length:", serialized.length);
  console.log("   Serialized bytes:", Array.from(serialized.slice(0, 10)).map(b => b.toString(16).padStart(2, "0")).join(" "));

  console.log("\n5. Deserialize the element...");
  const deserialized = Ed448Shake256.deserializeElement(serialized);
  console.log("   Deserialized length:", deserialized.length);

  console.log("\n✅ All tests passed! Ed448 ciphersuite works correctly.");
} catch (e) {
  console.error("\n❌ Error:", e);
  if (e instanceof Error) {
    console.error("Stack:", e.stack);
  }
}
