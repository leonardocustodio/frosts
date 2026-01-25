import { ed448 } from "@noble/curves/ed448";

console.log("Ed448 curve parameters from noble-curves:\n");

// Access the curve parameters
const CURVE = ed448.CURVE;
console.log("Curve order (n):", CURVE.n.toString());
console.log("\nCurve order (n) length in digits:", CURVE.n.toString().length);

// Our CURVE_ORDER
const OUR_ORDER = BigInt(
  "181709681073901722637330951972001133588695961144550024066731088774018019936699373822799989826221895039134860185795106935037862922546650026712086013",
);
console.log("\nOur CURVE_ORDER:   ", OUR_ORDER.toString());
console.log("Our order length:", OUR_ORDER.toString().length);

console.log("\nOrders match:", CURVE.n === OUR_ORDER);

// Show what scalar range is valid
console.log("\n\nValid scalar range for noble-curves:");
console.log("  Min: 1");
console.log("  Max (curve.n - 1):", (CURVE.n - 1n).toString().slice(0, 40) + "...");

// Test the scalar that failed
const testScalar = 5322351615790335849248940015691139823762n;
console.log("\n\nTest scalar:", testScalar);
console.log("Test scalar < curve.n:", testScalar < CURVE.n);
console.log("Test scalar >= 1:", testScalar >= 1n);

// Test what happens with a smaller scalar
console.log("\n\nTest with scalar = 5:");
try {
  const result = ed448.ExtendedPoint.BASE.multiply(5n);
  console.log("Success! Result:", result.toRawBytes().slice(0, 10));
} catch (e) {
  console.error("Failed:", e);
}
