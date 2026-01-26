/**
 * Test helper functions for FROST Ed448 tests.
 * Ported from frost-ed448/tests/helpers/mod.rs
 *
 * This module provides helper functions and types for testing
 * the FROST Ed448 ciphersuite implementation.
 */

export * from "./samples.js";

import type { CryptoRng } from "@frosts/core";

// Re-export CryptoRng for convenience
export type { CryptoRng };

/**
 * Create a seeded RNG for deterministic testing.
 * Uses a simple counter-based approach for reproducibility.
 *
 * @param seed - Optional seed bytes. If not provided, uses a default seed.
 * @returns A deterministic random number generator
 */
export function createTestRng(seed?: Uint8Array): CryptoRng {
  let counter = 0;
  const seedArray = seed ?? new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);

  return {
    fill(buffer: Uint8Array): void {
      for (let i = 0; i < buffer.length; i++) {
        // Simple deterministic byte generation based on seed and counter
        buffer[i] = (seedArray[i % seedArray.length] + counter + i) % 256;
      }
      counter++;
    },
    nextU32(): number {
      const result =
        (seedArray[counter % seedArray.length] << 24) |
        (seedArray[(counter + 1) % seedArray.length] << 16) |
        (seedArray[(counter + 2) % seedArray.length] << 8) |
        seedArray[(counter + 3) % seedArray.length];
      counter++;
      return result >>> 0;
    },
    nextU64(): bigint {
      const lo = BigInt(
        (seedArray[counter % seedArray.length] << 24) |
          (seedArray[(counter + 1) % seedArray.length] << 16) |
          (seedArray[(counter + 2) % seedArray.length] << 8) |
          (seedArray[(counter + 3) % seedArray.length] >>> 0),
      );
      const hi = BigInt(
        (seedArray[(counter + 4) % seedArray.length] << 24) |
          (seedArray[(counter + 5) % seedArray.length] << 16) |
          (seedArray[(counter + 6) % seedArray.length] << 8) |
          (seedArray[(counter + 7) % seedArray.length] >>> 0),
      );
      counter += 2;
      return (hi << 32n) | lo;
    },
  };
}

/**
 * Create a cryptographically secure RNG for production testing.
 *
 * @returns A cryptographically secure random number generator
 */
export function createSecureRng(): CryptoRng {
  return {
    fill(buffer: Uint8Array): void {
      if (
        typeof globalThis.crypto !== "undefined" &&
        globalThis.crypto.getRandomValues !== undefined
      ) {
        globalThis.crypto.getRandomValues(buffer as Uint8Array<ArrayBuffer>);
      } else {
        throw new Error("No secure random source available - Web Crypto API required");
      }
    },
    nextU32(): number {
      const buffer = new Uint8Array(4);
      if (
        typeof globalThis.crypto !== "undefined" &&
        globalThis.crypto.getRandomValues !== undefined
      ) {
        globalThis.crypto.getRandomValues(buffer);
      } else {
        throw new Error("No secure random source available - Web Crypto API required");
      }
      return (buffer[0] << 24) | (buffer[1] << 16) | (buffer[2] << 8) | buffer[3];
    },
    nextU64(): bigint {
      const buffer = new Uint8Array(8);
      if (
        typeof globalThis.crypto !== "undefined" &&
        globalThis.crypto.getRandomValues !== undefined
      ) {
        globalThis.crypto.getRandomValues(buffer);
      } else {
        throw new Error("No secure random source available - Web Crypto API required");
      }
      const lo = BigInt(
        (buffer[0] << 24) | (buffer[1] << 16) | (buffer[2] << 8) | (buffer[3] >>> 0),
      );
      const hi = BigInt(
        (buffer[4] << 24) | (buffer[5] << 16) | (buffer[6] << 8) | (buffer[7] >>> 0),
      );
      return (hi << 32n) | lo;
    },
  };
}

/**
 * Convert hex string to Uint8Array.
 *
 * @param hex - Hexadecimal string (with or without 0x prefix)
 * @returns Byte array
 */
export function hexToBytes(hex: string): Uint8Array {
  const cleanHex = hex.startsWith("0x") ? hex.slice(2) : hex;
  const bytes = new Uint8Array(cleanHex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(cleanHex.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

/**
 * Convert Uint8Array to hex string.
 *
 * @param bytes - Byte array
 * @returns Hexadecimal string (lowercase, no prefix)
 */
export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Compare two Uint8Arrays for equality.
 *
 * @param a - First array
 * @param b - Second array
 * @returns true if arrays are equal, false otherwise
 */
export function arraysEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

/**
 * Load test vectors from JSON file.
 * This function loads the test vector JSON files from the helpers directory.
 *
 * @param name - Name of the vector file (without extension).
 *               Valid names: "vectors", "vectors_dkg", "vectors-big-identifier",
 *                           "repair-share", "elements", "samples"
 * @returns Parsed JSON data
 */
export async function loadTestVectors(name: string): Promise<unknown> {
  // Use dynamic import to load JSON files
  const url = new globalThis.URL(`./${name}.json`, import.meta.url);
  const response = await globalThis.fetch(url);
  if (!response.ok) {
    throw new Error(`Failed to load test vectors "${name}": ${response.statusText}`);
  }
  return response.json();
}

/**
 * FROST Ed448 test vectors.
 * These are imported from the Rust test vector files.
 */
export const VECTORS = {
  config: {
    MAX_PARTICIPANTS: "3",
    NUM_PARTICIPANTS: "2",
    MIN_PARTICIPANTS: "2",
    name: "FROST(Ed448, SHAKE256)",
    group: "Ed448",
    hash: "SHAKE256",
  },
  inputs: {
    participant_list: [1, 3],
    group_secret_key:
      "6298e1eef3c379392caaed061ed8a31033c9e9e3420726f23b404158a401cd9df24632adfe6b418dc942d8a091817dd8bd70e1c72ba52f3c00",
    verifying_key_key:
      "3832f82fda00ff5365b0376df705675b63d2a93c24c6e81d40801ba265632be10f443f95968fadb70d10786827f30dc001c8d0f9b7c1d1b000",
    message: "74657374",
    share_polynomial_coefficients: [
      "dbd7a514f7a731976620f0436bd135fe8dddc3fadd6e0d13dbd58a1981e587d377d48e0b7ce4e0092967c5e85884d0275a7a740b6abdcd0500",
    ],
    participant_shares: [
      {
        identifier: 1,
        participant_share:
          "4a2b2f5858a932ad3d3b18bd16e76ced3070d72fd79ae4402df201f525e754716a1bc1b87a502297f2a99d89ea054e0018eb55d39562fd0100",
      },
      {
        identifier: 2,
        participant_share:
          "2503d56c4f516444a45b080182b8a2ebbe4d9b2ab509f25308c88c0ea7ccdc44e2ef4fc4f63403a11b116372438a1e287265cadeff1fcb0700",
      },
      {
        identifier: 3,
        participant_share:
          "00db7a8146f995db0a7cf844ed89d8e94c2b5f259378ff66e39d172828b264185ac4decf7219e4aa4478285b9c0eef4fccdf3eea69dd980d00",
      },
    ],
  },
  round_one_outputs: {
    outputs: [
      {
        identifier: 1,
        hiding_nonce_randomness: "3d9e765ab0f06bc3131acc2f7642223255fd5295f3c04bef5c644c0bae4f85be",
        binding_nonce_randomness:
          "86160f8224ea273128b0ea5af828a9c0b0985cd9b52a3b8b668ae9d3205a6672",
        hiding_nonce:
          "d9610abd59ac2e9b33a3919acf28f5c895918389c69a26a3fcfe6a70edab4685e9ea3d3641d8bfe1634616fafd457b2ef6503c51f191991300",
        binding_nonce:
          "1caf737f1e73b5ab7f155c239ea70fb5783cd8da454298984a325cb4eb968b0e625936cbb9623e57919b3cc01be40f7f45b6c37fd947772b00",
        hiding_nonce_commitment:
          "2afe1a6d56ee111e7e4b84060c07044643434362edbce8f79f568236884c1c16883e9a4d3f42029f324619b32587d501609941bab590682000",
        binding_nonce_commitment:
          "605d2b3b5af4159ca3fa23e4463a3573d4144b43c7b01322d621817c80fcd84f874ea79655648ca65f128a4cfbec236c0c89f3898b27529180",
        binding_factor_input:
          "3832f82fda00ff5365b0376df705675b63d2a93c24c6e81d40801ba265632be10f443f95968fadb70d10786827f30dc001c8d0f9b7c1d1b000e9a0f30b97fe77ef751b08d4e252a3719ae9135e7f7926f7e3b7dd6656b27089ca354997fe5a633aa0946c89f022462e7e9d50fd6ef313f72d956ea4571089427daa1862f623a41625177d91e4a8f350ce9c8bd3bc7c766515dc1dd3a0eab93777526b616cccb148fe1e5992dc1ae705c8ba12fd57e4d8cc8bbf0ff51b79275332fff65f8549bbdc289d7d5ab813a968e6da66f478f3193fda4e298ce953dfbc4d71287b7915d8e08301cc03da6f02e611e37c39ec5c1b1c96dad8436090b5fa5ce1544394e31e5af589fe54e065edbb351766eb597cef8a97f69fbf98597e3fd205a8a2010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        binding_factor:
          "02a61d347e83fc93eaab248c409eaea947cb6d2166b02d19c0d3760031c064b5f2f9354f301e274ac3a6ee000c91136dedfb4f98ffc50a3700",
      },
      {
        identifier: 3,
        hiding_nonce_randomness: "8cba373b6c3a3601d5cfa3d37cbc93f310d253a2fcf886695bb59ac703d8a100",
        binding_nonce_randomness:
          "1a84c88d88fbb99a4417157487b45367eb91d7dd2ba55566d6784f39f750a2f7",
        hiding_nonce:
          "3a8f5b86cf6e80d3a2d99ac5628a1229eaa9dd205b3b3bdd3bc8d2270c749d08836379c8b50d964f492ba8785f3deb571e0b4e7db887be1400",
        binding_nonce:
          "4b529518068f9b261d56cffced7f753b9b22db6a79c8c495584ec67edc561da644b70f9af42e633e14bc145b3ea61c5d2bf30090c3700b2f00",
        hiding_nonce_commitment:
          "3f06fbce6ca0f92331e97946e27c649e9fdb96f1ba1061189495bcd6d019e7915de818c3901b9d5d0e2de062ddeca7a40bbd84c9ffbc983900",
        binding_nonce_commitment:
          "ef2f07a309be3c8936c505b385dee51f319ebb9bf26520ed5579c9b3ede6467968d969fc3c7b34d704b86547e8ae11dcdae9fdc0794e642380",
        binding_factor_input:
          "3832f82fda00ff5365b0376df705675b63d2a93c24c6e81d40801ba265632be10f443f95968fadb70d10786827f30dc001c8d0f9b7c1d1b000e9a0f30b97fe77ef751b08d4e252a3719ae9135e7f7926f7e3b7dd6656b27089ca354997fe5a633aa0946c89f022462e7e9d50fd6ef313f72d956ea4571089427daa1862f623a41625177d91e4a8f350ce9c8bd3bc7c766515dc1dd3a0eab93777526b616cccb148fe1e5992dc1ae705c8ba12fd57e4d8cc8bbf0ff51b79275332fff65f8549bbdc289d7d5ab813a968e6da66f478f3193fda4e298ce953dfbc4d71287b7915d8e08301cc03da6f02e611e37c39ec5c1b1c96dad8436090b5fa5ce1544394e31e5af589fe54e065edbb351766eb597cef8a97f69fbf98597e3fd205a8a2030000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        binding_factor:
          "14e0cfb824bd2003099f3ebb2fe00e95355eab38098a5619acc62a8faa2092ce25cdc061a7b51b6ed41e291ed311a2909d2ce8c3acadfc1200",
      },
    ],
  },
  round_two_outputs: {
    outputs: [
      {
        identifier: 1,
        sig_share:
          "0dad0c550bade2576c6cbe1d7b57a55b00e57a6e3683c8f84fbfa48751745bb0b2b89624e7d1b443b1ff62ffde9ee0c15e5df678c4ed1c0400",
      },
      {
        identifier: 3,
        sig_share:
          "0baf31c64cf452fe3a520f14c5e2b898d6869341fdd8ea26044086a11a4372cd31ba2ee9cf7e316706067a53d05e184ebb95cae16aac7f3700",
      },
    ],
  },
  final_output: {
    sig: "60e3d4d641dd19054c1eced47f02f4a5e377126fb75f68cbd1122d948f93e26069f6740506da0366eb4225746faf894ecd196a1f56d1e1d280185c3e1b58a13556a7becd31403a5ef4d66b0eb0335cb31f54ff2a296cb7cd7de472c50db750e6aab705dd52affdf80f1af3c05a2f9a9c3b00",
  },
} as const;

/**
 * Ciphersuite name for Ed448-SHAKE256.
 */
export const CIPHERSUITE_NAME = "FROST-ED448-SHAKE256-v1";

/**
 * Scalar byte length for Ed448.
 */
export const SCALAR_LENGTH = 57;

/**
 * Element byte length for Ed448.
 */
export const ELEMENT_LENGTH = 57;

/**
 * FROST Ed448 DKG test vectors.
 * These are imported from the Rust vectors_dkg.json test file.
 */
export const VECTORS_DKG = {
  config: {
    MAX_PARTICIPANTS: 3,
    MIN_PARTICIPANTS: 2,
    name: "FROST(Ed448, SHAKE256)",
    group: "ed448",
    hash: "SHAKE256",
  },
  inputs: {
    verifying_key:
      "2c73a3b674e283032effc2494341a608145179b229d664a870336a09b433363079a5ad68044eed31c3cc187267fe8216e559e4e4a8b9f49a80",
    "1": {
      identifier: 1,
      signing_key:
        "01cbf4ac6b8ee0d03b799a62b7d7f32f05e2e117e9362f11004071fdb17ee2740206f45c910b4754eb0729e36e657136acfe16ff5abaf13800",
      coefficient:
        "74d5bf96312d4aaebf4c6a7e4760a50233f3fb0ce76f34df95781cd8a07b1607073cf70d8272f76956c67f6a9d643ba257e280f19754692300",
      vss_commitments: [
        "2747193abad63b685e15421f8c15c7c98107bf00d447561906a23e595dcba7367b7cf5ec4b7c751ec4f1721be4a1162d906af4c88a74c09b80",
        "abd8994d10bfb50fbd360b8f0ade24bd5362c12e06aa72ea9b92ab2d497399c78789a0874d3b0bf99a624549cbc7ec5ccaa503f1d80d189880",
      ],
      proof_of_knowledge:
        "345f573924403f60672d42d2f428959935f2dca278cec91c955d166ab06ca0e7919e311d376f0c5e4e28a5df96dda71d36576fc7d7748b128063d520bd4b3a6ddcdf05bb84c87a83766218067a3ebb85664084a5a8c58d99b073526234be5ec518333f5e8bcc80ed11d563569123f2fd1200",
      signing_shares: {
        "2": "e29c8b642abfa741710945aedadf34ac73ef6863c3e56d599cc3c58039d45b7382674cbd2c8e064c8bae33851c9166536181b83fe34ce02200",
        "3": "ae2817fbc11b1595e432362f7d40f28953a545f193851d182e5914f4800ccfcc0194d75f170693e2c0b7be169b45e5d890aaac1d55db9f0d00",
      },
      verifying_share:
        "4f4c185df443f1d836d213469cf7a52d4e0d0b9dd34046af1c29d0f6b5c7e9a8881c1a138b1c5cdce1a33c42b8f8068aac788f91e7de69a080",
      signing_share:
        "1fdca64c6411f60ea7e3f4a271d3e625dffcdf1b945b51d98c8dd3500edb23bc8d3d0f885712d8ec8d349be9c3a0f804f60cfd4d2b37db0c00",
    },
    "2": {
      identifier: 2,
      signing_key:
        "9e17dfce20dfd4f0d0bd893a75cba3ff3ab6574d716cd68b4b393d9cd3ff747dcbb6d629ee48d8cc06b29397f3706e18a497f641ee633b2d00",
      coefficient:
        "37ca04419ca24b74f5da8001d8d6fdcdc86fe7c49b54e6913aae526165d4e6f5b6b075933e452e7f84fc9fed2820f83abde9c1fdf4e8a43500",
      vss_commitments: [
        "01f375709143c4ad10db96da820082e5c2d802bd0ba78712bdbbe915f1b1d30d20732067395f157c124e4c9e32e37c47a59452950751d7d180",
        "f410470bc15065f35168c120b784d57db922c047f290ba7c1322b2c713d6d6cc44272b17c6ddc25abe54f4d2acd6c17fccbd9c25595d4ccf00",
      ],
      proof_of_knowledge:
        "7bd1f9052217b2a02f4798906480ac288927c54dbd846e5bcbf4d08389a205269bf620a6ad1a04a3a0bcfd238c57f5f3960dd4795cebe66a80ed3c4617d163ec19648bd55d2f7acb4c4080c0062b878086ddb73f83aee1ad73426cab8a7d08f4540ccf6e31e08606861dd5daca506fc10d00",
      signing_shares: {
        "1": "f6301c2f3c26fc096683a9d1d3d5d113db9103836d3b490b420de030f4750f83107ee27895f03528989428b8a92ee87a5bc318e28a63c43f00",
        "3": "cdc0200642d408d6a2147eebba853b2ee42730d85ca72287b5e0ec8182ccbeddcf3e7845cd35588bd9b7c63d9657f704fc706d7becb3d62200",
      },
      verifying_share:
        "053898556feae3f11a5977bcc0e14eb55086ff935aa22ec2c97b166e97c7a58fc165210d442069e66c4785fd6e7b3e7fcb7dd434055a1e5c80",
      signing_share:
        "f6ce1c841fd7064fc55d62515c8d6679dbabd725966622f5fa17519b16eb10ca19d51c0fcef9c27e81f7c26885373e0e769f009b4f4d203b00",
    },
    "3": {
      identifier: 3,
      signing_key:
        "82d5659bd4259a777be0b300b2bd1507535931b9143f676d90f505e37e4cdfbb33e9367a61d6cd39a8b7b6ef9f33d3ac25e4ebbfbd02693800",
      coefficient:
        "1f98090b80b8f340bee147bc3d4549a49082eae6c821056f8787d88d01c0ef10ceaaa0e5b52fc5a818000827fb11122c6bc6c05d97d8361500",
      vss_commitments: [
        "792df7d8f5569fb6ded2e5db245f2c1f07469d9cb0a7685a027b5d12142d245d1a417cca43ddaeab39f4cf4299aed16c638fc639eae1881000",
        "f13a1e5fb94aef454a6062735cfde4b37e173b695f3c86b77e5bda60b0a75a0f13446dfeb1fabb515cfb6cfef0973421fbf76bcec44fda9080",
      ],
      proof_of_knowledge:
        "eb47491f2461792114d357d02102c1a806451cfa88f1297f7a671a87a04de0ffde478ec1c2b91e743379254fe84eb2e0d170c69aec88bc1980bf8009ffc93d6ee0c3713681aa303cf85595bd975953318ab07be9e56dc6ba22465793ee337e383562fafc7525c05b36732b93f5f4fee22300",
      signing_shares: {
        "1": "77c1831adb90cd94d0404ec2a8730af57d4e29e10ad02e26ee61328c95f1258a17bad98617632d92ee5aa8224793231db3a599d322b82d2300",
        "2": "6aa7e48f3d7f4de3b1a0bb95a5085705e5618b8f67d89cf43dd8d649057d295ff0c837e4a918634a94a773606ed156c9db543c3bcd1e2a0e00",
      },
      verifying_share:
        "3a1b5a9945fc64b088174c34e16dbced81f824fe8f9f12d1ec98afd4ea593a6ec75a74f70b77522c66681bd468080b525963dbcc2785d53a00",
      signing_share:
        "da7c3a1048da9e6b8e480a72d48479ab4724f9804e96a44c7f7e04691ffbfdd7a56c2a9644e1ad1075baeae746ce8317f63104e87363652900",
    },
  },
} as const;

/**
 * FROST Ed448 test vectors with big identifiers (>u16).
 * These test that the implementation handles identifiers larger than 16 bits.
 * Extracted from vectors-big-identifier.json - participants 129, 256, 257.
 */
export const VECTORS_BIG_IDENTIFIER = {
  config: {
    MAX_PARTICIPANTS: "257",
    NUM_PARTICIPANTS: "3",
    MIN_PARTICIPANTS: "2",
    name: "FROST(Ed448, SHAKE256)",
    group: "ed448",
    hash: "SHAKE256",
  },
  inputs: {
    participant_list: [129, 256, 257],
    group_secret_key:
      "6298e1eef3c379392caaed061ed8a31033c9e9e3420726f23b404158a401cd9df24632adfe6b418dc942d8a091817dd8bd70e1c72ba52f3c00",
    verifying_key_key:
      "3832f82fda00ff5365b0376df705675b63d2a93c24c6e81d40801ba265632be10f443f95968fadb70d10786827f30dc001c8d0f9b7c1d1b000",
    message: "74657374",
    share_polynomial_coefficients: [
      "dbd7a514f7a731976620f0436bd135fe8dddc3fadd6e0d13dbd58a1981e587d377d48e0b7ce4e0092967c5e85884d0275a7a740b6abdcd0500",
    ],
    participant_shares: [
      {
        identifier: 129,
        participant_share:
          "5922504e9548d6bfe045ab9dcc41a998fede910eaa9d3858ab54bd5db8a7473554572b80808e9487773e51ec5e3290e82b18938d9b17dc2800",
      },
      {
        identifier: 256,
        participant_share:
          "9afc7284487dcf17c8a088aca4084324ae39b2435556309864bd2330ca82b225c6be063c0ae8256ed36b3f667ada01a9e5ca5b3c370fed0900",
      },
      {
        identifier: 257,
        participant_share:
          "75d418993f2501af2ec178f00fda78223c17763e33c53dab3f93ae494b683af93d93954786cc0678fcd2044fd35ed2d03f45d047a1ccba0f00",
      },
    ],
  },
  round_one_outputs: {
    outputs: [
      {
        identifier: 129,
        hiding_nonce_randomness: "398dff6ab0cd23e0826c40bd456f02a82ed50a0ee741bbeb5ff40549b32fd25f",
        binding_nonce_randomness:
          "86b1e9e202726fa611ec68e211bf374dcfe2e31bea3f3f743335f194574f9d5a",
        hiding_nonce:
          "362824dc5a28a66723702132cad78b7f8e1ecb31ced794f51eac2e5bda66b5e5b2f651c276c27c93c7aab9da71fd724794dc65472ea4bb3c00",
        binding_nonce:
          "ab8a20b25ca24a4e9a15193c50e62a3e92eca254f2c3462117fed674f06a2d6c77dc43c64b0b142b6eadd1df9c2f63f03d35e7d28aa8fb3200",
        hiding_nonce_commitment:
          "536b4eddcab3ec42de33bdaf1cd73731a89dbd2d9aa628e9bc3fd20e14bca1abdb96fdb403365fe369b7f455cf32af98238553cee525522580",
        binding_nonce_commitment:
          "7a2b3e671c848cdad2d4d969e0300b245625ada17a480de99b9615da132e4c01b5ae786a82d0c5b6f284dfe57670bcedf0adc479981f6f4a00",
        binding_factor_input:
          "3832f82fda00ff5365b0376df705675b63d2a93c24c6e81d40801ba265632be10f443f95968fadb70d10786827f30dc001c8d0f9b7c1d1b000e9a0f30b97fe77ef751b08d4e252a3719ae9135e7f7926f7e3b7dd6656b27089ca354997fe5a633aa0946c89f022462e7e9d50fd6ef313f72d956ea4571089427daa1862f623a41625177d91e4a8f350ce9c8bd3bc7c766515dc1dd3a0eab93777526b616cccb148fe1e5992dc1ae705c8ba66106db565fc6b7de14708224aaafe91425c672f8b660bcebe93d4fdbe47cdb0cdf6e3bab2bf79d270821f191871ad4e3ca4a27888d3c39f16f01a6c4998e50ed67788e401b5b3472eb4ef52ff3ad2fabc58282dcffb9785f9ea42313b440270f08356bc63a8ad503a28d44a91ac364cf177810000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        binding_factor:
          "c6277403d0f30f5ad734dc3ee1b1a120bed7667794e3273ec6d7baca5142ab83f56fd2217a1d2619f0fd666a12ea64872894c9e9e544070400",
      },
      {
        identifier: 256,
        hiding_nonce_randomness: "bb3dbe9685ba7d7436430d107fd817c3c1117f2489be87b597d3e1fa06e94f8e",
        binding_nonce_randomness:
          "3f8d8050d64c712db643929002243aec2639b9ffd6536b733cd4190e3c61c775",
        hiding_nonce:
          "82a1f23bce0eb99e498782cdec51e6762ac6462c02461537f6de7e1a20086bf8b8485bf20b408ebf98a210ace021ca143df702b168326b2c00",
        binding_nonce:
          "b708bb4c3474638f2ff98a2a8a531b3dc385cf417b2e142f56096eec440efefc6f24d83e4ee7b0ecf9d963afc986f86604a4017594c20c3000",
        hiding_nonce_commitment:
          "795bff47d58938f3697739f70162ea2c46f148ebb35f1220e1fc3e3b26883c62029224939c1cb0825bd32c4f583424260429263b14dc173480",
        binding_nonce_commitment:
          "6ddcd0087825f42f49e0a20667d0a22ec1f16632e665bc258b118d2c713f7dc648765ee9c9715132ed1613fb147f7b459bb9a9b076aeac6280",
        binding_factor_input:
          "3832f82fda00ff5365b0376df705675b63d2a93c24c6e81d40801ba265632be10f443f95968fadb70d10786827f30dc001c8d0f9b7c1d1b000e9a0f30b97fe77ef751b08d4e252a3719ae9135e7f7926f7e3b7dd6656b27089ca354997fe5a633aa0946c89f022462e7e9d50fd6ef313f72d956ea4571089427daa1862f623a41625177d91e4a8f350ce9c8bd3bc7c766515dc1dd3a0eab93777526b616cccb148fe1e5992dc1ae705c8ba66106db565fc6b7de14708224aaafe91425c672f8b660bcebe93d4fdbe47cdb0cdf6e3bab2bf79d270821f191871ad4e3ca4a27888d3c39f16f01a6c4998e50ed67788e401b5b3472eb4ef52ff3ad2fabc58282dcffb9785f9ea42313b440270f08356bc63a8ad503a28d44a91ac364cf177000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        binding_factor:
          "d59a8d07f61c7f426d7a63c37d4994d2fb51c616dd4d440919f088adf61fea9fddab43f1846d52d56eb6654eb0ec7c86ba329f6ff509611a00",
      },
      {
        identifier: 257,
        hiding_nonce_randomness: "59b38a54af4a8309e151e977574eea0f1392d51b41e84489c675e72eacccaa9c",
        binding_nonce_randomness:
          "a7ddd5ae6fb43cf39695e1d78fdb3928f445582662893e2c677d6eef71e8c8b9",
        hiding_nonce:
          "e0ffcbcf2ea177a659cd52de14139fe34a48ac51c745272324ef89e826374adbd4d90f1c5e6095a346eeeaa55b675b336efb434a26f8732f00",
        binding_nonce:
          "5cd906a579641e66b8f968146534cdad5309d4831156332ac97e9ea9a77a1dd0f67694071e5a8f8770f9f38754fa3ea4b39cb044c27f1e1200",
        hiding_nonce_commitment:
          "949a3bbc0272cdc49bc17f8469aa38057bc17a69d20d5482b2f6d4a089d109a417f1b84079ff2546891bcf768845b552775e911fc3807bb900",
        binding_nonce_commitment:
          "65d5fc0775c3b701b302bf27414e8ef322d4daf9949244b5b3d8262d40f060e830066aaf237ffac739e9997915cede51512ceea136b052aa00",
        binding_factor_input:
          "3832f82fda00ff5365b0376df705675b63d2a93c24c6e81d40801ba265632be10f443f95968fadb70d10786827f30dc001c8d0f9b7c1d1b000e9a0f30b97fe77ef751b08d4e252a3719ae9135e7f7926f7e3b7dd6656b27089ca354997fe5a633aa0946c89f022462e7e9d50fd6ef313f72d956ea4571089427daa1862f623a41625177d91e4a8f350ce9c8bd3bc7c766515dc1dd3a0eab93777526b616cccb148fe1e5992dc1ae705c8ba66106db565fc6b7de14708224aaafe91425c672f8b660bcebe93d4fdbe47cdb0cdf6e3bab2bf79d270821f191871ad4e3ca4a27888d3c39f16f01a6c4998e50ed67788e401b5b3472eb4ef52ff3ad2fabc58282dcffb9785f9ea42313b440270f08356bc63a8ad503a28d44a91ac364cf177010100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        binding_factor:
          "d54cfc69ea3e19f4c56e2852e127911cf64a92e6d62b57b433bc97f0d98c5011df3bc78bd220781eb64b68f40e8642445d0f0ab77d34e33300",
      },
    ],
  },
  round_two_outputs: {
    outputs: [
      {
        identifier: 129,
        sig_share:
          "519fc2abd478731b95e9b312608d5537544fdbc75e774b6aab5eb455b00ad0bc026f6d33e349d531b107db52c8c9c1224261b9ad04bb841a00",
      },
      {
        identifier: 256,
        sig_share:
          "1ed886dce506dc95f651a83ee34ebd1d5bf52940ad6b462592475bd56bfbd4d20677185ce1a74a5d8892acf8d5761ee710ecfbfbf52e5a3000",
      },
      {
        identifier: 257,
        sig_share:
          "e7f4a4b9110393fe38656af1be70044bd878e5924e68bf398b668c98244a76e57f378f6caf4b7a8153d4456e34114105a71de9bbf993d13300",
      },
    ],
  },
  final_output: {
    sig: "9217a13561be869233292a2e3a96b6b7ad6fa13b8e4e6d3241d442a77d9d0994d25259dcdf2ab57f1d43c51006f99b541820e46f39089e12806327969639c0698c6f1101b58f8aaa7ef78614ec10700205dfe8d14641501b75891d15fc733d9a108d6ecdb9d251210ffa6a9e65f47db03e00",
  },
} as const;
