// SPDX-FileCopyrightText: 2026 Alex Mextner
// SPDX-License-Identifier: MIT
// Safari-style strong passwords (`xxxxxx-xxxxxx-xxxxxx`), so passwords generated in the browser
// look like the ones iCloud Keychain itself creates.

/** Lowercase letters without the easily confused `l` and `o`. */
export const APPLE_ALPHABET = "abcdefghijkmnpqrstuvwxyz";
export const APPLE_DIGITS = "0123456789";

const GROUPS = 3;
const GROUP_LENGTH = 6;
const LENGTH = GROUPS * GROUP_LENGTH;
const UINT32_RANGE = 2 ** 32;

/**
 * A uniformly distributed integer in [0, bound) from `crypto.getRandomValues`. Draws that fall
 * in the incomplete last block of 2^32 are rejected so no value is favoured (no modulo bias).
 */
export function secureRandom(bound: number): number {
  if (!Number.isInteger(bound) || bound < 1 || bound > UINT32_RANGE) {
    throw new RangeError(`bound must be an integer in [1, 2^32], got ${bound}`);
  }
  const limit = UINT32_RANGE - (UINT32_RANGE % bound);
  const buffer = new Uint32Array(1);
  for (;;) {
    crypto.getRandomValues(buffer);
    const draw = buffer[0] ?? 0;
    if (draw < limit) return draw % bound;
  }
}

/**
 * An Apple-style password: three groups of six lowercase letters joined by dashes, with exactly
 * one letter uppercased and one character replaced by a digit, both at random positions.
 *
 * `random(bound)` must return an integer in [0, bound). Calls happen in a fixed order, which
 * makes injected sequences reproducible: uppercase position (bound 18), digit position among
 * the remaining 17, then for each of the 18 positions left to right either a digit (bound 10)
 * or a letter (bound 24).
 */
export function applePassword(random: (bound: number) => number = secureRandom): string {
  const draw = (bound: number): number => {
    const value = random(bound);
    if (!Number.isInteger(value) || value < 0 || value >= bound) {
      throw new RangeError(`random(${bound}) returned ${value}`);
    }
    return value;
  };
  const upperAt = draw(LENGTH);
  const digitSlot = draw(LENGTH - 1);
  const digitAt = digitSlot >= upperAt ? digitSlot + 1 : digitSlot;
  let password = "";
  for (let position = 0; position < LENGTH; position += 1) {
    if (position > 0 && position % GROUP_LENGTH === 0) password += "-";
    if (position === digitAt) {
      password += APPLE_DIGITS.charAt(draw(APPLE_DIGITS.length));
      continue;
    }
    const letter = APPLE_ALPHABET.charAt(draw(APPLE_ALPHABET.length));
    password += position === upperAt ? letter.toUpperCase() : letter;
  }
  return password;
}
