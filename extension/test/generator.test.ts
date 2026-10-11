// SPDX-FileCopyrightText: 2026 Alex Mextner
// SPDX-License-Identifier: MIT
// Apple-style password generator: exact format, character classes, reproducibility with an
// injected source, unbiased default randomness, and a rough uniformity check over many runs.

import { afterEach, describe, expect, test } from "bun:test";

import {
  APPLE_ALPHABET,
  APPLE_DIGITS,
  applePassword,
  secureRandom,
} from "../src/content/generator";

const FORMAT = /^[a-zA-Z0-9]{6}-[a-zA-Z0-9]{6}-[a-zA-Z0-9]{6}$/;
const RUNS = 3000;
const samples = Array.from({ length: RUNS }, () => applePassword());

function characters(password: string): string[] {
  return Array.from(password.replaceAll("-", ""));
}

/** A deterministic source that replays `values` (reduced into range), then returns 0. */
function replay(values: readonly number[]): (bound: number) => number {
  let next = 0;
  return (bound) => {
    const value = values[next] ?? 0;
    next += 1;
    return value % bound;
  };
}

describe("applePassword format", () => {
  test("the alphabet has no l or o and no duplicates", () => {
    expect(APPLE_ALPHABET).not.toMatch(/[lo]/);
    expect(new Set(APPLE_ALPHABET).size).toBe(APPLE_ALPHABET.length);
    expect(APPLE_ALPHABET).toBe("abcdefghijkmnpqrstuvwxyz");
  });

  test.each(samples.slice(0, 25))("%s has the xxxxxx-xxxxxx-xxxxxx shape", (password) => {
    expect(password).toHaveLength(20);
    expect(password).toMatch(FORMAT);
    expect(password.split("-")).toHaveLength(3);
  });

  test("every sample has exactly one uppercase letter and one digit", () => {
    for (const password of samples) {
      const chars = characters(password);
      expect(chars.filter((c) => /[A-Z]/.test(c))).toHaveLength(1);
      expect(chars.filter((c) => /[0-9]/.test(c))).toHaveLength(1);
      expect(chars.filter((c) => /[a-z]/.test(c))).toHaveLength(16);
    }
  });

  test("every letter, either case, comes from the alphabet", () => {
    for (const password of samples) {
      for (const c of characters(password)) {
        if (APPLE_DIGITS.includes(c)) continue;
        expect(APPLE_ALPHABET).toContain(c.toLowerCase());
      }
    }
  });
});

describe("applePassword with injected randomness", () => {
  test("is deterministic for the same source", () => {
    const values = [5, 7, 3, 1, 4, 1, 5, 9, 2, 6, 5, 3, 5, 8, 9, 7, 9, 3, 2, 3];
    expect(applePassword(replay(values))).toBe(applePassword(replay(values)));
  });

  test("all zeros puts the uppercase first and the digit second", () => {
    expect(applePassword(() => 0)).toBe("A0aaaa-aaaaaa-aaaaaa");
  });

  test("maximum draws put the uppercase last and the digit just before it", () => {
    expect(applePassword((bound) => bound - 1)).toBe("zzzzzz-zzzzzz-zzzz9Z");
  });

  test("the digit position skips over the uppercase position", () => {
    // Uppercase at 4; digit slot 4 of the remaining 17 lands on position 5.
    const password = applePassword(replay([4, 4, 0]));
    expect(characters(password).at(4)).toBe("A");
    expect(characters(password).at(5)).toBe("0");
  });

  test("bounds are requested in the documented order", () => {
    const bounds: number[] = [];
    applePassword((bound) => {
      bounds.push(bound);
      return 0;
    });
    expect(bounds.slice(0, 2)).toEqual([18, 17]);
    expect(bounds.slice(2)).toEqual([24, 10, ...Array.from({ length: 16 }, () => 24)]);
  });

  test.each([
    ["negative", -1],
    ["equal to the bound", 24],
    ["fractional", 0.5],
    ["NaN", Number.NaN],
  ])("a source returning a %s value is rejected", (_name, value) => {
    expect(() => applePassword(() => value)).toThrow(RangeError);
  });
});

describe("secureRandom", () => {
  const original = crypto.getRandomValues.bind(crypto);
  afterEach(() => {
    crypto.getRandomValues = original;
  });

  function feed(draws: readonly number[]): void {
    let next = 0;
    crypto.getRandomValues = <T extends ArrayBufferView | null>(array: T): T => {
      if (array instanceof Uint32Array) {
        array[0] = draws[next] ?? 0;
        next += 1;
      }
      return array;
    };
  }

  test("rejects draws in the incomplete last block instead of folding them", () => {
    // For bound 3, 2^32 % 3 = 1, so only the single top value 2^32 - 1 is rejected.
    feed([2 ** 32 - 1, 7]);
    expect(secureRandom(3)).toBe(1);
  });

  test("keeps drawing until a value is acceptable", () => {
    // For bound 10, values from 4294967290 up are rejected.
    feed([4_294_967_295, 4_294_967_290, 4_294_967_289]);
    expect(secureRandom(10)).toBe(9);
  });

  test("bound 1 always yields 0", () => {
    expect(Array.from({ length: 20 }, () => secureRandom(1))).toEqual(
      Array.from({ length: 20 }, () => 0),
    );
  });

  test.each([0, -3, 1.5, 2 ** 32 + 1])("bound %p is rejected", (bound) => {
    expect(() => secureRandom(bound)).toThrow(RangeError);
  });

  test("values stay in range", () => {
    for (let i = 0; i < 2000; i += 1) {
      const value = secureRandom(24);
      expect(Number.isInteger(value) && value >= 0 && value < 24).toBe(true);
    }
  });
});

describe("distribution sanity", () => {
  // Loose bounds: with RUNS samples a fair source stays far inside them, a broken one does not.
  test("the uppercase letter lands on every one of the 18 positions", () => {
    const counts = Array<number>(18).fill(0);
    for (const password of samples) {
      const at = characters(password).findIndex((c) => /[A-Z]/.test(c));
      counts[at] = (counts[at] ?? 0) + 1;
    }
    const expected = RUNS / 18;
    for (const count of counts) {
      expect(count).toBeGreaterThan(expected * 0.5);
      expect(count).toBeLessThan(expected * 1.5);
    }
  });

  test("the digit position is spread too and never collides with the uppercase", () => {
    const counts = Array<number>(18).fill(0);
    for (const password of samples) {
      const at = characters(password).findIndex((c) => /[0-9]/.test(c));
      counts[at] = (counts[at] ?? 0) + 1;
    }
    expect(Math.min(...counts)).toBeGreaterThan((RUNS / 18) * 0.5);
  });

  test("all ten digits occur", () => {
    const seen = new Set(samples.flatMap((p) => characters(p).filter((c) => /[0-9]/.test(c))));
    expect([...seen].sort().join("")).toBe(APPLE_DIGITS);
  });

  test("lowercase letters are roughly uniform", () => {
    const counts = new Map<string, number>();
    for (const password of samples) {
      for (const c of characters(password)) {
        if (/[a-z]/.test(c)) counts.set(c, (counts.get(c) ?? 0) + 1);
      }
    }
    expect(counts.size).toBe(APPLE_ALPHABET.length);
    const expected = (RUNS * 16) / APPLE_ALPHABET.length;
    for (const count of counts.values()) {
      expect(count).toBeGreaterThan(expected * 0.8);
      expect(count).toBeLessThan(expected * 1.2);
    }
  });

  test("no two of the samples repeat", () => {
    expect(new Set(samples).size).toBe(RUNS);
  });
});
