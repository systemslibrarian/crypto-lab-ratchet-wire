/**
 * Small byte-buffer helpers shared by the crypto layer.
 *
 * The curve layer (`@noble`) speaks `Uint8Array`, while the HKDF/AES-GCM layer
 * (Web Crypto) speaks `ArrayBuffer`. These two converters bridge the boundary
 * exactly once, so the rest of the code can stay in whichever representation is
 * natural for it.
 */

/**
 * Return a fresh, standalone `ArrayBuffer` holding exactly the bytes of `view`.
 *
 * Always copies: a `Uint8Array` can be a window onto a larger backing buffer
 * (so `.buffer` could expose adjacent bytes), and copying also means a caller
 * that later zeroes the returned buffer (forward-secrecy hygiene) can never
 * corrupt the source array it was derived from.
 */
export function toArrayBuffer(view: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(view.byteLength);
  copy.set(view);
  return copy.buffer;
}

/** Normalize any `BufferSource` to a `Uint8Array` without copying when possible. */
export function asUint8Array(data: BufferSource): Uint8Array {
  if (data instanceof Uint8Array) return data;
  if (ArrayBuffer.isView(data)) {
    return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  }
  return new Uint8Array(data);
}
