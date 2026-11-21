import { deflateSync } from 'node:zlib';
// Decode bounded uncompressed ICO frames and embedded PNG artwork.
const MAX_BYTES = 1024 * 1024;
function chunk(name: string, data: Buffer) {
  const body = Buffer.concat([Buffer.from(name), data]);
  let crc = 0xffffffff;
  for (const byte of body) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit++) crc = (crc >>> 1) ^ (crc & 1 ? 0xedb88320 : 0);
  }
  const size = Buffer.alloc(4),
    sum = Buffer.alloc(4);
  size.writeUInt32BE(data.length);
  sum.writeUInt32BE((crc ^ 0xffffffff) >>> 0);
  return Buffer.concat([size, body, sum]);
}
export function icoToPng(data: Buffer): Buffer | undefined {
  if (
    data.length < 22 ||
    data.length > MAX_BYTES ||
    data.readUInt16LE(0) !== 0 ||
    data.readUInt16LE(2) !== 1
  )
    return;
  const count = data.readUInt16LE(4);
  if (!count || count > 256 || 6 + count * 16 > data.length) return;
  const frames = [];
  for (let i = 0; i < count; i++) {
    const at = 6 + i * 16,
      width = data[at] || 256,
      height = data[at + 1] || 256;
    const size = data.readUInt32LE(at + 8),
      offset = data.readUInt32LE(at + 12);
    if (offset < 6 + count * 16 || size < 24 || offset + size > data.length) continue;
    frames.push({ width, height, bytes: data.subarray(offset, offset + size) });
  }
  frames.sort((a, b) => Math.abs(a.width - 32) - Math.abs(b.width - 32));
  for (const { width, height, bytes } of frames) {
    if (bytes.subarray(0, 8).equals(Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]))) {
      if (bytes.readUInt32BE(16) === width && bytes.readUInt32BE(20) === height) return bytes;
      continue;
    }
    if (
      bytes.length < 40 ||
      bytes.readUInt32LE(0) !== 40 ||
      bytes.readInt32LE(4) !== width ||
      bytes.readInt32LE(8) !== height * 2 ||
      bytes.readUInt16LE(12) !== 1 ||
      ![1, 4, 8, 24, 32].includes(bytes.readUInt16LE(14)) ||
      bytes.readUInt32LE(16) !== 0
    )
      continue;
    const bits = bytes.readUInt16LE(14);
    const indexed = bits <= 8;
    const paletteSize = indexed ? bytes.readUInt32LE(32) || (1 << bits) : 0;
    if (indexed && paletteSize > (1 << bits)) continue;
    const pixelsStart = 40 + paletteSize * 4;
    const rowStride = Math.ceil(width * bits / 32) * 4,
      maskStride = Math.ceil(width / 32) * 4,
      pixelsEnd = pixelsStart + rowStride * height;
    if (pixelsEnd + maskStride * height > bytes.length) continue;
    let hasAlpha = false;
    for (let at = pixelsStart + 3; bits === 32 && at < pixelsEnd; at += 4)
      if (bytes[at]) {
        hasAlpha = true;
        break;
      }
    const scan = Buffer.alloc((width * 4 + 1) * height);
    let valid = true;
    for (let y = 0; y < height && valid; y++)
      for (let x = 0; x < width; x++) {
        const row = height - 1 - y;
        let src = pixelsStart + row * rowStride + ((x * bits) >> 3);
        if (indexed) {
          // Packed palette indices come most-significant first in each byte.
          const shift = 8 - bits - ((x * bits) & 7);
          const index = (bytes[src] >> shift) & ((1 << bits) - 1);
          if (index >= paletteSize) {
            valid = false;
            break;
          }
          src = 40 + index * 4;
        }
        const dst = y * (width * 4 + 1) + 1 + x * 4;
        scan[dst] = bytes[src + 2];
        scan[dst + 1] = bytes[src + 1];
        scan[dst + 2] = bytes[src];
        const transparent = bytes[pixelsEnd + row * maskStride + (x >> 3)] & (0x80 >> (x & 7));
        scan[dst + 3] = transparent ? 0 : hasAlpha ? bytes[src + 3] : 255;
      }
    if (!valid) continue;
    const header = Buffer.alloc(13);
    header.writeUInt32BE(width);
    header.writeUInt32BE(height, 4);
    header[8] = 8;
    header[9] = 6;
    return Buffer.concat([
      Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]),
      chunk('IHDR', header),
      chunk('IDAT', deflateSync(scan)),
      chunk('IEND', Buffer.alloc(0)),
    ]);
  }
}
