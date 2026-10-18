/** Display only. All input counters and sorting remain backend byte values. */
export const DISPLAY_UNITS = [
  'autoByte',
  'autoBit',
  'B',
  'KB',
  'MB',
  'GB',
  'bit',
  'Kbit',
  'Mbit',
  'Gbit',
] as const;
export type DisplayUnit = (typeof DISPLAY_UNITS)[number];
export function isDisplayUnit(v: unknown): v is DisplayUnit {
  return typeof v === 'string' && DISPLAY_UNITS.includes(v as DisplayUnit);
}
export function displayAmount(
  value: number | undefined,
  rate = false,
  unit: DisplayUnit = 'autoByte',
): string {
  if (value === undefined || !Number.isFinite(value) || value < 0) return '—';
  const bits = unit === 'autoBit' || unit.toLowerCase().endsWith('bit');
  let n = value * (bits ? 8 : 1),
    power = 0;
  const labels = bits ? ['bit', 'Kbit', 'Mbit', 'Gbit', 'Tbit'] : ['B', 'KB', 'MB', 'GB', 'TB'];
  if (unit.startsWith('auto')) {
    while (n >= 1000 && power < labels.length - 1) {
      n /= 1000;
      power++;
    }
  } else {
    power = labels.indexOf(unit);
    n /= 1000 ** Math.max(0, power);
  }
  const digits =
    n > 0 && n < 0.01 ? Math.min(12, Math.ceil(-Math.log10(n)) + 1) : power === 0 && !rate ? 0 : 2;
  return `${n
    .toFixed(digits)
    .replace(/(\.\d*?[1-9])0+$/, '$1')
    .replace(/\.0+$/, '')} ${labels[power]}${rate ? '/s' : ''}`;
}
