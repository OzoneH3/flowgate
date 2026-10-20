// Lex local desktop Exec text, never execute it. A wrapper may identify a game
// only by its one literal absolute executable argument, not its display name.
function words(text: string): string[] | undefined {
  if (text.length > 4096 || /[$`\n\r;&|<>%]/.test(text)) return;
  const out: string[] = [];
  let word = '',
    quote = '',
    started = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (c === '\\' && quote !== "'") {
      if (++i >= text.length) return;
      word += text[i];
      started = true;
    } else if (quote) {
      if (c === quote) quote = '';
      else word += c;
    } else if (c === '"' || c === "'") {
      quote = c;
      started = true;
    } else if (/\s/.test(c)) {
      if (started) out.push(word);
      word = '';
      started = false;
    } else {
      word += c;
      started = true;
    }
  }
  if (quote) return;
  if (started) out.push(word);
  return out.length <= 32 ? out : undefined;
}
export function desktopGameExecutable(exec: string): string | undefined {
  let tokens = words(exec);
  if (!tokens) return;
  if (['bash', 'sh'].includes(tokens[0]?.split('/').pop() || '')) {
    if (tokens.length !== 3 || tokens[1] !== '-c') return;
    tokens = words(tokens[2]);
    if (!tokens) return;
  }
  // A single literal game, or one literal wrapper and its sole game argument.
  if (!tokens.length || tokens.length > 2) return;
  const candidate = tokens.at(-1)!;
  if (
    !candidate.startsWith('/') ||
    candidate.split('/').includes('..') ||
    !/\.exe$/i.test(candidate)
  )
    return;
  return candidate;
}
