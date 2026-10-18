import type { Application } from './protocol';
const cache = new Map<string, { icon: string | null; name?: string }>();
export function applicationHeading(app: Application | undefined, fallback: string) {
  const header = document.createElement('div');
  header.className = 'compact-application';
  const icon = document.createElement('span');
  icon.className = 'application-icon';
  icon.textContent = '◇';
  const label = document.createElement('strong');
  label.textContent = app?.display_name || app?.name.replace(/ \(deleted\)$/, '') || fallback;
  label.title = app?.display_executable || app?.executable || fallback;
  header.append(icon, label);
  if (!app?.key) return header;
  const key = JSON.stringify([app.key, app.revision, app.executable]);
  const paint = (metadata: { icon: string | null; name?: string }) => {
    if (metadata.name) label.textContent = metadata.name;
    if (metadata.icon) {
      const img = document.createElement('img');
      img.width = img.height = 16;
      img.alt = '';
      img.src = metadata.icon;
      img.onerror = () => {
        icon.textContent = '◇';
      };
      icon.replaceChildren(img);
    }
  };
  const known = cache.get(key);
  if (known) paint(known);
  else
    void window.flowgate
      .applicationMetadata([key])
      .then((result) => {
        const metadata = result[key];
        if (!metadata) return;
        if (cache.size >= 128) cache.delete(cache.keys().next().value!);
        cache.set(key, metadata);
        paint(metadata);
      })
      .catch(() => {});
  return header;
}
