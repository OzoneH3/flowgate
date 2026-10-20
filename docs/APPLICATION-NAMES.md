# Application display names

Friendly names are display metadata only. They never change an application's
key, revision, UID, executable, Wine prefix, rule scope or permissions. The
executable remains available in Details. Missing or ambiguous metadata falls
back to the executable name.

Windows applications use bounded PE VERSIONINFO FileDescription/ProductName
resources. Native desktop applications use matching desktop entries. Flatpak
applications use their exact deployment's Application.name and desktop entry.

A live sandbox executable can supply its backend-proven host backing path.
For a stored rule without that path, the UI searches installed user/system
Flatpak deployments and requires the native application key (including UID)
and file revision to match the candidate executable. It does not choose a
package merely because the executable basename matches. A missing/updated
old deployment can therefore retain its filename label.

Some packages copy and self-update their executable under private application
data. The desktop entry's wrapper can supply its display association, but only
when bounded static parsing resolves its final exec target to exactly the
stored executable. Supported wrappers use initial quoted literal assignments,
references to those variables and XDG_DATA_HOME, and one final quoted exec.
No shell is executed; substitutions, unknown variables, reassignment and
ambiguous exec targets are rejected. Unsupported wrappers retain filenames.
Other binaries in the same directory do not inherit the application's name or
permissions. Names are read from installed metadata, never hard-coded per app.

Regression coverage includes inactive rules, same-folder unrelated binaries,
wrong UID, changed revision, malformed wrappers and a saved rule alongside a
live application record. Native-window evidence uses local fixture sockets;
it does not mutate the host daemon.
