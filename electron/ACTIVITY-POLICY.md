# Activity: configured policy and existing daemon

Starting UI commit: `6c176474f9cc016105b16ea26712fa8a8aa9b082`.
No backend commits merged; compatible with the running explicit-administrator-v1
contract. Backend policy and authentication files are untouched.

## Policy semantics

In/Out cells select rules only by authoritative application key/revision/UID and
direction. They report inventory constraints, not precedence or connection matching.
Single unconstrained wildcard-protocol rule: app-wide; single protocol-only rule:
protocol label; endpoint constraints: scoped; multiple actions: mixed; otherwise
multiple scoped rules. Disabled/expired rules remain separately visible. No rule
means no explicit rule, not Allow or Ask. Unavailable policy is distinct.

Click opens the exact scope inventory and the existing editor. An unfinished editor
is not replaced. Permission metadata separately gates rule management and decisions.
Stored policy remains visible while enforcement is stopped. Read-only clients get
no Edit action. Conditional deletion/versioning and acknowledgement rules remain.
Creating an initial rule from Activity without a pending request remains an API
limitation; there is no invented application-to-permission conversion.

## Evidence (paths relative to this worktree)

- `.workspace/activity-policy/activity-comparison.png`: before / official reference /
  after; original captures retained as before.png and after.png. No screenshot content
  retouched. rows-comparison.png and sidebar-comparison.png are labelled close-ups.
- after-narrow.png: actual 860×600. after.json records computed geometry/permissions.
- Actual sandboxed Wayland root monitor: machine Activity, real rates/icons, stopped
  enforcement, administrator stored-policy permission and no decision permission;
  descending-first rate sorting and selectable policy list passed. Host rules empty;
  screenshots do not fabricate any. Root generation stayed
  `5a559274aa006090cdc4bb5cd8faed47`.
- production-launch.json/log: normal launcher with --daemon, no owned observer;
  frontend exit preserved root generation, enforcement state and stored rules.
- tests.log: build plus 22 focused backend/rules/delete/notification/presentation/model
  checks passed, including fail-closed permissions, scoped summaries and old conflict
  protections. No broad UDP or enforcement suite repeated.
- isolated.log: `.workspace/policy-ui-WKtA4z` actual sandboxed Wayland and real Go API
  in disposable namespaces; **seeded test rule**, real cell→editor→preview→Block save,
  exact expiry/application preserved and version advanced. Companion read-only denies
  draft and exposes no Edit. No firewall activation. Fixture binary SHA256
  c90baa358b12186daad2cab90c1942710b4083514b5e63fe2e44064ea13dd8fc.
- synthetic.log: explicitly synthetic presentation edge cases (mixed, disabled,
  expired, disconnected and stable selection), no mutations. Prior settled tray,
  accounting, UDP and enforcement evidence is reused, not claimed rerun here.

Reproduce focused isolated workflow with an existing compatible built Go binary:
`FLOWGATE_TEST_DAEMON=/absolute/path/to/flowgate node electron/test/policy-workflow.mjs`.
It owns only its fixture processes. No host policy writes or root daemon lifecycle
operations are performed. Exact color/font equivalence across Windows and KDE is
not claimed; service icon coverage and initial-rule creation remain limited.
