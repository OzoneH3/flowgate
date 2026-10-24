# Network endpoint permissions

Network endpoint rules are explicit administrator permissions for one remote IP
and TCP port in the outgoing direction. They cover **all users and programs**,
including traffic whose application cannot be identified and traffic generated
by the kernel. They do not identify a kernel service, application, SMB share or
user. No endpoint rule is created automatically from a blocked request.

This provides a reviewed network scope for transports such as kernel CIFS mounts
that cannot be represented by a userspace application's descriptor ownership.
Giving a shell or mount helper application permission does not identify the
kernel transport. Missing ownership alone also does not prove kernel origin.

In the Electron **Rules** tab, choose **Endpoint permission…**, enter an exact IP
and remote TCP port, choose Allow or Deny and an expiry, then request a preview.
The preview states the full scope and current enforcement coverage. Saving
requires acknowledging the all-users/programs scope and precedence. A saved rule
has no effect while its direction is not being intercepted. Same-host traffic
retains the existing localhost policy.

Endpoint rules have a separate, higher policy tier. Endpoint Deny wins over
Endpoint Allow; remaining ties use the smaller rule ID. An endpoint Allow
**overrides application Deny and Ask** for every matching flow. Existing
application, process and zone rules do not acquire this authority. IP or port
changes, other directions and UDP remain outside the endpoint rule.

Removal and expiry govern new admissions and reconnects. Existing admitted TCP
connections may continue; deletion is not a disconnect operation. Rule scope is
immutable in this interface: conditionally delete the exact version, then create
and review a replacement. Unknown save outcomes have a **Check save result**
action that reads inventory; the client does not automatically resend creation.

The first version accepts one non-loopback unicast IP and a port from 1 to
65535. Hostnames, CIDRs, wildcard addresses, scoped/link-local addresses,
multicast, local-port constraints, interface bindings, application/UID bindings
and Ask are unavailable. IPv4-mapped IPv6 inputs normalize to IPv4. Expiry is
explicit: a future time within 365 days or No expiry. The UI offers bounded
shorter durations and No expiry.

## API and compatibility

`network-endpoint-policy-v1` is advertised only by a writable administrator
controller. `endpoint-rule-preview` accepts a generation and `endpoint_draft`
with `action`, `remote_address`, `remote_port` and required `expires`. The save
request repeats that draft with the preview token. The backend binds the
30-second preview to the peer, generation and complete configured policy.
Mutation refusals require a fresh review; a successful save receipt identifies
the exact reserved rule. The ordinary and read-only endpoints can display
machine rule inventory but cannot create or delete endpoint rules.

Rules use schema 7 and the explicit `network_endpoint` flag. Generic application
editing, enable/disable and creation from an application basis are unavailable.
Conditional deletion uses the existing generation, rule ID and expected version.
Older binaries that cannot read schema 7 refuse the new policy. Before a
**deliberate downgrade**, remove endpoint rules using a compatible administrator
client; never convert them silently to legacy AllPrograms rules. Installer
preflight and schema compatibility are checked separately from a rule save.

Diagnostic `no_userspace_owner_observed` means a complete observation found one
matching socket and no userspace holder. It does not mean a specific kernel
service was verified. Incomplete observations and no matching socket retain
separate reasons. These diagnostic labels do not grant permission.

When an endpoint rule decides a flow, `not-requested` with
`attribution_not_required` means the application ownership collectors were
intentionally skipped: the explicit network permission supplies independent
authority. It does not mean kernel or application ownership was observed.
Interception, queue capacity and admission deadlines still apply, and another
firewall or the peer can refuse the connection. All-traffic scope describes
which flows match; it is not a guarantee of delivery or successful authentication.

The guarded updater requires passwordless update helper **v2**, which includes
the stored-schema check. An older helper is refused before protection is stopped.
An administrator who previously enabled passwordless updates must refresh the
existing helper once, from the reviewed checkout, using
`sudo /usr/bin/python3 -I scripts/setup-passwordless-update.py` from the desktop
account. This development change does not run that privileged setup, install a
release or create a live endpoint permission automatically.
