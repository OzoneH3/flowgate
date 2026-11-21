# Linux compatibility record

The standalone package targets x86-64 Linux with systemd. The tables cover the
ten distribution and desktop profiles exercised by the local FlowGate VM lab
on 20–21 November 2026. Each result applies to the installed build, guest
setup and scenario shown. [Standalone verification record](STANDALONE-RELEASE.md#verification-record)

## RC8 and subsequent checks

The audited RC8 package contains FlowGate
`7511ac1764c8a922c1ad259747338973adf197f2`. The desktop **Allow once** checks
required one click on the original live request, exactly one receiver delivery,
a linked user decision, unchanged saved rules and a competing request still
pending at zero deliveries. The **Deny once** checks required the linked
denial and zero deliveries for the live request.

| Guest | Scenario and result | Run |
| --- | --- | --- |
| Debian 13.7, headless | Twelve rule cases passed, plus a separate UDP fast-path pass. | `c16cf263da6d`, `2b04e50d2c34` |
| Linux Mint 22.3 Cinnamon, X11 | Allow once and Deny once passed. | `e745ae884af4`, `169aff123f0c` |
| Kubuntu 26.04.1 KDE Plasma, Wayland | Allow once passed. | `de060586f8e3` |
| CachyOS KDE Plasma, Wayland | Allow once and Deny once passed with stock UFW. | `0f10f2b56394`, `73c8718f07dd` |
| Xubuntu 26.04.1 Xfce, X11 | Allow once passed. | `554eabd8f2e8` |
| openSUSE Tumbleweed KDE Plasma, Wayland | Allow once passed with stock firewalld after a verifier retry. | `a5b3c637bd04` |
| Ubuntu 26.04.1 GNOME, Wayland | Stopped at desktop launch while waiting for GNOME Shell. | `db0932188a72` |
| Fedora 45 GNOME, Wayland | Stopped at desktop launch without a Wayland socket. | `1dc527678a53` |
| CachyOS Hyprland, Wayland | Launched, then stopped at popup navigation during first-login setup. | `4903f27a2302` |
| Pop!_OS 24.04 COSMIC, Wayland | The dock covered the popup footer at stock 1280×800 and default scaling. | `6751c9237ac6` |

Pop!_OS run `282332ea3741` passed **Allow once** at the same display settings
on placement-fix build `a96ab84d54b31eb43ef03604c2de62770cc863f1`. The
runner advanced past the resolver card using **Next request**.

Debian 13.7 run `c268f1c6c733` passed the guarded upgrade from
`13e3029ac2e4d2695b851cfb09710d9ab4bb8bf7` to
`1b336f7a9664fb5dcaaa11994f6eaf4fa6ea72f2` on stock `/run` mounted
`noexec`. It also verified rollback to monitoring with the saved rule
preserved and the predecessor's UDP collector limitation reported.

## Earlier headless firewall checks

The same runner (`75af5ee36a464b60a80669c9f15598f3b52eb02d`) tested FlowGate
`13e3029ac2e4d2695b851cfb09710d9ab4bb8bf7` on three guests. Each passed the
12-case rule suite and the separate UDP fast-path suite. The rule cases covered
Ask/Allow Once, queued decisions, saved Allow and Block rules, expiry, address
scope and precedence, independent TCP directions, and an established TCP
disconnect. The runner answered requests through the daemon API.

| Guest | Rule suite run | UDP suite run |
| --- | --- | --- |
| Debian 13.7 netinst, headless | `105a144b005e` | `23e6663f2f72` |
| Ubuntu Desktop 26.04.1, headless checks | `28064f5a4261` | `8fa2e2744731` |
| Fedora Workstation 45, headless checks | `f913fe3bf984` | `ad768273d030` |

An earlier Ubuntu 26.04.1 **cloud** image had a different package set. On
`6ec6327a5907f5f71e52a1359b4044250f16e015`, installation stopped at a missing
`/usr/bin/runuser` (`801393f41af0`). Four headless cases passed after adding
desktop libraries and a guest-only symlink (`a94031a05254`).

## Earlier desktop decisions by guest

A **delivery** here means the receiving endpoint counted zero labelled TCP
payloads while the request was held, then one after a desktop Allow Once.
The Decision Log linked the user's decision to the original request. Where
a competing request was measured, it had its own ID. The separate sweep below
shows how far a subsequent build got on every desktop.

| Distribution | Desktop and session | Installed FlowGate commit | Run and observed outcome |
| --- | --- | --- | --- |
| Ubuntu 26.04.1 | GNOME 50.1, Wayland | `5359baf0873f17ee8af18e00b62417bbaae77398` | `6a91c9aef959` verified popup delivery using the installer's AppArmor profile with no manual desktop adjustments. |
| Fedora 45 Workstation | GNOME, Wayland | `64a07da1ebdf7033622c8e77385bc99265f19279` | `58f1f260a27c` verified popup delivery with SELinux enforcing. A competing request stayed pending. See the later firewalld blocker below. |
| Kubuntu 26.04.1 | KDE Plasma, Wayland | `51cf10f14988478392645c10f7c321077f479b64` | `06a2cc5bc222` verified popup delivery. The first unassisted frame showed the prompt. The competing request stayed pending at zero. |
| CachyOS | KDE Plasma, Wayland | `51cf10f14988478392645c10f7c321077f479b64` | `25821f6e7065` verified popup delivery with stock UFW active. The prompt appeared automatically. The runner later switched windows during queue navigation. The competitor stayed pending at zero. |
| Linux Mint 22.3 | Cinnamon, X11 | `24f9b61b006801f15ae089c9bad8b6e6bdb74e84` | `7fd4e6775382` verified popup delivery. The competitor stayed pending at zero. |
| Xubuntu 26.04.1 | Xfce, X11 | `24f9b61b006801f15ae089c9bad8b6e6bdb74e84` | `196644b9317c` verified popup delivery. The competitor stayed pending at zero. |
| Pop!_OS 24.04 LTS | COSMIC, Wayland | `24f9b61b006801f15ae089c9bad8b6e6bdb74e84` | `39aa2bd631ab` verified popup delivery with the competitor pending at zero. Repeats `fe2cc1982341` and `319e8087c6b9` stopped before approval while selecting the request. |
| CachyOS | Hyprland 0.57.2, Wayland | `13e3029ac2e4d2695b851cfb09710d9ab4bb8bf7` | `85f1c8665c43` launched the UI but stock UFW blocked readiness. With UFW disabled in the guest, `01289275e189` verified delivery after navigating to the prompt and using the keyboard. The competitor stayed pending at zero. |
| openSUSE Tumbleweed | KDE Plasma, Wayland | `e7a4c3325dbd53c2ee0921321fdceb7c95301ea5` | `a08c13a2255b` activated both directions with stock firewalld. The selected prompt was visible and the receiver stayed at zero. Duplicate OCR matches stopped the runner before the click. |

## Earlier CachyOS KDE result and RC8 verifier audit

The maintainer reports using FlowGate successfully on CachyOS with KDE Plasma.
The stock-UFW Wayland VM run `25821f6e7065` independently recorded one
Allow Once click, receiver counts of zero before and one after, and unchanged
saved rules. Its original request `f673b45c865f886ba9cc40bd38cbc905` had a
linked user/once/allow decision. The original competitor stayed pending at
zero. That run used FlowGate `51cf10f14988478392645c10f7c321077f479b64`
and lab `1bfca9c1120d5a9e395658dc5b6df014c5b59d44`. Its trace lacks an
immediate pre-click socket-status sample. The later RC8 Plasma runs are
listed above.

### What counts as a desktop pass

The initial stock-matrix audit used FlowGate `7511ac1764c8a922c1ad259747338973adf197f2`
and lab verifier `35563f215ecf4097c5590c7ebcb8ef057e1b2b19`.
Both artifact receipts and the archive's embedded source matched the matrix
handoff. [RC8 archive and installer digests](STANDALONE-RELEASE.md#verification-record)

1. Match the displayed application, PID, outbound TCP direction and both socket endpoints to the target request. Identify one enabled **Allow once** on that card. **Allow always** saves a rule. Selecting a duration changes the lower button from **Allow once** to a timed process allowance.
2. Immediately before the decision click, require both original request IDs pending, the original dial in flight with its original inode and endpoints, and zero labelled target payloads at the receiver.
3. After one decision click, require exactly one labelled target payload and a final **user / once / allow** decision linked through the original pending record. Require identical saved rules and the same competitor still pending with zero deliveries.

An offline replay exercised the committed selector and its decision-click
path on saved frames with input intercepted. The replay used native fixture frames and explicitly modified controls, with
simulated pending requests. Guest results require the installed package and
an independent receiver.

| Replay | Observed decision input |
| --- | --- |
| Fresh card with **Allow always** and **Allow once**, including a composite with a third, timed Allow | Selected the lower **Allow once**. The genuine timed-preset frame produced no decision click. |
| Wrong application, PID, remote address or port | No decision click. |
| Two visible **Allow once** controls in a modified frame | No decision click. |
| Same application, PID and peer, different original dial | **Wrong-card click.** The expected local port was 50202. The saved card showed 50218. The selector accepts the app name anywhere in the card and checks only the remote endpoint. The original request and receiver checks still guard the final result. Match the displayed local endpoint before clicking. |
| Alternate capture of the visible Once control | **Missed control.** The runner could not locate the card boundary. Separately, changing only the OCR token from `once` to `once.` on a passing frame also suppressed the click. |

A separate offline replay used the prior Plasma trace and varied individual
observations. The verifier rejected a dead original dial, an early delivery,
zero or two deliveries at its checked sample, a wrong decision link, source
or scope, changed rules, a replaced competitor, and competitor delivery.
**One false pass was reproduced:** after validating a count of one, the
runner reads the receiver again for `count_after` without checking that
value. With a duplicate arriving between reads, it returned success and
recorded two. Require the last receiver observation to satisfy the count
before accepting a matrix result.

## Nine-desktop check on one build

All nine guests launched the installed desktop on FlowGate
`90792e537299b3d5cf0ca6342f26e524323ec07d`. The lab used runner
`d96c95c40d3deb3a5e7cc859fb1bf48ac1b0c19f` with local desktop-test adapters.
**Held at zero** means the receiver counted zero while the request was pending.
The runner could not select and verify the target in the visible queue and
stopped before approval. Post-Allow delivery is unknown in those rows.

| Distribution and desktop | Session | Run | Last verified step or blocker |
| --- | --- | --- | --- |
| Ubuntu 26.04.1 GNOME | Wayland | `372b5bed2302` | Held at zero |
| Mint 22.3 Cinnamon | X11 | `e8827886e48d` | Held at zero |
| Kubuntu 26.04.1 Plasma | Wayland | `e4ef0781cf5c` | Held at zero |
| Fedora 45 GNOME | Wayland | `0088c421ca5d` | UI launched. Stock firewalld's packet-mark reverse-path check blocked readiness before Ask. |
| CachyOS Plasma | Wayland | `5fd04e24c7a5` | Held at zero with UFW active |
| CachyOS Hyprland | Wayland | `a833789487b1` | Held at zero with UFW active |
| Xubuntu 26.04.1 Xfce | X11 | `2005cd78d12c` | Held at zero |
| Pop!_OS 24.04 COSMIC | Wayland | `391082d49d54` | Held at zero |
| openSUSE Tumbleweed Plasma | Wayland | `cfc33f3b2dee` | Held at zero with firewalld active |

On this build, Mint run `5bdc4ab14f79` also verified tray hide/reopen,
Activity search, the app inspector and a changed timeout on a fresh request.
A manual Allow appeared in the Decision Log after the probe timed out. The
receiver stayed at zero. Four headless policy cases passed in `39fa0c2c410e`.

A later Mint run (`de894698309f`, FlowGate
`7313ff40da3d48be7a809e0a2dce18244a004245`) installed and launched the UI.
The verifier stopped on a missing `decision_timeout` field before creating
the Ask request. On Fedora, a later code change
(`0801fa52203ec71a3aab54bd7f18f9c5cc14908e`) passed a replay of the
captured loose reverse-path firewall rule. Live activation with that fix
still needs a guest result.

## Reading the evidence

Run IDs identify local lab records. In the runner checkout or its retained
test copy, open `.workspace/runs/<run ID>/result.json` for the installed source,
artifact receipts and outcome. Desktop runs also retain screenshots and request
traces. For receiver evidence use the held and after counts alongside the
linked Decision Log outcome. The public checkout contains the [rule semantics](SEMANTICS.md),
[attribution model](ATTRIBUTION.md) and [release verification record](STANDALONE-RELEASE.md#verification-record).
