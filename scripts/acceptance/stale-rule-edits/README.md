# Stale rule edits

Run headlessly when the flowgate-lab VM slot is free. The runner at
`bd60c80a` or a compatible successor supplies a disposable guest, SSH,
the installed FlowGate API client and a host-loopback TCP receiver. From the
FlowGate checkout, use the previously verified RC8 pair for build `64a07da1`:

```sh
dist="$PWD/build/dist/fg-lab-fedora-guard-final"
python3 -B scripts/acceptance/stale-rule-edits/run.py --profile debian-13 \
  --archive "$dist/flowgate-0.1.0-rc.8-linux-x86_64.tar.gz" \
  --archive-sha256 55f522e7f12f87f91bbcc5ab7c170c846abeed3f26ee8975b9b579b5b0fb01af \
  --installer "$dist/flowgate-release.py" \
  --installer-sha256 94a2956bf3477875aa63eafc3f2abd555160837d220f8449b3dfe3cbc349124c
```

Use `--lab` for a lab checkout elsewhere. The runner verifies both digests
and the installed build, runs one guest, and removes the overlay on exit.

The fixture saves an explicit outgoing application Allow, edits it to Block,
and tries saving the old Allow with the old version in the current generation.
It expects `version_conflict`. A protected daemon restart then changes the
generation. Submitting an Allow edit with the current Block version and the
previous generation must return `generation_conflict`.

After each refusal, the complete Block record must match the saved record. A
fresh TCP attempt must terminate without host delivery, and the Decision Log
must name the Block ID and version. The final edit uses the current generation
and version, saves Allow, and delivers exactly one new labeled payload.

The exit status reports pass or fail. The runner prints an evidence directory
under `.workspace/stale-rule-edits/runs/`. The scenario JSONL includes both
requests and errors, generations, saved rules, client results, exact-tuple log
rows, and receiver counts.
