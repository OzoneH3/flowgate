import type { EvaluationState } from './protocol';
const $ = (id: string) => document.getElementById(id)!;
// Updates text/disabled state in place, preserving keyboard focus and open details.
export function renderDaemonEvaluation(e: EvaluationState) {
  const status = $('evaluationStatus');
  status.textContent = `${e.label}. ${e.message}`;
  const section = status.parentElement!;
  let details = document.getElementById('evaluationChecks') as HTMLDetailsElement | null;
  if (!details) {
    details = document.createElement('details');
    details.id = 'evaluationChecks';
    const summary = document.createElement('summary');
    summary.textContent = 'Readiness checks and scope';
    const body = document.createElement('pre');
    body.id = 'evaluationCheckText';
    details.append(summary, body);
    section.append(details);
  }
  const checks =
    e.status?.readiness.checks
      .map(
        (c) => `${c.status} · ${c.id} · ${c.code}\n${c.detail}${c.next ? '\nNext: ' + c.next : ''}`,
      )
      .join('\n\n') || 'No detailed checks supplied. Use Check readiness to obtain a fresh result.';
  const text = `Incoming initiation only · five minutes including startup. ${e.status?.unsupported_outgoing || 'Outgoing support not reported; unavailable.'}\nReadiness: ${e.status?.readiness.state || 'unknown'} · Cleanup: ${e.status?.cleanup || 'unknown'}\n\n${checks}`;
  if ($('evaluationCheckText').textContent !== text) $('evaluationCheckText').textContent = text;
  details.hidden = false;
  ($('evalProfile') as HTMLSelectElement).value = 'incoming';
  ($('evalProfile') as HTMLSelectElement).disabled = true;
  $('evalProfile').title =
    'Only incoming evaluation is supported by daemon-evaluation-v1. Outgoing traffic is not covered.';
  ($('evalStart') as HTMLButtonElement).disabled = !e.canStart;
  ($('evalStop') as HTMLButtonElement).disabled = !e.canStop;
  ($('evalStatus') as HTMLButtonElement).disabled = !e.canCheck;
  $('evalStatus').textContent = 'Check readiness';
  $('evalStart').textContent = 'Start incoming · 5 minutes…';
  $('evalStop').textContent = 'Stop firewall evaluation';
  $('evalCancel').hidden = true;
  $('evalRecover').hidden = true;
  const summary = document.querySelector('#controlMenu > summary')!;
  const secs = Math.max(0, Math.ceil((e.remainingMs || 0) / 1000));
  summary.textContent =
    e.phase === 'active'
      ? `Firewall · ${secs ? `${Math.floor(secs / 60)}:${String(secs % 60).padStart(2, '0')}` : 'confirming expiry'}`
      : `Firewall · ${e.busy ? 'pending' : e.status?.readiness.state === 'checking' ? 'checking' : e.status?.readiness.state === 'blocked' && e.phase === 'stopped' ? 'blocked' : e.phase}`;
  (summary as HTMLElement).title = e.label || '';
}
