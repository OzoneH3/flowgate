import type { Row } from './model';
import { ruleCoversRevision, type Rule, type RuleFilter } from './protocol';
import type { NetworkZones } from './network-zones';
export interface ApplicationZone {
  zone: 'local' | 'internet';
  model: string;
  parentLabel: string;
}
export const matchesApplicationZone = (scope: RuleFilter, zone: ApplicationZone) =>
  scope.network_zone === zone.zone && (scope.zone_model || 'configured-prefix-v1') === zone.model;
// Display filters, not new policy identities. No zone traffic totals are derived
// from socket lifetime counters; those need a backend attribution baseline.
export function addApplicationZones(roots: Row[], rules: Rule[], definition?: NetworkZones): Row[] {
  const walk = (row: Row, parent?: Row) => {
    for (const child of row.children) walk(child, row);
    if (
      !definition ||
      row.applicationZone ||
      row.displayApplication ||
      !(row.kind === 'application' || (row.kind === 'process' && parent?.kind === 'launch'))
    )
      return;
    const p = row.process,
      identity =
        row.inactive ||
        (row.runtimeApplication && {...row.runtimeApplication.application,uid:row.runtimeApplication.uid}) ||
        (p && { key: p.application.key, revision: p.application.revision, uid: p.uid });
    if (!identity?.key || !identity.revision) return;
    const own = rules.filter(
      (r) =>
        !r.filter.process &&
        ruleCoversRevision(r, identity.revision) &&
        ((r.filter.application === identity.key && r.filter.uid === identity.uid) ||
          (identity.uid === 0 && r.root_application === identity.key)),
    );
    const models = [
      definition.model,
      ...new Set(
        own
          .filter((r) => r.filter.network_zone)
          .map((r) => r.filter.zone_model || 'configured-prefix-v1'),
      ),
    ].filter((m, i, a) => a.indexOf(m) === i);
    const children: Row[] = [];
    for (const model of models)
      for (const zone of ['local', 'internet'] as const) {
        if (
          model !== definition.model &&
          !own.some((r) =>
            matchesApplicationZone(r.filter, { zone, model, parentLabel: row.label }),
          )
        )
          continue;
        const scope = { zone, model, parentLabel: row.label },
          suffix = model !== definition.model ? ' · legacy prefixes' : '';
        children.push({
          id: `${row.id}:zone:${model}:${zone}`,
          parent: row.id,
          kind: 'application',
          label: `${row.label}, ${zone === 'local' ? 'Local Network' : 'Internet'}${suffix}`,
          rows: [],
          children: [],
          runtimeApplication:row.runtimeApplication,
          process: p,
          inactive: row.inactive,
          applicationZone: scope,
          policyRows: row.rows,
        });
      }
    row.children = [...children, ...row.children];
  };
  for (const row of roots) walk(row);
  return roots;
}
