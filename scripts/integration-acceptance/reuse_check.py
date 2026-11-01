#!/usr/bin/env python3
"""Record code equivalence for a narrowly declared reused-evidence claim.
Zero diff is necessary evidence, not proof that an arbitrary test covers a claim.
Read-only git operations; no checkout/build/host interaction.
"""
import argparse, hashlib, json, pathlib, subprocess
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--repo', type=pathlib.Path, required=True)
p.add_argument('--old', required=True);p.add_argument('--new', required=True)
p.add_argument('--evidence', type=pathlib.Path, required=True)
p.add_argument('--output', type=pathlib.Path, required=True)
p.add_argument('paths', nargs='+');a=p.parse_args()
assert '.workspace' in a.output.resolve().parts
assert not a.output.exists(), 'preserve prior assessment'
def git(*args):return subprocess.check_output(['git','-C',str(a.repo),*args])
old=git('rev-parse',a.old).decode().strip();new=git('rev-parse',a.new).decode().strip()
diff=git('diff','--name-status',old,new,'--',*a.paths).decode()
result={'old':old,'new':new,'declared_paths':a.paths,'changed':diff.splitlines(),
        'code_equivalent_for_declared_paths':not bool(diff),
        'evidence':str(a.evidence.resolve()),
        'evidence_sha256':hashlib.sha256(a.evidence.read_bytes()).hexdigest(),
        'limitation':'Source equivalence only; intended claim and environment must still be reviewed. Does not create receiver coverage.'}
a.output.write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result))
