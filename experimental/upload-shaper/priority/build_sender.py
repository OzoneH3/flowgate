"""Build only the bounded guest sender; never launch it on the host.
Usage: python3 build_sender.py <output inside project .workspace>
Reuses the settled sender protocol, allowing up to2048 sockets for the idle
candidate-heavy population. Bulk still transmits on fd0 only.
"""
import pathlib, subprocess, sys
root=pathlib.Path(__file__).resolve().parents[3]
out=pathlib.Path(sys.argv[1]).resolve()
assert out.is_relative_to(root/'.workspace'), 'fixture output must be in .workspace'
s=(root/'experimental/upload-shaper/tests/sender.c').read_text()
assert s.count('fds[8]')==1 and s.count('i < count && i < 8')==1
s=s.replace('fds[8]','fds[2048]').replace('i < count && i < 8','i < count && i < 2048')
source=out.with_suffix('.c');source.write_text(s)
subprocess.run(['cc','-O2','-Wall','-Wextra','-o',str(out),str(source)],check=True)
