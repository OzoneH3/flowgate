# Direct user approval: bounded host timing diagnostic, 2026-10-30.
import hashlib,os,runpy
from pathlib import Path
expected={'/home/flowgate-user/Apps/flowgate/.workspace/socket-auth-prototype/experiments/socket-auth/host-census-check.py': 'da937374d08976eb47a2783adfc47f651e8f60a9ce86e1f5a94be6100a08069b', '/home/flowgate-user/Apps/flowgate/.workspace/socket-auth-prototype/experiments/socket-auth/census-cost/main.go': '06e6d4a378cb8298d3f66362187e759a4acd31b2a78d71162667039d55713ab2', '/home/flowgate-user/Apps/flowgate/.workspace/socket-auth-prototype/.workspace/socket-auth/census-cost': 'cc767166fe51ad5995f7b7d88cf7875cfd2ff3dbc53a8decf839cc8fe2a7df4d'}
for name,digest in expected.items():
 assert hashlib.sha256(Path(name).read_bytes()).hexdigest()==digest,name
os.environ["FLOWGATE_HOST_CENSUS_APPROVED"]="1"
runpy.run_path('/home/flowgate-user/Apps/flowgate/.workspace/socket-auth-prototype/experiments/socket-auth/host-census-check.py',run_name="__main__")
