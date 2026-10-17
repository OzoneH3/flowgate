#!/usr/bin/env python3
"""Explicit collection-only terminal action; never calls host-start or nft."""
import os,subprocess,sys
from pathlib import Path
root=Path(__file__).resolve().parents[1]
print('FlowGate extended UDP traffic monitoring (experimental, collection only). No firewall activation.\nStop in Activity or press Ctrl+C here. TCP monitoring is independent.',flush=True)
# sudo is the system authentication owner; no Qt password handling or shell input.
args=['sudo',str(root/'.workspace/flowgate'),'udp-start','--uid',str(os.getuid())]
try:sys.exit(subprocess.call(args))
except KeyboardInterrupt:pass
