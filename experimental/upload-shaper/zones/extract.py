import pathlib,json,base64,sys
root=pathlib.Path(__file__).resolve().parents[3]/'.workspace/zone-receiver'
name=sys.argv[1] if len(sys.argv)>1 else 'run1'
d=root/(name+'-artifacts');d.mkdir(exist_ok=True)
inside=False
for line in (root/(name+'.log')).read_text(errors='replace').splitlines():
 if line=='M1_EXPORT_BEGIN':inside=True;continue
 if line=='M1_EXPORT_END':inside=False;continue
 if inside:
  try:
   row=json.loads(line);p=d/row['name'];assert p.parent==d;p.write_bytes(base64.b64decode(row['b64']))
  except (ValueError,KeyError):pass
for p in d.glob('results.json'):print(p.read_text())
for p in d.glob('failure.txt'):print(p.read_text())
