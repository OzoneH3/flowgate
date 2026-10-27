# Generate a private diagnostic controller copy; never use for acceptance.
import pathlib,sys
source=pathlib.Path(sys.argv[1]);destination=pathlib.Path(sys.argv[2])
assert source.resolve()!=destination.resolve()
s=source.read_text()
wrapper='\n# Private diagnostic only, never installed or used for acceptance.\n_trace_events = 0\n_trace_file = None\ndef _traced(name, function):\n    def wrapped(self, *args, **kwargs):\n        global _trace_events, _trace_file\n        start = time.monotonic_ns(); cpu = time.process_time_ns()\n        try:\n            return function(self, *args, **kwargs)\n        finally:\n            end = time.monotonic_ns(); own = time.process_time_ns() - cpu\n            if _trace_events < 20000:\n                if _trace_file is None:\n                    _trace_file = open(\'/work/.workspace/m1/controller-trace.txt\', \'w\')\n                _trace_file.write(json.dumps({\'stage\':name,\'op\':str(args[0]) if name==\'k\' and args else \'\', \'begin_ns\':start,\'end_ns\':end,\'self_cpu_ns\':own})+\'\\n\');_trace_file.flush();_trace_events += 1\n                if _trace_events == 20000:_trace_file.write(\'{"truncated":true}\\n\');_trace_file.flush()\n    return wrapped\nfor _name in (\'tick\',\'verify\',\'exists\',\'k\'):\n    setattr(Controller, _name, _traced(_name, getattr(Controller, _name)))\n\n'
needle="if __name__ == '__main__':"
assert s.count(needle)==1
destination.write_text(s.replace(needle,wrapper+needle))
