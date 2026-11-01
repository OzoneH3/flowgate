# Production-session receiver extensions, separate from finite core denominator.
# All network paths are internal to a disconnected TCG guest.
mode=os.environ['ACCEPTANCE_MODE']
def gate():return api().get('socket_authorization') or {}
def fast():return gate().get('fast_packets',0)
def stopchild(p):
 if p.poll() is None:p.terminate();p.wait(10)

exec(compile((P/'scope.py').read_text(),str(P/'scope.py'),'exec'),globals())
exec(compile((P/'priority.py').read_text(),str(P/'priority.py'),'exec'),globals())
exec(compile((P/'udp_loss.py').read_text(),str(P/'udp_loss.py'),'exec'),globals())
exec(compile((P/'coverage_escape.py').read_text(),str(P/'coverage_escape.py'),'exec'),globals())
exec(compile((P/'policy_receiver.py').read_text(),str(P/'policy_receiver.py'),'exec'),globals())
exec(compile((P/'validation.py').read_text(),str(P/'validation.py'),'exec'),globals())
