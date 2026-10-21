package daemon

import "flowgate/internal/identity"

// ruleInvocation retains observed script context for display after exit. It is
// never used to match permissions: readable script arguments are not execution
// authority, and the rule still targets the interpreter executable.
func ruleInvocation(app identity.Application, p *identity.Provenance) *identity.Invocation {
	if app.Kind != "native" || p == nil || p.Invocation == nil {
		return nil
	}
	i := p.Invocation
	if i.Mode != "file" || i.Name == "" || i.Path == "" || i.Revision == "" {
		return nil
	}
	return &identity.Invocation{Mode: "file", Name: i.Name, Path: i.Path, Revision: i.Revision}
}
func attributionInvocation(a identity.Attribution) *identity.Invocation {
	if a.Application == nil || a.Principal() == nil || len(a.Owners) != 1 {
		return nil
	}
	return ruleInvocation(*a.Application, a.Owners[0].Provenance)
}
