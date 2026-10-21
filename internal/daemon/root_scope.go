package daemon

import (
	"flowgate/internal/identity"
	"flowgate/internal/policy"
)

// The configured administrator's saved native application rules also cover
// root execution of that exact executable revision. No ancestry grants access.
func (e *Engine) rootScope(r policy.Rule) policy.Rule {
	r.RootApplication = ""
	if e.AdministratorUID == nil || *e.AdministratorUID == 0 || r.Filter.UID != *e.AdministratorUID || !r.CanShareRoot() {
		return r
	}
	r.RootApplication = identity.ApplicationKey(0, identity.Application{Kind: "native", Executable: r.Executable})
	return r
}
