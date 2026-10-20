package daemon

import (
	"flowgate/internal/identity"
	"testing"
)

func TestRuntimeActivityRuleBindsWindowsImageNotBroker(t *testing.T) {
	a, s, live, _ := observedAPI(t)
	app := identity.Application{Kind: "wine", Key: "windows-app", Revision: "pe-revision", Executable: "/prefix/game.exe", Prefix: "/prefix"}
	broker := *live
	table := identity.TableEvidence{BrokerPID: broker.PID, BrokerStart: broker.Start, UID: broker.UID, Prefix: app.Prefix}
	s.Rows[0].Socket.Cookie = "original-cookie"
	s.Rows[0].RuntimeApplication = &identity.RuntimeApplication{Application: app, UID: broker.UID, Evidence: table}
	attribution := identity.Attribution{Status: "corroborated-runtime-table", Application: &app, Table: &table, Owners: []identity.Process{broker}, Sockets: []identity.Socket{s.Rows[0].Socket}, VisibilityComplete: true}
	a.e.Resolve = func(identity.Flow) identity.Attribution { return attribution }
	d := observedDraft("outgoing")
	preview := requirePreview(t, a, d)
	if preview.Rule.Filter.Application != app.Key || !preview.Rule.Filter.Process.IsZero() {
		t.Fatal(preview)
	}
	saved := callResponse(a.path, saveRequest(a, preview, d))
	if saved.Error != "" || saved.SavedRule == nil || saved.SavedRule.Filter.Application != app.Key {
		t.Fatal(saved)
	}
	view, err := a.e.PolicyView(a.e.Generation, "", broker.UID, false, nil)
	if err != nil || len(view.Applications) != 1 || view.Applications[0].Identity.Key != app.Key || view.Rows[0].Status != "observed_runtime" {
		t.Fatal(view, err)
	}
	d.TargetScope = "process"
	if r := callResponse(a.path, previewRequest(a, d)); r.ErrorCode != "unsupported_process" {
		t.Fatal(r)
	}
	d.TargetScope = "application"
	d.RemoteAddress = "127.0.0.3"
	for _, change := range []string{"cookie", "generation", "image", "prefix", "gone"} {
		t.Run(change, func(t *testing.T) {
			attribution = identity.Attribution{Status: "corroborated-runtime-table", Application: &app, Table: &table, Owners: []identity.Process{broker}, Sockets: []identity.Socket{s.Rows[0].Socket}, VisibilityComplete: true}
			p := requirePreview(t, a, d)
			switch change {
			case "cookie":
				attribution.Sockets[0].Cookie = "reused"
			case "generation":
				attribution.Owners[0].Start = "new"
			case "image", "prefix":
				other := app
				other.Key = "different-identity"
				attribution.Application = &other
			case "gone":
				attribution.Application = nil
			}
			if r := callResponse(a.path, saveRequest(a, p, d)); r.ErrorCode != "stale_target" {
				t.Fatal(r)
			}
		})
	}
}
