package identity

import "testing"

func TestServiceDisplayPreservesExecutableAuthority(t *testing.T) {
	for _, unit := range []string{"synthetic-alpha", "synthetic-beta@instance"} {
		a := Application{Kind: "native", Name: "runtime", DisplayName: "runtime", Executable: "/synthetic/runtime", Revision: "revision", Key: "key"}
		before := a
		applyServiceDisplay(&a, "0::/user.slice/user-1000.slice/user@1000.service/app.slice/"+unit+".service")
		if a.DisplayName != unit+" (runtime)" {
			t.Fatal(a.DisplayName)
		}
		a.DisplayName = before.DisplayName
		if a.Key != before.Key || a.Revision != before.Revision || a.Name != before.Name || a.Executable != before.Executable || ApplicationKey(1000, a) != ApplicationKey(1000, before) {
			t.Fatal("service label changed permission identity")
		}
	}
}

func TestServiceDisplayRefusesUnrelatedOrAmbiguousCgroups(t *testing.T) {
	for _, c := range []string{"0::/user.slice/user@1000.service/app.slice/app-example.scope", "2:cpu:/alpha.service", "0::/alpha.service/../beta.service", "0::/alpha.service\n1:name=systemd:/beta.service", "0::/bad\tname.service", "0::/"} {
		a := Application{Kind: "native", DisplayName: "runtime"}
		applyServiceDisplay(&a, c)
		if a.DisplayName != "runtime" {
			t.Fatalf("accepted %q: %s", c, a.DisplayName)
		}
	}
	for _, kind := range []string{"wine", "wine-unresolved", "electron"} {
		a := Application{Kind: kind, DisplayName: "application"}
		applyServiceDisplay(&a, "0::/launcher.service")
		if a.DisplayName != "application" {
			t.Fatal("runtime identity relabelled")
		}
	}
}
