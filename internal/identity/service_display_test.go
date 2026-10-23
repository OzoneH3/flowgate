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

func TestServiceDisplayExcludesDesktopLaunchers(t *testing.T) {
	for _, unit := range []string{"app-synthetic@0123456789", "app-terminal@autostart", "dbus-:1.1-org.example.Service@0", "synthetic@autostart", "user@1000", `app\x2dsynthetic@123`, `bad\x0aname`, `bad\xff`, `bad\xZZ`, `bad\x2fname`} {
		for _, executable := range []string{"synthetic-game", "synthetic-command"} {
			a := Application{Kind: "native", DisplayName: executable}
			applyServiceDisplay(&a, "0::/user.slice/app.slice/"+unit+".service")
			if a.DisplayName != executable {
				t.Fatalf("launcher %q renamed child: %s", unit, a.DisplayName)
			}
		}
	}
}

func TestServiceDisplayDecodesEscapedName(t *testing.T) {
	a := Application{Kind: "native", DisplayName: "runtime"}
	applyServiceDisplay(&a, `0::/user.slice/app.slice/synthetic\x2dworker.service`)
	if a.DisplayName != "synthetic-worker (runtime)" {
		t.Fatal(a.DisplayName)
	}
}
