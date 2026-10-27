package uploadshape

import "testing"

func TestDeploymentModeRequiresExplicitStartupOptIn(t *testing.T) {
	for _, tc := range []struct {
		o    Options
		want bool
	}{
		{Options{}, false},
		{Options{Interface: "eth0"}, false},
		{Options{Interface: "eth0", ParentNetNS: "net:[1]"}, false},
		{Options{Interface: "eth0", ParentNetNS: "net:[2]"}, true},
		{Options{Interface: "eth0", HostTrial: true}, true},
		{Options{Interface: "eth0", HostTrial: true, ParentNetNS: "net:[2]"}, false},
		{Options{HostTrial: true}, false},
	} {
		if got := validateDeploymentMode(tc.o, "net:[1]") == nil; got != tc.want {
			t.Fatalf("options %+v allowed=%v", tc.o, got)
		}
	}
}
