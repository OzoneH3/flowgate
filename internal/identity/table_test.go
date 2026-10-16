package identity

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestTableRows(t *testing.T) {
	f, _ := ParseFlow("tcp", "incoming", "127.0.0.1:1234", "127.0.0.1:50000")
	a := WindowsOwner{PID: 12, Created: 1, Image: "Z:\\alpha.exe", Address: "127.0.0.1", Port: 1234, State: 2}
	b := a
	b.PID = 16
	b.Image = "Z:\\beta.exe"
	rows, err := selectTableRows(tableSnapshot{Rows: []WindowsOwner{a, a, b}}, f)
	if err != nil || len(rows) != 2 {
		t.Fatalf("shared holders lost: %+v %v", rows, err)
	}
	a.Created = 0
	if _, err = selectTableRows(tableSnapshot{Rows: []WindowsOwner{a}}, f); err == nil {
		t.Fatal("accepted missing generation")
	}
}
func TestTableObserverLoss(t *testing.T) {
	w := &WineTable{dead: true}
	start := time.Now()
	if _, err := w.snapshot("tcp"); err == nil {
		t.Fatal("stopped observer accepted")
	}
	if time.Since(start) > time.Second {
		t.Fatal("stopped observer blocked")
	}
	if _, err := NewWineTable("", "", "", "", "unknown"); err == nil {
		t.Fatal("unrecognized runtime accepted")
	}
}

func TestTableRejectsBrokenResponses(t *testing.T) {
	for _, response := range []string{`not-json`, `{"version":"11.19","complete":false}`, `{"version":"unexpected","complete":true}`, `{"version":"11.19","complete":true,"error":2}`} {
		t.Run(response, func(t *testing.T) {
			dir := t.TempDir()
			helper := filepath.Join(dir, "helper.sh")
			if err := os.WriteFile(helper, []byte("while read line; do printf '%s\\n' '"+response+"'; done\n"), 0600); err != nil {
				t.Fatal(err)
			}
			w, err := NewWineTable("/bin/sh", helper, "/bin/sh", dir, "11.19")
			if err != nil {
				t.Fatal(err)
			}
			defer w.Close()
			if _, err = w.snapshot("tcp"); err == nil {
				t.Fatal("bad snapshot accepted")
			}
			if _, err = w.snapshot("tcp"); err == nil {
				t.Fatal("failed observer revived")
			}
		})
	}
}
