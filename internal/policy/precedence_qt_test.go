package policy

import (
	"os"
	"strings"
	"testing"
)

// The Qt rule editor cannot import Go; keep its precedence text identical.
func TestQtRuleEditorStatesEvaluatorPrecedence(t *testing.T) {
	b, err := os.ReadFile("../../desktop/ruleeditor.cpp")
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	if !strings.Contains(src, `"`+PrecedenceSentence+`"`) {
		t.Fatal("desktop/ruleeditor.cpp precedence text differs from policy.PrecedenceSentence")
	}
	if strings.Contains(src, "smallest rule ID") {
		t.Fatal("stale smallest-ID-only precedence text remains in the Qt editor")
	}
}
