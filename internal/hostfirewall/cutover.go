package hostfirewall

import (
	"context"
	"flowgate/internal/policy"
	"fmt"
	ct "github.com/ti-mo/conntrack"
	"time"
)

// While state is starting, preserve traffic that can race the initial dump.
// The continuous priority9 guard remains authoritative. The same owned table
// token and cleanup path cover this temporary table and the final profile.
func preservationRules(token string) string {
	return fmt.Sprintf(`add table inet %s { comment "flowgate:%s"; }
add chain inet %s input { type filter hook input priority 10; policy accept; }
add chain inet %s output { type filter hook output priority 10; policy accept; }
add rule inet %s input meta l4proto { tcp, udp } ct mark set ct mark | 0x20000000 accept
add rule inet %s output meta l4proto { tcp, udp } ct mark set ct mark | 0x20000000 accept
`, Table, token, Table, Table, Table, Table)
}

func preserveConfirmed(ctx context.Context, fs []ct.Flow, mark func(ct.Flow, uint32) error) error {
	// The temporary hooks can create only the preserved bit. Any other use of
	// our mask is a collision; refuse before changing any snapshot entry.
	for _, f := range fs {
		if f.Mark&mask != 0 && f.Mark&mask != preserved {
			return fmt.Errorf("reserved conntrack bits changed during cutover")
		}
	}
	for _, f := range fs {
		if err := ctx.Err(); err != nil {
			return err
		}
		p := f.TupleOrig.Proto.Protocol
		if (p == 6 || p == 17) && f.Status.Confirmed() {
			if err := mark(f, preserved); err != nil {
				return err
			}
		}
	}
	return ctx.Err()
}

// Initial validation/claim must precede mutations. Packets after the second dump
// are marked by the temporary rules. Atomic replacement defines the cutoff;
// there is no permanent accept rule for new UDP or TCP admissions.
func cutoverProfileWith(ctx context.Context, initial, stage, preserve, finish func() error) error {
	for _, step := range []func() error{initial, stage, preserve, finish} {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := step(); err != nil {
			return err
		}
	}
	return ctx.Err()
}

// Verify the still-owned, structurally unchanged temporary table before
// replacing it. As with cleanup ownership checks, this is not a kernel CAS:
// concurrent privileged mutation after the reads is outside this proof. A known
// foreign token refuses; a same-token structural change refuses activation and
// remains subject to the ordinary owned-table rollback cleanup.
func finishCutover(ctx context.Context, token, profile, expectedDigest string, bootstrap ...policy.BootstrapInterface) error {
	present, err := owns(Record{Token: token})
	if err != nil {
		return err
	}
	if !present {
		return fmt.Errorf("temporary cutover table disappeared")
	}
	actual, err := tableDigest()
	if err != nil {
		return err
	}
	if actual != expectedDigest {
		return fmt.Errorf("temporary cutover table changed")
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	return batch("delete table inet " + Table + "\n" + profileRules(token, profile, bootstrap...))
}
func activateProfile(ctx context.Context, token, profile string, claim func() error, bootstrap ...policy.BootstrapInterface) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	var expectedDigest string
	return cutoverProfileWith(ctx,
		func() error { return bootstrapContext(ctx, claim) },
		func() error {
			if err := batch(preservationRules(token)); err != nil {
				return err
			}
			var err error
			expectedDigest, err = tableDigest()
			return err
		},
		func() error {
			fs, err := flows()
			if err != nil {
				return err
			}
			return preserveConfirmed(ctx, fs, setMark)
		},
		func() error {
			return finishCutover(ctx, token, profile, expectedDigest, bootstrap...)
		},
	)
}
