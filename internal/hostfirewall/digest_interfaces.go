package hostfirewall

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net"
	"strconv"
	"strings"
)

var errAuditInconclusive = errors.New("firewall audit interface snapshot inconclusive")

func interfaceIndices() (map[string]uint32, error) {
	links, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	out := make(map[string]uint32, len(links))
	for _, link := range links {
		out[link.Name] = uint32(link.Index)
	}
	return out, nil
}

// nft 1.1.7 ignores -n for iface_index rendering. Only canonicalize the
// meta-oif scalar in tagged rules of our exact socket_output chain. Everything
// else (including oifname and the tag itself) stays part of the normal digest.
func canonicalInterfaceMatches(raw []byte, before, after map[string]uint32) ([]byte, error) {
	if !maps.Equal(before, after) {
		return nil, errAuditInconclusive
	}
	var document map[string]any
	if err := json.Unmarshal(raw, &document); err != nil {
		return nil, err
	}
	rows, _ := document["nftables"].([]any)
	for _, row := range rows {
		item, _ := row.(map[string]any)
		rule, _ := item["rule"].(map[string]any)
		if rule["family"] != "inet" || rule["table"] != Table || rule["chain"] != "socket_output" {
			continue
		}
		comment, _ := rule["comment"].(string)
		tag := strings.TrimPrefix(comment, "flowgate-socket:")
		if tag == comment || len(tag) != 32 {
			continue
		}
		if _, err := hex.DecodeString(tag); err != nil {
			continue
		}
		expressions, _ := rule["expr"].([]any)
		for _, expression := range expressions {
			expr, _ := expression.(map[string]any)
			match, _ := expr["match"].(map[string]any)
			left, _ := match["left"].(map[string]any)
			meta, _ := left["meta"].(map[string]any)
			if meta["key"] != "oif" {
				continue
			}
			switch right := match["right"].(type) {
			case string:
				number, numberErr := strconv.ParseUint(right, 10, 32)
				index := before[right]
				if index != 0 {
					if numberErr == nil {
						return nil, fmt.Errorf("%w: numeric-looking interface name", errAuditInconclusive)
					}
					match["right"] = index
				} else if numberErr == nil && number != 0 {
					match["right"] = uint32(number)
				} else {
					return nil, fmt.Errorf("%w: unresolved interface", errAuditInconclusive)
				}
			case float64:
				if right < 1 || right > 4294967295 || right != float64(uint32(right)) {
					return nil, fmt.Errorf("invalid output interface index")
				}
			default:
				return nil, fmt.Errorf("unsupported output interface match shape")
			}
		}
	}
	return json.Marshal(document)
}
