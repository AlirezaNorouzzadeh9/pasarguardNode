package singbox

import (
	"fmt"

	"github.com/sagernet/sing-box/option"

	"github.com/pasarguard/node/common"
)

// applyUsers returns a copy of an inbound's options carrying exactly the given
// users.
//
// sing-box has no runtime user API for any protocol we care about (only
// shadowsocks-2022 does), so changing a user means rebuilding the inbound. The
// user list is typed per protocol, hence the switch: each case pulls the
// credential the protocol actually authenticates on, and skips users that do
// not carry one, so a vless-only user does not end up as a broken hysteria
// entry.
func applyUsers(in option.Inbound, users []*common.User) (option.Inbound, error) {
	out := in

	switch opts := in.Options.(type) {
	case *option.Hysteria2InboundOptions:
		clone := *opts
		clone.Users = nil
		for _, u := range users {
			// Hysteria in this fork's proto carries a single `auth` secret.
			if auth := u.GetProxies().GetHysteria().GetAuth(); auth != "" {
				clone.Users = append(clone.Users, option.Hysteria2User{
					Name:     u.GetEmail(),
					Password: auth,
				})
			}
		}
		out.Options = &clone

	case *option.TrojanInboundOptions:
		clone := *opts
		clone.Users = nil
		for _, u := range users {
			if pw := u.GetProxies().GetTrojan().GetPassword(); pw != "" {
				clone.Users = append(clone.Users, option.TrojanUser{
					Name:     u.GetEmail(),
					Password: pw,
				})
			}
		}
		out.Options = &clone

	case *option.VLESSInboundOptions:
		clone := *opts
		clone.Users = nil
		for _, u := range users {
			if id := u.GetProxies().GetVless().GetId(); id != "" {
				clone.Users = append(clone.Users, option.VLESSUser{
					Name: u.GetEmail(),
					UUID: id,
				})
			}
		}
		out.Options = &clone

	case *option.VMessInboundOptions:
		clone := *opts
		clone.Users = nil
		for _, u := range users {
			if id := u.GetProxies().GetVmess().GetId(); id != "" {
				clone.Users = append(clone.Users, option.VMessUser{
					Name: u.GetEmail(),
					UUID: id,
				})
			}
		}
		out.Options = &clone

	case *option.ShadowsocksInboundOptions:
		clone := *opts
		clone.Users = nil
		for _, u := range users {
			if pw := u.GetProxies().GetShadowsocks().GetPassword(); pw != "" {
				clone.Users = append(clone.Users, option.ShadowsocksUser{
					Name:     u.GetEmail(),
					Password: pw,
				})
			}
		}
		out.Options = &clone

	default:
		// Inbounds without users (direct, tun, mixed…) are left exactly as
		// configured rather than treated as an error: a config may legitimately
		// mix them with user-bearing ones.
		return out, nil
	}

	return out, nil
}

// carriesUsers reports whether an inbound type authenticates users at all, so
// the sync path can skip rebuilding the ones that do not.
func carriesUsers(in option.Inbound) bool {
	switch in.Options.(type) {
	case *option.Hysteria2InboundOptions,
		*option.TrojanInboundOptions,
		*option.VLESSInboundOptions,
		*option.VMessInboundOptions,
		*option.ShadowsocksInboundOptions:
		return true
	default:
		return false
	}
}

// userCount reports how many of the given users the inbound would accept, used
// for logging so an operator can see a sync actually landed.
func userCount(in option.Inbound, users []*common.User) (int, error) {
	applied, err := applyUsers(in, users)
	if err != nil {
		return 0, err
	}
	switch opts := applied.Options.(type) {
	case *option.Hysteria2InboundOptions:
		return len(opts.Users), nil
	case *option.TrojanInboundOptions:
		return len(opts.Users), nil
	case *option.VLESSInboundOptions:
		return len(opts.Users), nil
	case *option.VMessInboundOptions:
		return len(opts.Users), nil
	case *option.ShadowsocksInboundOptions:
		return len(opts.Users), nil
	default:
		return 0, fmt.Errorf("inbound %q carries no users", applied.Tag)
	}
}
