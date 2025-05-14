package config

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"net/url"
	"runtime"
	"strings"
	"time"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/json/badoption"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	dns "github.com/sagernet/sing-dns"
)

const (
	DNSRemoteTag       = "dns-remote"
	DNSLocalTag        = "dns-local"
	DNSDirectTag       = "dns-direct"
	DNSBlockTag        = "dns-block"
	DNSFakeTag         = "dns-fake"
	DNSTricksDirectTag = "dns-trick-direct"

	OutboundDirectTag         = "direct"
	OutboundBypassTag         = "bypass"
	OutboundBlockTag          = "block"
	OutboundSelectTag         = "select"
	OutboundURLTestTag        = "auto"
	OutboundDNSTag            = "dns-out"
	OutboundDirectFragmentTag = "direct-fragment"

	InboundTUNTag   = "tun-in"
	InboundMixedTag = "mixed-in"
	InboundDNSTag   = "dns-in"
)

var OutboundMainProxyTag = OutboundSelectTag

func BuildConfigJson(configOpt HiddifyOptions, input option.Options) (string, error) {
	options, err := BuildConfig(configOpt, input)
	if err != nil {
		return "", err
	}
	var buffer bytes.Buffer
	json.NewEncoder(&buffer)
	encoder := json.NewEncoder(&buffer)
	encoder.SetIndent("", "  ")
	err = encoder.Encode(options)
	if err != nil {
		return "", err
	}
	return buffer.String(), nil
}

// TODO include selectors
func BuildConfig(opt HiddifyOptions, input option.Options) (*option.Options, error) {
	fmt.Printf("config options: %++v\n", opt)

	var options option.Options
	if opt.EnableFullConfig {
		options.Inbounds = input.Inbounds
		options.DNS = input.DNS
		options.Route = input.Route
	}

	setClashAPI(&options, &opt)
	setLog(&options, &opt)
	setInbound(&options, &opt)
	setDns(&options, &opt)
	setRoutingOptions(&options, &opt)
	setFakeDns(&options, &opt)
	err := setOutbounds(&options, &input, &opt)
	if err != nil {
		return nil, err
	}

	return &options, nil
}

func addForceDirect(options *option.Options, opt *HiddifyOptions, directDNSDomains map[string]bool) {
	remoteDNSAddress := opt.RemoteDnsAddress
	if strings.Contains(remoteDNSAddress, "://") {
		remoteDNSAddress = strings.SplitAfter(remoteDNSAddress, "://")[1]
	}
	parsedUrl, err := url.Parse(fmt.Sprintf("https://%s", remoteDNSAddress))
	if err == nil && net.ParseIP(parsedUrl.Host) == nil {
		directDNSDomains[parsedUrl.Host] = true
	}
	if len(directDNSDomains) > 0 {
		directDNSDomainskeys := make([]string, 0, len(directDNSDomains))
		for key := range directDNSDomains {
			directDNSDomainskeys = append(directDNSDomainskeys, key)
		}

		domains := strings.Join(directDNSDomainskeys, ",")
		directRule := Rule{Domains: domains, Outbound: OutboundBypassTag}
		dnsRule := directRule.MakeDNSRule()
		var dnsAction option.DNSRuleAction
		dnsAction.Action = C.RuleActionTypeRoute
		dnsAction.RouteOptions.Server = DNSDirectTag
		dnsRule.DNSRuleAction = dnsAction

		// 添加到 DNS 规则列表
		options.DNS.Rules = append([]option.DNSRule{{
			Type:           C.RuleTypeDefault,
			DefaultOptions: dnsRule,
		}}, options.DNS.Rules...)
	}
}

func setOutbounds(options *option.Options, input *option.Options, opt *HiddifyOptions) error {
	directDNSDomains := make(map[string]bool)
	var outbounds []option.Outbound
	var tags []string
	if opt.Warp.EnableWarp && (opt.Warp.Mode == "warp_over_proxy" || opt.Warp.Mode == "proxy_over_warp") {
		out, err := GenerateWarpSingbox(opt.Warp.WireguardConfig, opt.Warp.CleanIP, opt.Warp.CleanPort, opt.Warp.FakePackets, opt.Warp.FakePacketSize, opt.Warp.FakePacketDelay, opt.Warp.FakePacketMode)
		if err != nil {
			return fmt.Errorf("failed to generate warp config: %v", err)
		}
		out.Tag = "guichao Warp ✅"
		// 使用 JSON 转换的方式来设置 WireGuardOptions.Detour
		// 使用 json.Marshal 替代 MarshalJSON 方法
		jsonData, err := json.Marshal(out)
		if err == nil {
			var obj map[string]interface{}
			err = json.Unmarshal(jsonData, &obj)
			if err == nil {
				if wgOptions, ok := obj["wireguard_options"].(map[string]interface{}); ok {
					if opt.Warp.Mode == "warp_over_proxy" {
						wgOptions["detour"] = OutboundSelectTag
						OutboundMainProxyTag = out.Tag
					} else {
						wgOptions["detour"] = OutboundDirectTag
					}
					modifiedJson, err := json.Marshal(obj)
					if err == nil {
						// 使用 json.Unmarshal 替代 UnmarshalJSON 方法
						err = json.Unmarshal(modifiedJson, &out)
						if err != nil {
							fmt.Printf("Error unmarshaling modified outbound: %v\n", err)
						}
					} else {
						fmt.Printf("Error marshaling modified outbound: %v\n", err)
					}
				}
			} else {
				fmt.Printf("Error unmarshaling outbound: %v\n", err)
			}
		} else {
			fmt.Printf("Error marshaling outbound: %v\n", err)
		}
		patchWarp(out, opt, true, nil)
		outbounds = append(outbounds, *out)
	}
	for _, out := range input.Outbounds {
		outbound, serverDomain, err := patchOutbound(out, *opt, nil)
		if err != nil {
			return err
		}
		if serverDomain != "" {
			directDNSDomains[serverDomain] = true
		}
		out = *outbound

		switch out.Type {
		case C.TypeDirect, C.TypeBlock, C.TypeDNS, C.TypeSelector, C.TypeURLTest:
			continue
		default:
			if !strings.Contains(out.Tag, "§hide§") {
				tags = append(tags, out.Tag)
			}
			out = patchHiddifyWarpFromConfig(out, *opt)
			outbounds = append(outbounds, out)
		}
	}

	// 创建 URLTest 类型的 Outbound
	// 在新版本中，结构可能已经改变
	urlTestOptions := &option.URLTestOutboundOptions{
		Outbounds: tags,
		URL:       opt.ConnectionTestUrl,
		// 注意：这里的类型可能需要调整
		Interval:                  badoption.Duration(opt.URLTestInterval.Duration()),
		Tolerance:                 1,
		IdleTimeout:               badoption.Duration(opt.URLTestInterval.Duration() * 3),
		InterruptExistConnections: true,
	}

	urlTest := option.Outbound{
		Type:    C.TypeURLTest,
		Tag:     OutboundURLTestTag,
		Options: urlTestOptions,
	}
	defaultSelect := urlTest.Tag

	for _, tag := range tags {
		if strings.Contains(tag, "§default§") {
			defaultSelect = "§default§"
		}
	}
	// 创建 Selector 类型的 Outbound
	// 在新版本中，结构可能已经改变
	selectorOptions := &option.SelectorOutboundOptions{
		Outbounds:                 append([]string{urlTest.Tag}, tags...),
		Default:                   defaultSelect,
		InterruptExistConnections: true,
	}

	selector := option.Outbound{
		Type:    C.TypeSelector,
		Tag:     OutboundSelectTag,
		Options: selectorOptions,
	}

	outbounds = append([]option.Outbound{selector, urlTest}, outbounds...)

	options.Outbounds = append(
		outbounds,
		[]option.Outbound{
			{
				Tag:  OutboundDNSTag,
				Type: C.TypeDNS,
			},
			{
				Tag:  OutboundDirectTag,
				Type: C.TypeDirect,
			},
			{
				Tag:  OutboundDirectFragmentTag,
				Type: C.TypeDirect,
				Options: &option.DirectOutboundOptions{
					// 在新版本中，DialerOptions 和 TLSFragment 结构可能已经改变
					// 需要检查新版本中的类型定义
					DialerOptions: option.DialerOptions{
						TCPFastOpen: false,

						// 注意：这里的 TLSFragment 字段可能需要调整
					},
				},
			},
			{
				Tag:  OutboundBypassTag,
				Type: C.TypeDirect,
			},
			{
				Tag:  OutboundBlockTag,
				Type: C.TypeBlock,
			},
		}...,
	)

	addForceDirect(options, opt, directDNSDomains)
	return nil
}

func setClashAPI(options *option.Options, opt *HiddifyOptions) {
	if opt.EnableClashApi {
		if opt.ClashApiSecret == "" {
			opt.ClashApiSecret = generateRandomString(16)
		}
		options.Experimental = &option.ExperimentalOptions{
			ClashAPI: &option.ClashAPIOptions{
				ExternalController:               fmt.Sprintf("%s:%d", "127.0.0.1", opt.ClashApiPort),
				Secret:                           opt.ClashApiSecret,
				AccessControlAllowOrigin:         []string{"*"},
				AccessControlAllowPrivateNetwork: true,
			},

			CacheFile: &option.CacheFileOptions{
				Enabled: true,
				Path:    "clash.db",
			},
		}
	}
}

func setLog(options *option.Options, opt *HiddifyOptions) {
	options.Log = &option.LogOptions{
		Level:        opt.LogLevel,
		Output:       opt.LogFile,
		Disabled:     false,
		Timestamp:    true,
		DisableColor: true,
	}
}
func setInbound(options *option.Options, opt *HiddifyOptions) {
	var inboundDomainStrategy option.DomainStrategy
	if !opt.ResolveDestination {
		inboundDomainStrategy = option.DomainStrategy(dns.DomainStrategyAsIS)
	} else {
		inboundDomainStrategy = opt.IPv6Mode
	}
	if opt.EnableTunService {
		ActivateTunnelService(*opt)
	} else if opt.EnableTun {
		tunOptions := option.TunInboundOptions{
			Stack:       opt.TUNStack,
			MTU:         opt.MTU,
			AutoRoute:   true,
			StrictRoute: opt.StrictRoute,
			// EndpointIndependentNat is deprecated and removed in newer versions
			InboundOptions: option.InboundOptions{
				SniffEnabled:             true,
				SniffOverrideDestination: false,
				DomainStrategy:           inboundDomainStrategy,
			},
		}

		tunInbound := option.Inbound{
			Type:    C.TypeTun,
			Tag:     InboundTUNTag,
			Options: tunOptions,
		}

		// Use Address instead of Inet4Address/Inet6Address
		switch opt.IPv6Mode {
		case option.DomainStrategy(dns.DomainStrategyUseIPv4):
			tunOptions.Address = []netip.Prefix{
				netip.MustParsePrefix("172.19.0.1/28"),
			}
		case option.DomainStrategy(dns.DomainStrategyUseIPv6):
			tunOptions.Address = []netip.Prefix{
				netip.MustParsePrefix("fdfe:dcba:9876::1/126"),
			}
		default:
			tunOptions.Address = []netip.Prefix{
				netip.MustParsePrefix("172.19.0.1/28"),
				netip.MustParsePrefix("fdfe:dcba:9876::1/126"),
			}
		}

		// Consider adding AutoRedirect for Linux
		// if runtime.GOOS == "linux" {
		//     tunOptions.AutoRedirect = true
		// }

		tunInbound.Options = tunOptions
		options.Inbounds = append(options.Inbounds, tunInbound)
	}

	var bind string
	if opt.AllowConnectionFromLAN {
		bind = "0.0.0.0"
	} else {
		bind = "127.0.0.1"
	}

	mixedOptions := &option.HTTPMixedInboundOptions{
		ListenOptions: option.ListenOptions{
			Listen:     common.Ptr(badoption.Addr(netip.MustParseAddr(bind))),
			ListenPort: opt.MixedPort,
			InboundOptions: option.InboundOptions{
				SniffEnabled:             true,
				SniffOverrideDestination: true,
				DomainStrategy:           inboundDomainStrategy,
			},
		},
		SetSystemProxy: opt.SetSystemProxy,
	}

	options.Inbounds = append(
		options.Inbounds,
		option.Inbound{
			Type:    C.TypeMixed,
			Tag:     InboundMixedTag,
			Options: mixedOptions,
		},
	)

	addr := common.Ptr(badoption.Addr(netip.MustParseAddr(bind)))
	directOptions := &option.DirectInboundOptions{
		ListenOptions: option.ListenOptions{
			Listen:     addr,
			ListenPort: opt.LocalDnsPort,
		},
		// OverrideAddress: "1.1.1.1",
		// OverridePort:    53,
	}

	options.Inbounds = append(
		options.Inbounds,
		option.Inbound{
			Type:    C.TypeDirect,
			Tag:     InboundDNSTag,
			Options: directOptions,
		},
	)
}

func setDns(options *option.Options, opt *HiddifyOptions) {
	options.DNS = &option.DNSOptions{
		RawDNSOptions: option.RawDNSOptions{
			Final: DNSRemoteTag,
			DNSClientOptions: option.DNSClientOptions{
				IndependentCache: opt.IndependentDNSCache,
			},
			Servers: []option.DNSServerOptions{
				{
					Type: C.DNSTypeUDP,
					Tag:  DNSRemoteTag,
					Options: &option.RemoteDNSServerOptions{
						DNSServerAddressOptions: option.DNSServerAddressOptions{
							Server: opt.RemoteDnsAddress,
						},
					},
				},
				//{
				//	Type: C.DNSTypeHTTPS,
				//	Tag:  DNSTricksDirectTag,
				//	Options: &option.RemoteHTTPSDNSServerOptions{
				//		RemoteTLSDNSServerOptions: option.RemoteTLSDNSServerOptions{
				//			RemoteDNSServerOptions: option.RemoteDNSServerOptions{
				//				LocalDNSServerOptions: option.LocalDNSServerOptions{
				//					DialerOptions: option.DialerOptions{
				//						DomainResolver: &option.DomainResolveOptions{
				//							Server:   opt.RemoteDnsAddress,
				//							Strategy: opt.RemoteDnsDomainStrategy,
				//						},
				//						Detour: OutboundDirectTag,
				//					},
				//				},
				//				DNSServerAddressOptions: option.DNSServerAddressOptions{
				//					Server: "sky.rethinkdns.com",
				//				},
				//			},
				//		},
				//	},
				//},
				{
					Type: C.DNSTypeUDP,
					Tag:  DNSDirectTag,
					Options: &option.RemoteDNSServerOptions{
						DNSServerAddressOptions: option.DNSServerAddressOptions{
							Server: opt.DirectDnsAddress,
						},
					},
				},
				{
					Type: C.DNSTypeLocal,
					Tag:  DNSLocalTag,
					Options: &option.LocalDNSServerOptions{
						DialerOptions: option.DialerOptions{
							Detour: OutboundDirectTag,
						},
					},
				},
			},
		},
	}
}
func setFakeDns(options *option.Options, opt *HiddifyOptions) {
	if opt.EnableFakeDNS {
		inet4Range := "198.18.0.0/15"
		inet6Range := "fc00::/18"
		inet4 := badoption.Prefix(netip.MustParsePrefix(inet4Range))
		inet6 := badoption.Prefix(netip.MustParsePrefix(inet6Range))
		options.DNS.FakeIP = &option.LegacyDNSFakeIPOptions{
			Enabled:    true,
			Inet4Range: &inet4,
			Inet6Range: &inet6,
		}
	}
}

func setRoutingOptions(options *option.Options, opt *HiddifyOptions) {
	dnsRules := []option.DefaultDNSRule{}
	routeRules := []option.Rule{}
	rulesets := []option.RuleSet{}

	if opt.EnableTun && runtime.GOOS == "android" {
		routeRules = append(
			routeRules,
			option.Rule{
				Type: C.RuleTypeDefault,
				DefaultOptions: option.DefaultRule{
					RawDefaultRule: option.RawDefaultRule{
						Inbound:     []string{InboundTUNTag},
						PackageName: []string{"app.guichaovpn.com"},
					},
					RuleAction: option.RuleAction{
						Action: C.RuleActionTypeRoute,
						RouteOptions: option.RouteActionOptions{
							Outbound: OutboundBypassTag,
						},
					},
				},
			},
		)
	}

	routeRules = append(routeRules, option.Rule{
		Type: C.RuleTypeDefault,
		DefaultOptions: option.DefaultRule{
			RawDefaultRule: option.RawDefaultRule{
				Inbound: []string{InboundDNSTag},
			},
			RuleAction: option.RuleAction{
				Action: C.RuleActionTypeRoute,
				RouteOptions: option.RouteActionOptions{
					Outbound: OutboundDNSTag,
				},
			},
		},
	})

	routeRules = append(routeRules, option.Rule{
		Type: C.RuleTypeDefault,
		DefaultOptions: option.DefaultRule{
			RawDefaultRule: option.RawDefaultRule{
				Port: []uint16{53},
			},
			RuleAction: option.RuleAction{
				Action: C.RuleActionTypeRoute,
				RouteOptions: option.RouteActionOptions{
					Outbound: OutboundDNSTag,
				},
			},
		},
	})
	if opt.BypassLAN {
		routeRules = append(
			routeRules,
			option.Rule{
				Type: C.RuleTypeDefault,
				DefaultOptions: option.DefaultRule{
					RawDefaultRule: option.RawDefaultRule{
						// GeoIP: []string{"private"}, // 已弃用
						IPIsPrivate: true,
					},
					RuleAction: option.RuleAction{
						Action: C.RuleActionTypeReject,
						RejectOptions: option.RejectActionOptions{
							Method: C.RuleActionRejectMethodDefault,
							NoDrop: false,
						},
					},
				},
			},
		)
	}

	for _, rule := range opt.Rules {
		// 处理路由规则
		routeRule := rule.MakeRule()

		// 创建 RuleAction 结构
		var action option.RuleAction
		action.Action = C.RuleActionTypeRoute

		// 根据 Outbound 设置目标出站
		switch rule.Outbound {
		case "bypass":
			action.RouteOptions.Outbound = OutboundBypassTag
		case "block":
			// 对于 block，应该使用 reject 动作而不是路由到 block 出站
			action = option.RuleAction{
				Action: C.RuleActionTypeReject,
				RejectOptions: option.RejectActionOptions{
					Method: C.RuleActionRejectMethodDefault,
					NoDrop: false,
				},
			}

		case "proxy":
			action.RouteOptions.Outbound = OutboundMainProxyTag
		}

		// 移除旧的 Outbound 字段，添加 RuleAction
		routeRule.RuleAction = action

		if routeRule.IsValid() {
			routeRules = append(
				routeRules,
				option.Rule{
					Type:           C.RuleTypeDefault,
					DefaultOptions: routeRule,
				},
			)
		}

		// 处理 DNS 规则
		dnsRule := rule.MakeDNSRule()

		// 创建 DNS 规则动作
		var dnsAction option.DNSRuleAction
		dnsAction.Action = C.RuleActionTypeRoute

		switch rule.Outbound {
		case "bypass":
			dnsAction.RouteOptions.Server = DNSDirectTag
		case "block":
			//dnsAction.Action = C.RuleActionTypeReject
			dnsAction = option.DNSRuleAction{
				Action: C.RuleActionTypeReject,
				RejectOptions: option.RejectActionOptions{
					Method: C.RuleActionRejectMethodDefault,
					NoDrop: false,
				},
			}
			// 或者如果您想保持原来的行为：
			// dnsAction.RouteOptions.Server = DNSBlockTag
			// dnsAction.RouteOptions.DisableCache = true
		case "proxy":
			if opt.EnableFakeDNS {
				fakeDnsRule := dnsRule
				fakeDnsAction := dnsAction
				fakeDnsAction.RouteOptions.Server = DNSFakeTag
				fakeDnsRule.DNSRuleAction = fakeDnsAction
				fakeDnsRule.Inbound = []string{InboundTUNTag, InboundMixedTag}
				dnsRules = append(dnsRules, fakeDnsRule)
			}
			dnsAction.RouteOptions.Server = DNSRemoteTag
		}

		// 移除旧的字段，添加 RuleAction
		//dnsRule.Server = ""          // 清除旧字段
		//dnsRule.DisableCache = false // 清除旧字段
		dnsRule.DNSRuleAction = dnsAction

		dnsRules = append(dnsRules, dnsRule)
	}

	parsedURL, err := url.Parse(opt.ConnectionTestUrl)
	if err == nil {
		var dnsCPttl uint32 = 3000
		dnsRules = append(dnsRules, option.DefaultDNSRule{
			RawDefaultDNSRule: option.RawDefaultDNSRule{
				Domain: []string{parsedURL.Host},
			},
			DNSRuleAction: option.DNSRuleAction{
				Action: C.RuleActionTypeRoute,
				RouteOptions: option.DNSRouteActionOptions{
					Server:       DNSRemoteTag,
					RewriteTTL:   &dnsCPttl,
					DisableCache: false,
				},
			},
		})
	}

	if opt.BlockAds {
		rulesets = append(rulesets, option.RuleSet{
			Type:   C.RuleSetTypeRemote,
			Tag:    "geosite-ads",
			Format: C.RuleSetFormatBinary,
			RemoteOptions: option.RemoteRuleSet{
				URL:            "https://raw.githubusercontent.com/hiddify/hiddify-geo/rule-set/block/geosite-category-ads-all.srs",
				UpdateInterval: badoption.Duration(5 * time.Hour * 24),
			},
		})
		rulesets = append(rulesets, option.RuleSet{
			Type:   C.RuleSetTypeRemote,
			Tag:    "geosite-malware",
			Format: C.RuleSetFormatBinary,
			RemoteOptions: option.RemoteRuleSet{
				URL:            "https://raw.githubusercontent.com/hiddify/hiddify-geo/rule-set/block/geosite-malware.srs",
				UpdateInterval: badoption.Duration(5 * time.Hour * 24),
			},
		})
		rulesets = append(rulesets, option.RuleSet{
			Type:   C.RuleSetTypeRemote,
			Tag:    "geosite-phishing",
			Format: C.RuleSetFormatBinary,
			RemoteOptions: option.RemoteRuleSet{
				URL:            "https://raw.githubusercontent.com/hiddify/hiddify-geo/rule-set/block/geosite-phishing.srs",
				UpdateInterval: badoption.Duration(5 * time.Hour * 24),
			},
		})
		rulesets = append(rulesets, option.RuleSet{
			Type:   C.RuleSetTypeRemote,
			Tag:    "geosite-cryptominers",
			Format: C.RuleSetFormatBinary,
			RemoteOptions: option.RemoteRuleSet{
				URL:            "https://raw.githubusercontent.com/hiddify/hiddify-geo/rule-set/block/geosite-cryptominers.srs",
				UpdateInterval: badoption.Duration(5 * time.Hour * 24),
			},
		})
		rulesets = append(rulesets, option.RuleSet{
			Type:   C.RuleSetTypeRemote,
			Tag:    "geoip-phishing",
			Format: C.RuleSetFormatBinary,
			RemoteOptions: option.RemoteRuleSet{
				URL:            "https://raw.githubusercontent.com/hiddify/hiddify-geo/rule-set/block/geoip-phishing.srs",
				UpdateInterval: badoption.Duration(5 * time.Hour * 24),
			},
		})
		rulesets = append(rulesets, option.RuleSet{
			Type:   C.RuleSetTypeRemote,
			Tag:    "geoip-malware",
			Format: C.RuleSetFormatBinary,
			RemoteOptions: option.RemoteRuleSet{
				URL:            "https://raw.githubusercontent.com/hiddify/hiddify-geo/rule-set/block/geoip-malware.srs",
				UpdateInterval: badoption.Duration(5 * time.Hour * 24),
			},
		})

		routeRules = append(routeRules, option.Rule{
			Type: C.RuleTypeDefault,
			DefaultOptions: option.DefaultRule{
				RawDefaultRule: option.RawDefaultRule{
					RuleSet: []string{
						"geosite-ads",
						"geosite-malware",
						"geosite-phishing",
						"geosite-cryptominers",
						"geoip-malware",
						"geoip-phishing",
					},
				},
				RuleAction: option.RuleAction{
					// 对于阻止广告和恶意软件，推荐使用 reject 动作而不是路由到 block 出站
					Action: C.RuleActionTypeReject,
					RejectOptions: option.RejectActionOptions{
						Method: C.RuleActionRejectMethodDefault,
						NoDrop: false,
					},

					// 如果您仍然想使用 block 出站，可以使用以下配置
					// Action: C.RuleActionTypeRoute,
					// RouteOptions: option.RouteActionOptions{
					//     Outbound: OutboundBlockTag,
					// },
				},
			},
		})

		// 修改 DNS 规则，使用新的规则动作系统
		dnsRules = append(dnsRules, option.DefaultDNSRule{
			RawDefaultDNSRule: option.RawDefaultDNSRule{
				RuleSet: []string{
					"geosite-ads",
					"geosite-malware",
					"geosite-phishing",
					"geosite-cryptominers",
					"geoip-malware",
					"geoip-phishing",
				},
			},
			DNSRuleAction: option.DNSRuleAction{
				Action: C.RuleActionTypeRoute,
				RouteOptions: option.DNSRouteActionOptions{
					Server: DNSBlockTag,
					// DisableCache: true, // If you need to disable caching, uncomment this
				},
			},
		})

		if opt.Region != "other" {
			// 修改第一个 DNS 规则，使用新的规则动作系统
			dnsRules = append(dnsRules, option.DefaultDNSRule{
				RawDefaultDNSRule: option.RawDefaultDNSRule{
					DomainSuffix: []string{"." + opt.Region},
				},
				DNSRuleAction: option.DNSRuleAction{
					Action: C.RuleActionTypeRoute,
					RouteOptions: option.DNSRouteActionOptions{
						Server: DNSDirectTag,
					},
				},
			})

			// 修改第一个路由规则，使用新的规则动作系统
			routeRules = append(routeRules, option.Rule{
				Type: C.RuleTypeDefault,
				DefaultOptions: option.DefaultRule{
					RawDefaultRule: option.RawDefaultRule{
						DomainSuffix: []string{"." + opt.Region},
					},
					RuleAction: option.RuleAction{
						Action: C.RuleActionTypeRoute,
						RouteOptions: option.RouteActionOptions{
							Outbound: OutboundDirectTag,
						},
					},
				},
			})

			// 修改第二个 DNS 规则，使用新的规则动作系统
			dnsRules = append(dnsRules, option.DefaultDNSRule{
				RawDefaultDNSRule: option.RawDefaultDNSRule{
					RuleSet: []string{
						"geoip-" + opt.Region,
						"geosite-" + opt.Region,
					},
				},
				DNSRuleAction: option.DNSRuleAction{
					Action: C.RuleActionTypeRoute,
					RouteOptions: option.DNSRouteActionOptions{
						Server: DNSDirectTag,
					},
				},
			})

			// 规则集定义部分保持不变
			rulesets = append(rulesets, option.RuleSet{
				Type:   C.RuleSetTypeRemote,
				Tag:    "geoip-" + opt.Region,
				Format: C.RuleSetFormatBinary,
				RemoteOptions: option.RemoteRuleSet{
					URL:            "https://raw.githubusercontent.com/hiddify/hiddify-geo/rule-set/country/geoip-" + opt.Region + ".srs",
					UpdateInterval: badoption.Duration(5 * time.Hour * 24),
				},
			})
			rulesets = append(rulesets, option.RuleSet{
				Type:   C.RuleSetTypeRemote,
				Tag:    "geosite-" + opt.Region,
				Format: C.RuleSetFormatBinary,
				RemoteOptions: option.RemoteRuleSet{
					URL:            "https://raw.githubusercontent.com/hiddify/hiddify-geo/rule-set/country/geosite-" + opt.Region + ".srs",
					UpdateInterval: badoption.Duration(5 * time.Hour * 24),
				},
			})

			// 修改第二个路由规则，使用新的规则动作系统
			routeRules = append(routeRules, option.Rule{
				Type: C.RuleTypeDefault,
				DefaultOptions: option.DefaultRule{
					RawDefaultRule: option.RawDefaultRule{
						RuleSet: []string{
							"geoip-" + opt.Region,
							"geosite-" + opt.Region,
						},
					},
					RuleAction: option.RuleAction{
						Action: C.RuleActionTypeRoute,
						RouteOptions: option.RouteActionOptions{
							Outbound: OutboundDirectTag,
						},
					},
				},
			})
		}

		options.Route = &option.RouteOptions{
			Rules:               routeRules,
			Final:               OutboundMainProxyTag,
			AutoDetectInterface: true,
			OverrideAndroidVPN:  true,
			RuleSet:             rulesets,
			// You might want to add cache file configuration for rule sets
			// DefaultDomainStrategy: option.DomainStrategy(dns.DomainStrategyAsIS),
		}

		// Add DNS rules if DNS routing is enabled
		if opt.EnableDNSRouting {
			for _, dnsRule := range dnsRules {
				if dnsRule.IsValid() {
					options.DNS.Rules = append(
						options.DNS.Rules,
						option.DNSRule{
							Type:           C.RuleTypeDefault,
							DefaultOptions: dnsRule,
						},
					)
				}
			}
		}

	}
}
func patchHiddifyWarpFromConfig(out option.Outbound, opt HiddifyOptions) option.Outbound {
	if opt.Warp.EnableWarp && opt.Warp.Mode == "proxy_over_warp" {
		// 使用 JSON 转换的方式来处理 Outbound 结构
		jsonData, err := json.Marshal(out)
		if err != nil {
			fmt.Printf("Error marshaling outbound: %v\n", err)
			return out
		}

		var obj map[string]interface{}
		err = json.Unmarshal(jsonData, &obj)
		if err != nil {
			fmt.Printf("Error unmarshaling outbound: %v\n", err)
			return out
		}

		// 设置 detour 字段
		setDetour := func(optionName string) {
			if options, ok := obj[optionName].(map[string]interface{}); ok {
				if _, hasDetour := options["detour"]; !hasDetour || options["detour"] == "" {
					options["detour"] = "Hiddify Warp ✅"
				}
			}
		}

		// 为所有可能的选项设置 detour
		optionNames := []string{
			"direct_options", "http_options", "hysteria2_options", "hysteria_options",
			"ssh_options", "shadowtls_options", "shadowsocks_options", "shadowsocksr_options",
			"socks_options", "tuic_options", "tor_options", "trojan_options",
			"vless_options", "vmess_options", "wireguard_options",
		}

		for _, name := range optionNames {
			setDetour(name)
		}

		// 将修改后的对象转换回 Outbound
		modifiedJson, err := json.Marshal(obj)
		if err != nil {
			fmt.Printf("Error marshaling modified outbound: %v\n", err)
			return out
		}

		err = json.Unmarshal(modifiedJson, &out)
		if err != nil {
			fmt.Printf("Error unmarshaling modified outbound: %v\n", err)
		}
	}
	return out
}

func getIPs(domains []string) []string {
	res := []string{}
	for _, d := range domains {
		ips, err := net.LookupHost(d)
		if err != nil {
			continue
		}
		for _, ip := range ips {
			if !strings.HasPrefix(ip, "10.") {
				res = append(res, ip)
			}
		}
	}
	return res
}

func isBlockedDomain(domain string) bool {
	if strings.HasPrefix("full:", domain) {
		return false
	}
	ips, err := net.LookupHost(domain)
	if err != nil {
		// fmt.Println(err)
		return true
	}

	// Print the IP addresses associated with the domain
	fmt.Printf("IP addresses for %s:\n", domain)
	for _, ip := range ips {
		if strings.HasPrefix(ip, "10.") {
			return true
		}
	}
	return false
}

func removeDuplicateStr(strSlice []string) []string {
	allKeys := make(map[string]bool)
	list := []string{}
	for _, item := range strSlice {
		if _, value := allKeys[item]; !value {
			allKeys[item] = true
			list = append(list, item)
		}
	}
	return list
}

func generateRandomString(length int) string {
	// Determine the number of bytes needed
	bytesNeeded := (length*6 + 7) / 8

	// Generate random bytes
	randomBytes := make([]byte, bytesNeeded)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return "hiddify"
	}

	// Encode random bytes to base64
	randomString := base64.URLEncoding.EncodeToString(randomBytes)

	// Trim padding characters and return the string
	return randomString[:length]
}
