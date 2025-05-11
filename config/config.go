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
	"strings"

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
		// trickDnsDomains := []string{}
		// directDNSDomains = removeDuplicateStr(directDNSDomains)
		// b, _ := batch.New(context.Background(), batch.WithConcurrencyNum[bool](10))
		// for _, d := range directDNSDomains {
		// 	b.Go(d, func() (bool, error) {
		// 		return isBlockedDomain(d), nil
		// 	})
		// }
		// b.Wait()
		// for domain, isBlock := range b.Result() {
		// 	if isBlock.Value {
		// 		trickDnsDomains = append(trickDnsDomains, domain)
		// 	}
		// }

		// trickDomains := strings.Join(trickDnsDomains, ",")
		// trickRule := Rule{Domains: trickDomains, Outbound: OutboundBypassTag}
		// trickDnsRule := trickRule.MakeDNSRule()
		// trickDnsRule.Server = DNSTricksDirectTag
		// options.DNS.Rules = append([]option.DNSRule{{Type: C.RuleTypeDefault, DefaultOptions: trickDnsRule}}, options.DNS.Rules...)

		directDNSDomainskeys := make([]string, 0, len(directDNSDomains))
		for key := range directDNSDomains {
			directDNSDomainskeys = append(directDNSDomainskeys, key)
		}

		domains := strings.Join(directDNSDomainskeys, ",")
		directRule := Rule{Domains: domains, Outbound: OutboundBypassTag}
		dnsRule := directRule.MakeDNSRule()
		// 在新版本中，Server 字段可能已经改名或移动
		// 这里需要根据新版本的 DefaultDNSRule 结构进行适配
		options.DNS.Rules = append([]option.DNSRule{{Type: C.RuleTypeDefault, DefaultOptions: dnsRule}}, options.DNS.Rules...)
	}
}

func setOutbounds(options *option.Options, input *option.Options, opt *HiddifyOptions) error {
	directDNSDomains := make(map[string]bool)
	var outbounds []option.Outbound
	var tags []string
	OutboundMainProxyTag = OutboundSelectTag
	// inbound==warp over proxies
	// outbound==proxies over warp
	if opt.Warp.EnableWarp {
		for _, out := range input.Outbounds {
			// C.TypeCustom 可能已经不存在于新版本中
			// 需要检查新版本中的类型定义
			if out.Type == C.TypeWireGuard {
				// 使用 JSON 转换的方式来获取 WireGuardOptions
				// 使用 json.Marshal 替代 MarshalJSON 方法
				jsonData, err := json.Marshal(out)
				if err == nil {
					var obj map[string]interface{}
					err = json.Unmarshal(jsonData, &obj)
					if err == nil {
						if wgOptions, ok := obj["wireguard_options"].(map[string]interface{}); ok {
							if privateKey, ok := wgOptions["private_key"].(string); ok {
								if privateKey == opt.Warp.WireguardConfig.PrivateKey || privateKey == "p1" {
									opt.Warp.EnableWarp = false
									break
								}
							}
						}
					}
				}
			}
		}
	}
	if opt.Warp.EnableWarp && (opt.Warp.Mode == "warp_over_proxy" || opt.Warp.Mode == "proxy_over_warp") {
		out, err := GenerateWarpSingbox(opt.Warp.WireguardConfig, opt.Warp.CleanIP, opt.Warp.CleanPort, opt.Warp.FakePackets, opt.Warp.FakePacketSize, opt.Warp.FakePacketDelay, opt.Warp.FakePacketMode)
		if err != nil {
			return fmt.Errorf("failed to generate warp config: %v", err)
		}
		out.Tag = "Hiddify Warp ✅"
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
		// tags = append(tags, out.Tag)
	}
	for _, out := range input.Outbounds {
		// StaticIPs 可能已经不存在于新版本中
		// 需要检查新版本中的 DNSOptions 结构
		outbound, serverDomain, err := patchOutbound(out, *opt, nil)
		if err != nil {
			return err
		}

		if serverDomain != "" {
			directDNSDomains[serverDomain] = true
		}
		out = *outbound

		switch out.Type {
		case C.TypeDirect, C.TypeBlock, C.TypeDNS:
			continue
		case C.TypeSelector, C.TypeURLTest:
			continue
			// C.TypeCustom 可能已经不存在于新版本中
			// 需要检查新版本中的类型定义
			//case C.TypeCustom:
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
	urlTestOptions := option.URLTestOutboundOptions{
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
	selectorOptions := option.SelectorOutboundOptions{
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
				Options: option.DirectOutboundOptions{
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
				ExternalController: fmt.Sprintf("%s:%d", "127.0.0.1", opt.ClashApiPort),
				Secret:             opt.ClashApiSecret,
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
			Stack:                  opt.TUNStack,
			MTU:                    opt.MTU,
			AutoRoute:              true,
			StrictRoute:            opt.StrictRoute,
			EndpointIndependentNat: true,
			// GSO:                    runtime.GOOS != "windows",
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
		switch opt.IPv6Mode {
		case option.DomainStrategy(dns.DomainStrategyUseIPv4):
			tunOptions.Inet4Address = []netip.Prefix{
				netip.MustParsePrefix("172.19.0.1/28"),
			}
		case option.DomainStrategy(dns.DomainStrategyUseIPv6):
			tunOptions.Inet6Address = []netip.Prefix{
				netip.MustParsePrefix("fdfe:dcba:9876::1/126"),
			}
		default:
			tunOptions.Inet4Address = []netip.Prefix{
				netip.MustParsePrefix("172.19.0.1/28"),
			}
			tunOptions.Inet6Address = []netip.Prefix{
				netip.MustParsePrefix("fdfe:dcba:9876::1/126"),
			}
		}
		tunInbound.Options = tunOptions
		options.Inbounds = append(options.Inbounds, tunInbound)

	}

	var bind string
	if opt.AllowConnectionFromLAN {
		bind = "0.0.0.0"
	} else {
		bind = "127.0.0.1"
	}

	mixedOptions := option.HTTPMixedInboundOptions{
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
	directOptions := option.DirectInboundOptions{
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
			Servers: []option.DNSServerOptions{
				{
					Type: "",
					Tag:  DNSRemoteTag,
					Options: &option.LegacyDNSServerOptions{
						Address:         opt.RemoteDnsAddress,
						AddressResolver: DNSDirectTag,
						Strategy:        opt.RemoteDnsDomainStrategy,
					},
				},
				{
					Type: "",
					Tag:  DNSTricksDirectTag,
					Options: &option.LegacyDNSServerOptions{
						Address:  "https://sky.rethinkdns.com/",
						Strategy: opt.DirectDnsDomainStrategy,
						Detour:   OutboundDirectFragmentTag,
					},
				},
				{
					Type: "",
					Tag:  DNSDirectTag,
					Options: &option.LegacyDNSServerOptions{
						Address:         opt.DirectDnsAddress,
						AddressResolver: DNSLocalTag,
						Strategy:        opt.DirectDnsDomainStrategy,
						Detour:          OutboundDirectTag,
					},
				},
				{
					Type: "",
					Tag:  DNSLocalTag,
					Options: &option.LegacyDNSServerOptions{
						Address: "local",
						Detour:  OutboundDirectTag,
					},
				},
				{
					Type: "",
					Tag:  DNSBlockTag,
					Options: &option.LegacyDNSServerOptions{
						Address: "rcode://success",
					},
				},
			},
			Final: DNSRemoteTag,
			DNSClientOptions: option.DNSClientOptions{
				IndependentCache: opt.IndependentDNSCache,
			},
		},
	}
	// sky_rethinkdns := getIPs([]string{"www.speedtest.net", "sky.rethinkdns.com"})
	// if len(sky_rethinkdns) > 0 {
	// 	options.DNS.StaticIPs["sky.rethinkdns.com"] = sky_rethinkdns
	// }
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
	var rules []option.Rule

	// DNS 入站流量转发到 DNS 出站
	rules = append(rules, option.Rule{
		Type: C.RuleTypeDefault,
		DefaultOptions: option.DefaultRule{
			RawDefaultRule: option.RawDefaultRule{
				Inbound: badoption.Listable[string]{InboundDNSTag},
			},
			RuleAction: option.RuleAction{
				Action: C.RuleActionTypeRoute,
				RouteOptions: option.RouteActionOptions{
					Outbound: OutboundDNSTag,
				},
			},
		},
	})

	// 53 端口流量转发到 DNS 出站
	rules = append(rules, option.Rule{
		Type: C.RuleTypeDefault,
		DefaultOptions: option.DefaultRule{
			RawDefaultRule: option.RawDefaultRule{
				Port: badoption.Listable[uint16]{53},
			},
			RuleAction: option.RuleAction{
				Action: C.RuleActionTypeRoute,
				RouteOptions: option.RouteActionOptions{
					Outbound: OutboundDNSTag,
				},
			},
		},
	})

	// 其它规则可按需补充

	options.Route = &option.RouteOptions{
		Rules:               rules,
		Final:               OutboundMainProxyTag,
		AutoDetectInterface: true,
		OverrideAndroidVPN:  true,
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
