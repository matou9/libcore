package config

import (
	"encoding/json"
	"fmt"
	"net"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

type outboundMap map[string]interface{}

func patchOutboundMux(base option.Outbound, configOpt HiddifyOptions, obj outboundMap) outboundMap {
	if configOpt.Mux.Enable {
		multiplex := option.OutboundMultiplexOptions{
			Enabled:    true,
			Padding:    configOpt.Mux.Padding,
			MaxStreams: configOpt.Mux.MaxStreams,
			Protocol:   configOpt.Mux.Protocol,
		}
		obj["multiplex"] = multiplex
		// } else {
		// 	delete(obj, "multiplex")
	}
	return obj
}

func patchOutboundTLSTricks(base option.Outbound, configOpt HiddifyOptions, obj outboundMap) outboundMap {
	if base.Type == C.TypeSelector || base.Type == C.TypeURLTest || base.Type == C.TypeBlock || base.Type == C.TypeDNS {
		return obj
	}
	if isOutboundReality(base) {
		return obj
	}

	var tls *option.OutboundTLSOptions
	var transport *option.V2RayTransportOptions

	switch base.Type {
	case C.TypeVLESS:
		if vlessOpt, ok := base.Options.(option.VLESSOutboundOptions); ok {
			tls = vlessOpt.TLS
			transport = vlessOpt.Transport
		}
	case C.TypeTrojan:
		if trojanOpt, ok := base.Options.(option.TrojanOutboundOptions); ok {
			tls = trojanOpt.TLS
			transport = trojanOpt.Transport
		}
	case C.TypeVMess:
		if vmessOpt, ok := base.Options.(option.VMessOutboundOptions); ok {
			tls = vmessOpt.TLS
			transport = vmessOpt.Transport
		}
	}

	if base.Type == C.TypeDirect {
		return patchOutboundFragment(base, configOpt, obj)
	}

	if tls == nil || !tls.Enabled || transport == nil {
		return obj
	}

	if transport.Type != C.V2RayTransportTypeWebsocket && transport.Type != C.V2RayTransportTypeGRPC && transport.Type != C.V2RayTransportTypeHTTPUpgrade {
		return obj
	}

	// 这里假设 TLSTricks 字段已被移除或结构变更，如需兼容请补充新版逻辑
	return obj
}

func patchOutboundFragment(base option.Outbound, configOpt HiddifyOptions, obj outboundMap) outboundMap {
	if configOpt.TLSTricks.EnableFragment {
		obj["tcp_fast_open"] = false
		obj["tls_fragment"] = map[string]interface{}{
			"enabled": configOpt.TLSTricks.EnableFragment,
			"size":    configOpt.TLSTricks.FragmentSize,
			"sleep":   configOpt.TLSTricks.FragmentSleep,
		}
	}
	return obj
}

func isOutboundReality(base option.Outbound) bool {
	if base.Type != C.TypeVLESS {
		return false
	}
	if vlessOpt, ok := base.Options.(option.VLESSOutboundOptions); ok {
		if vlessOpt.TLS == nil || vlessOpt.TLS.Reality == nil {
			return false
		}
		return vlessOpt.TLS.Reality.Enabled
	}
	return false
}

func patchOutbound(base option.Outbound, configOpt HiddifyOptions, staticIpsDns map[string][]string) (*option.Outbound, string, error) {
	formatErr := func(err error) error {
		return fmt.Errorf("error patching outbound[%s][%s]: %w", base.Tag, base.Type, err)
	}
	err := patchWarp(&base, &configOpt, true, staticIpsDns)
	if err != nil {
		return nil, "", formatErr(err)
	}
	var outbound option.Outbound

	jsonData, err := json.Marshal(base)
	if err != nil {
		return nil, "", formatErr(err)
	}

	var obj outboundMap
	err = json.Unmarshal(jsonData, &obj)
	if err != nil {
		return nil, "", formatErr(err)
	}
	var serverDomain string
	if detour, ok := obj["detour"].(string); !ok || detour == "" {
		if server, ok := obj["server"].(string); ok {
			if server != "" && net.ParseIP(server) == nil {
				serverDomain = fmt.Sprintf("full:%s", server)
			}
		}
	}

	obj = patchOutboundTLSTricks(base, configOpt, obj)

	switch base.Type {
	case C.TypeVMess, C.TypeVLESS, C.TypeTrojan, C.TypeShadowsocks:
		obj = patchOutboundMux(base, configOpt, obj)
	}

	modifiedJson, err := json.Marshal(obj)
	if err != nil {
		return nil, "", formatErr(err)
	}

	err = json.Unmarshal(modifiedJson, &outbound)
	if err != nil {
		return nil, "", formatErr(err)
	}

	return &outbound, serverDomain, nil
}

// func (o outboundMap) transportType() string {
// 	if transport, ok := o["transport"].(map[string]interface{}); ok {
// 		if transportType, ok := transport["type"].(string); ok {
// 			return transportType
// 		}
// 	}
// 	return ""
// }
