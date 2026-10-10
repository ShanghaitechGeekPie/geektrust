package compatibility

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"unicode"
)

type Profile string

const (
	Auto         Profile = ""
	Generic      Profile = "generic"
	ShanghaiTech Profile = "shanghaitech"
	ECNU         Profile = "ecnu"
)

type Options struct {
	Profile   Profile
	Protocol  ProtocolOptions
	Fallbacks *Fallbacks
}

type ProtocolOptions struct {
	ControllerPlatform string
	Process            *ProcessMetadata
}

type ProcessMetadata struct {
	Name     string
	Platform string
	Path     string
}

type Fallbacks struct {
	ApplicationID       string
	Gateways            []string
	MissingGatewayGroup bool
	StreamToL3          bool
}

func (o Options) Validate() error {
	switch o.Profile {
	case Auto, Generic, ShanghaiTech, ECNU:
	default:
		return fmt.Errorf("unknown compatibility profile %q", o.Profile)
	}
	if len(o.Protocol.ControllerPlatform) > 64 || strings.IndexFunc(o.Protocol.ControllerPlatform, unicode.IsControl) >= 0 {
		return fmt.Errorf("invalid controller platform")
	}
	if p := o.Protocol.Process; p != nil {
		for _, v := range []string{p.Name, p.Platform, p.Path} {
			if strings.TrimSpace(v) == "" || len(v) > 4096 || strings.IndexFunc(v, unicode.IsControl) >= 0 {
				return fmt.Errorf("invalid process metadata")
			}
		}
	}
	if f := o.Fallbacks; f != nil {
		if len(f.ApplicationID) > 256 || strings.IndexFunc(f.ApplicationID, unicode.IsControl) >= 0 {
			return fmt.Errorf("invalid fallback application ID")
		}
		for _, a := range f.Gateways {
			h, p, e := net.SplitHostPort(a)
			n, x := strconv.Atoi(p)
			if e != nil || x != nil || h == "" || n < 1 || n > 65535 || strings.ContainsAny(h, "/\\@?# \t\r\n") {
				return fmt.Errorf("invalid fallback gateway")
			}
		}
	}
	return nil
}
