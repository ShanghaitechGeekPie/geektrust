package l3

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net"
	"time"
)

// procPath is the process path impersonated in the trust environment. Its
// SHA-256 (uppercase hex) must appear as both env fingerprint and procHash
// (TECHNICAL.md §6.2).
const procPath = "/Applications/aTrust.app/Contents/Resources/bin/aTrustXtunnel"

// authRequestIP field order is protocol-significant: the reference serializes
// an OrderedDict in exactly this order (TECHNICAL.md §6.2). Go marshals
// struct fields in declaration order. Do NOT add appToken/rcAppliedInfo.
type authRequestIP struct {
	Sid           string   `json:"sid"`
	AppID         string   `json:"appId"`
	URL           string   `json:"url"`
	DeviceID      string   `json:"deviceId"` // key is lowercase deviceId
	ConnectionID  string   `json:"connectionId"`
	Env           trustEnv `json:"env"`
	ConntrackHash uint64   `json:"conntrackHash"`
	Lang          string   `json:"lang"`
	IP            authIP   `json:"ip"`
	ProcHash      string   `json:"procHash"`
	XRequestSig   string   `json:"xRequestSig"` // gateway does not verify; empty
}

type authIP struct {
	Atype    int    `json:"atype"`
	Protocol int    `json:"protocol"`
	DestAddr string `json:"destAddr"`
	DestPort int    `json:"destPort"`
	SrcAddr  string `json:"srcAddr"`
	SrcPort  int    `json:"srcPort"`
}

type trustEnv struct {
	Application struct {
		Runtime struct {
			Process struct {
				Name             string `json:"name"`
				DigitalSignature string `json:"digital_signature"`
				Platform         string `json:"platform"`
				Fingerprint      string `json:"fingerprint"`
				Description      string `json:"description"`
				Path             string `json:"path"`
				Version          string `json:"version"`
				SecurityEnv      string `json:"security_env"`
			} `json:"process"`
			ProcessTrusted string `json:"process_trusted"`
		} `json:"runtime"`
	} `json:"application"`
}

// procFingerprint is SHA256(procPath) in uppercase hex, shared by
// env.application.runtime.process.fingerprint and procHash.
var procFingerprint = fmt.Sprintf("%X", sha256.Sum256([]byte(procPath)))

// buildAuthRequestIP serializes the per-connection auth body exactly per
// TECHNICAL.md §6.2.
func buildAuthRequestIP(sid, appID, deviceID, dstIP string, dstPort int, vip net.IP, srcPort uint16, conntrackHash uint64) ([]byte, error) {
	// connectionId = MD5(device_id).upper() + "-" + unix microseconds.
	connID := fmt.Sprintf("%X-%d", md5.Sum([]byte(deviceID)), time.Now().UnixMicro())

	var env trustEnv
	p := &env.Application.Runtime.Process
	p.Name = "aTrustXtunnel"
	p.DigitalSignature = "TrustAppClosed"
	p.Platform = "macOS"
	p.Fingerprint = procFingerprint
	p.Description = "TrustAppClosed"
	p.Path = procPath
	p.Version = "TrustAppClosed"
	p.SecurityEnv = "normal"
	env.Application.Runtime.ProcessTrusted = "TRUSTED"

	req := authRequestIP{
		Sid:           sid,
		AppID:         appID,
		URL:           fmt.Sprintf("tcp:%s:%d", dstIP, dstPort),
		DeviceID:      deviceID,
		ConnectionID:  connID,
		Env:           env,
		ConntrackHash: conntrackHash,
		Lang:          "zh-CN",
		IP: authIP{
			Atype:    0x0800, // 2048, IPv4
			Protocol: 6,      // TCP
			DestAddr: dstIP,
			DestPort: dstPort,
			SrcAddr:  vip.String(),
			SrcPort:  int(srcPort),
		},
		ProcHash:    procFingerprint,
		XRequestSig: "",
	}
	return json.Marshal(req)
}
