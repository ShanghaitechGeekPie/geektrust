package webui

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"geektrust/internal/config"
	"geektrust/internal/sdpc"
	"geektrust/internal/session"
)

//go:embed all:dist
var distFS embed.FS

// placeholderPage is served when the frontend has not been built (only
// dist/.gitkeep is embedded). The API works regardless.
const placeholderPage = `<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><title>geekTrust 面板</title></head>
<body style="font-family:system-ui;max-width:640px;margin:4em auto;line-height:1.6">
<h1>geekTrust Web 面板</h1>
<p>前端资源尚未构建。请在仓库根目录执行 <code>make web</code>（需要 Node 20+），然后重新构建 geekTrust。</p>
<p>REST API 不受影响：<code>GET /api/status</code> 可直接使用。</p>
</body></html>
`

// ProviderAPI is the narrow provider surface the handlers need; fakes can
// implement it for deterministic tests.
type ProviderAPI interface {
	ActiveSDPC() *sdpc.Client
	TryForceRelogin() (run func(context.Context), ok bool)
}

// Server is the panel HTTP server.
type Server struct {
	hub      *Hub
	broker   *Broker
	provider ProviderAPI
	cfg      *config.Config
	http     *http.Server
	dist     fs.FS
	hasUI    bool
}

// NewServer wires the routes, security middleware and embedded frontend.
func NewServer(hub *Hub, broker *Broker, provider ProviderAPI, cfg *config.Config) *Server {
	s := &Server{hub: hub, broker: broker, provider: provider, cfg: cfg}
	if sub, err := fs.Sub(distFS, "dist"); err == nil {
		s.dist = sub
		if f, err := sub.Open("index.html"); err == nil {
			f.Close()
			s.hasUI = true
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/status", s.handleStatus)
	mux.HandleFunc("GET /api/events", s.handleEvents)
	mux.HandleFunc("POST /api/sms", s.handleSMS)
	mux.HandleFunc("POST /api/sms/resend", s.handleResend)
	mux.HandleFunc("POST /api/relogin", s.handleRelogin)
	mux.HandleFunc("GET /api/trust-devices", s.handleTrustList)
	mux.HandleFunc("POST /api/trust-devices/bind", s.handleTrustBind)
	mux.HandleFunc("POST /api/trust-devices/unbind", s.handleTrustUnbind)
	mux.HandleFunc("POST /api/trust-devices/logout", s.handleTrustLogout)
	// Unknown API paths get a JSON 404 instead of the frontend shell.
	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusNotFound, "unknown API endpoint")
	})
	// Static must not use a method-scoped pattern here: "GET /" conflicts
	// with the broader "/api/" fallback in http.ServeMux.
	mux.HandleFunc("/", s.handleStatic)
	s.http = &http.Server{Handler: s.secure(mux)}
	// SSE streams never go idle, so a graceful Shutdown would always wait
	// out its whole timeout while a panel tab is open. Closing the hub's
	// subscribers makes every event handler return promptly.
	s.http.RegisterOnShutdown(hub.CloseSubscribers)
	return s
}

// Serve runs the HTTP server on the pre-bound listener.
func (s *Server) Serve(listener net.Listener) error {
	return s.http.Serve(listener)
}

// Shutdown gracefully stops the server; connections that outlive ctx (e.g.
// a client that stopped reading mid-response) are hard-closed instead of
// leaked past the deadline.
func (s *Server) Shutdown(ctx context.Context) error {
	err := s.http.Shutdown(ctx)
	if err != nil {
		s.http.Close()
	}
	return err
}

// secure applies the panel's browser-attack defenses on every response:
// anti-clickjacking headers, DNS-rebinding Host check, and cross-site POST
// rejection (Origin + JSON content type). The authority compared against is
// the canonicalized Web.Listen from config validation.
func (s *Server) secure(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "frame-ancestors 'none'")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if r.Host != s.cfg.Web.Listen {
			writeError(w, http.StatusForbidden, "forbidden host")
			return
		}
		if r.Method == http.MethodPost {
			// All legitimate request bodies are tiny JSON documents.
			r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
			if origin := r.Header.Get("Origin"); origin != "" {
				u, err := url.Parse(origin)
				if err != nil || u.Host != s.cfg.Web.Listen {
					writeError(w, http.StatusForbidden, "forbidden origin")
					return
				}
			}
			// Parse exactly: application/jsonp or malformed values must not
			// reach state-changing handlers.
			mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
			if err != nil || mediaType != "application/json" {
				writeError(w, http.StatusForbidden, "content-type must be application/json")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": session.SanitizeErrorText(msg)})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if v != nil {
		json.NewEncoder(w).Encode(v)
	}
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(s.hub.Snapshot())
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ch, initial, cancel := s.hub.Subscribe()
	defer cancel()
	fmt.Fprintf(w, "data: %s\n\n", initial)
	flusher.Flush()

	keepalive := time.NewTicker(25 * time.Second)
	defer keepalive.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case data, ok := <-ch:
			if !ok {
				return
			}
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		case <-keepalive.C:
			fmt.Fprint(w, ": keepalive\n\n")
			flusher.Flush()
		}
	}
}

type smsRequest struct {
	Code string `json:"code"`
	Gen  uint64 `json:"gen"`
}

func (s *Server) handleSMS(w http.ResponseWriter, r *http.Request) {
	var req smsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if !isSixDigits(req.Code) {
		writeError(w, http.StatusBadRequest, "code must be 6 digits")
		return
	}
	if err := s.broker.ClaimWeb(req.Code, req.Gen); err != nil {
		writeError(w, http.StatusConflict, "no SMS verification pending (or stale generation)")
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{})
}

func (s *Server) handleResend(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Gen uint64 `json:"gen"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	err := s.broker.Resend(r.Context(), req.Gen)
	switch {
	case err == nil:
		writeJSON(w, http.StatusAccepted, map[string]any{})
	case sdpc.IsSessionExpired(err):
		// Broker has retired the stale prompt; the existing Provider
		// acquisition will rebuild the authentication chain in the background.
		writeJSON(w, http.StatusAccepted, map[string]any{"restarting": true})
	case errors.Is(err, ErrNoPending):
		writeError(w, http.StatusConflict, "no SMS verification pending (or stale generation)")
	default:
		var apiErr *sdpc.APIError
		if errors.As(err, &apiErr) && apiErr.Code == sdpc.CodeSMSStillValid {
			writeError(w, http.StatusTooManyRequests, apiErr.Message)
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
	}
}

func (s *Server) handleRelogin(w http.ResponseWriter, r *http.Request) {
	run, ok := s.provider.TryForceRelogin()
	if !ok {
		writeError(w, http.StatusConflict, "login already in progress")
		return
	}
	// The reserved acquisition must run exactly once and outlive the request.
	go run(context.Background())
	writeJSON(w, http.StatusAccepted, map[string]any{})
}

func (s *Server) activeSC(w http.ResponseWriter) *sdpc.Client {
	sc := s.provider.ActiveSDPC()
	if sc == nil {
		writeError(w, http.StatusServiceUnavailable, "no active session")
	}
	return sc
}

func (s *Server) handleTrustList(w http.ResponseWriter, r *http.Request) {
	sc := s.activeSC(w)
	if sc == nil {
		return
	}
	list, err := sc.QueryTrustDevice(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) handleTrustBind(w http.ResponseWriter, r *http.Request) {
	if s.cfg.ClientType != "client" {
		writeError(w, http.StatusConflict, `trust-device bind requires client_type = "client" in config`)
		return
	}
	sc := s.activeSC(w)
	if sc == nil {
		return
	}
	if err := sc.TrustDevice(r.Context()); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{})
}

func (s *Server) handleTrustUnbind(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IDs []string `json:"ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if len(req.IDs) == 0 {
		writeError(w, http.StatusBadRequest, "ids must not be empty")
		return
	}
	sc := s.activeSC(w)
	if sc == nil {
		return
	}
	if err := sc.UntrustDevice(r.Context(), req.IDs); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{})
}

func (s *Server) handleTrustLogout(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if strings.TrimSpace(req.ID) == "" {
		writeError(w, http.StatusBadRequest, "id must not be empty")
		return
	}
	sc := s.activeSC(w)
	if sc == nil {
		return
	}
	if err := sc.LogoutDevice(r.Context(), req.ID); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{})
}

// handleStatic serves the embedded frontend (with SPA fallback) or the
// placeholder page when the frontend has not been built. GET/HEAD only.
//
// Cache rules keep rebuilds sane: Vite asset filenames are content-hashed,
// so /assets/* is immutable, while index.html must always revalidate — a
// cached shell referencing purged hashes would otherwise blank the panel
// after every rebuild.
func (s *Server) handleStatic(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !s.hasUI {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		io.WriteString(w, placeholderPage)
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/")
	if path == "" {
		path = "index.html"
	}
	if info, err := fs.Stat(s.dist, path); err != nil || info.IsDir() {
		// A missing hashed asset must be a hard 404: serving the SPA shell
		// as JS/CSS would hand the browser HTML under a script MIME type.
		if strings.HasPrefix(path, "assets/") {
			http.NotFound(w, r)
			return
		}
		// SPA fallback: unknown paths and directories get the app shell.
		r.URL.Path = "/"
		path = "index.html"
	}
	if strings.HasPrefix(path, "assets/") {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	} else {
		w.Header().Set("Cache-Control", "no-cache")
	}
	http.FileServerFS(s.dist).ServeHTTP(w, r)
}
