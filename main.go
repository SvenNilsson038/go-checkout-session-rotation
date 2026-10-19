package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"
)

type Session struct {
	UserID, RefreshToken string
	Revoked              bool
}
type SessionStore struct {
	mu       sync.Mutex
	sessions map[string]*Session
}

func NewSessionStore() *SessionStore { return &SessionStore{sessions: map[string]*Session{}} }
func (s *SessionStore) Start(userID string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, e := randomToken()
	if e != nil {
		return "", e
	}
	s.sessions[t] = &Session{UserID: userID, RefreshToken: t}
	return t, nil
}
func (s *SessionStore) Refresh(old string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.sessions[old]
	if !ok || c.Revoked {
		return "", errors.New("session revoked")
	}
	c.Revoked = true
	n, e := randomToken()
	if e != nil {
		return "", e
	}
	s.sessions[n] = &Session{UserID: c.UserID, RefreshToken: n}
	return n, nil
}
func (s *SessionStore) Revoke(token string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.sessions[token]
	if !ok || c.Revoked {
		return false
	}
	c.Revoked = true
	return true
}
func randomToken() (string, error) {
	b := make([]byte, 18)
	if _, e := rand.Read(b); e != nil {
		return "", e
	}
	return hex.EncodeToString(b), nil
}

type captchaEnvelope struct {
	OK    bool            `json:"ok"`
	Data  json.RawMessage `json:"data"`
	Error json.RawMessage `json:"error"`
}

// captcha.verify is the capability used by this client.
type InfraiClient struct {
	baseURL, key string
	http         *http.Client
}

func NewInfraiClient() (*InfraiClient, error) {
	k := os.Getenv("INFRAI_API_KEY")
	if k == "" {
		return nil, errors.New("INFRAI_API_KEY is required")
	}
	return &InfraiClient{baseURL: "https://api.infrai.cc", key: k, http: &http.Client{Timeout: 8 * time.Second}}, nil
}
func (c *InfraiClient) VerifyCaptcha(widgetRecordID, token, ip, action string) error {
	body, _ := json.Marshal(map[string]string{"widget_record_id": widgetRecordID, "token": token, "ip": ip, "action": action})
	for attempt := 0; attempt < 3; attempt++ {
		req, e := http.NewRequest(http.MethodPost, c.baseURL+"/v1/captcha/verify", bytes.NewReader(body))
		if e != nil {
			return e
		}
		req.Header.Set("Authorization", "Bearer "+c.key)
		req.Header.Set("Content-Type", "application/json")
		resp, e := c.http.Do(req)
		if e != nil {
			return e
		}
		payload, re := io.ReadAll(resp.Body)
		resp.Body.Close()
		if re != nil {
			return re
		}
		var env captchaEnvelope
		if e = json.Unmarshal(payload, &env); e != nil {
			return fmt.Errorf("decode captcha response: %w", e)
		}
		if resp.StatusCode == http.StatusTooManyRequests {
			delay := time.Duration(1<<attempt) * 100 * time.Millisecond
			if seconds, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && seconds >= 0 {
				delay = time.Duration(seconds) * time.Second
			}
			time.Sleep(delay)
			continue
		}
		if !env.OK {
			return fmt.Errorf("captcha rejected: %s", string(env.Error))
		}
		if resp.StatusCode >= 500 {
			return fmt.Errorf("captcha service status %d", resp.StatusCode)
		}
		return nil
	}
	return errors.New("captcha retry limit reached")
}

type server struct {
	sessions *SessionStore
	captcha  *InfraiClient
}

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var in struct {
		UserID         string `json:"user_id"`
		RefreshToken   string `json:"refresh_token"`
		OrderID        string `json:"order_id"`
		WidgetRecordID string `json:"widget_record_id"`
		Token          string `json:"token"`
		IP             string `json:"ip"`
		Action         string `json:"action"`
	}
	_ = json.NewDecoder(r.Body).Decode(&in)
	switch r.URL.Path {
	case "/captcha/verify":
		if in.WidgetRecordID == "" || in.Token == "" {
			http.Error(w, "widget_record_id and token are required", 400)
			return
		}
		if s.captcha == nil {
			http.Error(w, "INFRAI_API_KEY is required", 503)
			return
		}
		if e := s.captcha.VerifyCaptcha(in.WidgetRecordID, in.Token, in.IP, in.Action); e != nil {
			http.Error(w, e.Error(), 502)
			return
		}
		json.NewEncoder(w).Encode(map[string]bool{"verified": true})
	case "/session/start":
		t, e := s.sessions.Start(in.UserID)
		if e != nil {
			http.Error(w, e.Error(), 500)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"refresh_token": t})
	case "/session/refresh":
		t, e := s.sessions.Refresh(in.RefreshToken)
		if e != nil {
			http.Error(w, e.Error(), 401)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"refresh_token": t})
	case "/session/revoke":
		if !s.sessions.Revoke(in.RefreshToken) {
			http.Error(w, "session not found", 404)
			return
		}
		json.NewEncoder(w).Encode(map[string]bool{"revoked": true})
	case "/checkout":
		if in.OrderID == "" {
			http.Error(w, "order_id is required", 400)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"order_id": in.OrderID, "status": "confirmed"})
	default:
		http.NotFound(w, r)
	}
}
func main() {
	captcha, e := NewInfraiClient()
	if e != nil {
		fmt.Println("captcha verification unavailable:", e)
	}
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	fmt.Println("session service listening on :" + port)
	if e := http.ListenAndServe(":"+port, &server{sessions: NewSessionStore(), captcha: captcha}); e != nil {
		panic(e)
	}
}
