package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCaptchaVerifyRoute(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/captcha/verify" || r.Method != http.MethodPost {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body["widget_record_id"] != "widget-1" || body["token"] != "token-1" {
			t.Errorf("missing required fields: %v", body)
		}
		w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()
	s := &server{sessions: NewSessionStore(), captcha: &InfraiClient{baseURL: upstream.URL, key: "test", http: upstream.Client()}}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/captcha/verify", strings.NewReader(`{"widget_record_id":"widget-1","token":"token-1"}`)))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"verified":true`) {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestRefreshRotationAndRevocation(t *testing.T) {
	tests := []struct {
		name string
		use  func(*SessionStore, string) error
		want bool
	}{
		{name: "old token is rejected after rotation", use: func(s *SessionStore, t string) error { _, e := s.Refresh(t); return e }, want: true},
		{name: "revoked token is rejected", use: func(s *SessionStore, t string) error { s.Revoke(t); _, e := s.Refresh(t); return e }, want: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := NewSessionStore()
			first, e := s.Start("customer-42")
			if e != nil {
				t.Fatal(e)
			}
			if _, e = s.Refresh(first); e != nil {
				t.Fatal(e)
			}
			if got := tc.use(s, first) != nil; got != tc.want {
				t.Fatalf("error=%v want=%v", got, tc.want)
			}
		})
	}
}
