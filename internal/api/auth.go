package api

import (
	"database/sql"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	dbpkg "github.com/skrashevich/svkexe/internal/db"
	"github.com/skrashevich/svkexe/ui"
)

// SessionCookieName is the name of the cookie carrying the session token.
const SessionCookieName = "svkexe_session"

// bcryptCost tunes bcrypt work factor — 12 balances security and sub-100 ms
// login latency on modest hardware.
const bcryptCost = 12

// CookieSecure controls whether session cookies carry the Secure attribute.
// Set via the GATEWAY_COOKIE_SECURE env var in main.go. Defaults to false so
// local HTTP testing works; production deployments behind TLS should set it.
var CookieSecure = false

// CookieDomain sets the Domain attribute on session cookies. When set to
// ".example.com", the cookie is shared across all subdomains.
var CookieDomain string

// setSessionCookie writes an HttpOnly, SameSite=Lax session cookie.
func setSessionCookie(w http.ResponseWriter, token string, maxAgeSeconds int) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    token,
		Path:     "/",
		Domain:   CookieDomain,
		HttpOnly: true,
		Secure:   CookieSecure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   maxAgeSeconds,
	})
}

func clearSessionCookie(w http.ResponseWriter) {
	setSessionCookie(w, "", -1)
}

// pageData is the root context passed to the inline HTML templates.
type pageData struct {
	Title         string
	Error         string
	AllowRegister bool
	Email         string
	Lang          string
	Path          string
}

func authFuncs() template.FuncMap {
	return template.FuncMap{
		"t": ui.T,
	}
}

func authPage(r *http.Request, data pageData) pageData {
	data.Lang = ui.Resolve(r)
	if r.URL.RawQuery == "" {
		data.Path = r.URL.Path
	} else {
		data.Path = r.URL.Path + "?" + r.URL.RawQuery
	}
	return data
}

var loginTmpl = template.Must(template.New("login").Funcs(authFuncs()).Parse(`<!doctype html>
<html lang="{{.Lang}}"><head><meta charset="utf-8"><title>{{t .Lang "login.title"}}</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
  body{font-family:system-ui,sans-serif;background:#0f1115;color:#eee;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}
  .card{background:#1a1d24;padding:2rem;border-radius:8px;min-width:320px;box-shadow:0 4px 24px rgba(0,0,0,.4)}
  h1{margin:0 0 1rem;font-size:1.25rem}
  label{display:block;margin-top:.75rem;font-size:.9rem;color:#aaa}
  input{width:100%;box-sizing:border-box;padding:.5rem;margin-top:.25rem;background:#0f1115;color:#eee;border:1px solid #333;border-radius:4px}
  button{margin-top:1.25rem;width:100%;padding:.6rem;background:#3b82f6;color:#fff;border:0;border-radius:4px;font-weight:600;cursor:pointer}
  button:hover{background:#2563eb}
  .err{background:#3a1a1d;color:#f87171;padding:.5rem .75rem;border-radius:4px;margin-bottom:1rem;font-size:.9rem}
  a{color:#93c5fd;text-decoration:none;font-size:.85rem}
  .foot{margin-top:1rem;text-align:center}
  .langs{display:flex;gap:.5rem;justify-content:flex-end;margin:0 0 .75rem}
  .langs button{margin:0;width:auto;padding:.25rem .6rem;background:transparent;color:#aaa;border:1px solid #333;font-weight:600}
  .langs button.on{color:#fff;border-color:#93c5fd}
</style></head><body>
<form class="card" method="POST" action="/login">
  <div class="langs" role="group" aria-label="{{t .Lang "lang.switch"}}">
    <button type="submit" formaction="/lang" formnovalidate name="lang" value="en"{{if eq .Lang "en"}} class="on"{{end}}>EN</button>
    <button type="submit" formaction="/lang" formnovalidate name="lang" value="ru"{{if eq .Lang "ru"}} class="on"{{end}}>RU</button>
    <input type="hidden" name="next" value="{{.Path}}">
  </div>
  <h1>{{t .Lang "login.title"}}</h1>
  {{if .Error}}<div class="err">{{.Error}}</div>{{end}}
  <label>{{t .Lang "login.email"}} <input type="email" name="email" value="{{.Email}}" autofocus required></label>
  <label>{{t .Lang "login.password"}} <input type="password" name="password" required></label>
  <button type="submit">{{t .Lang "login.submit"}}</button>
  {{if .AllowRegister}}<div class="foot"><a href="/register">{{t .Lang "login.register"}}</a></div>{{end}}
</form>
</body></html>`))

var registerTmpl = template.Must(template.New("register").Funcs(authFuncs()).Parse(`<!doctype html>
<html lang="{{.Lang}}"><head><meta charset="utf-8"><title>{{t .Lang "reg.title"}}</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
  body{font-family:system-ui,sans-serif;background:#0f1115;color:#eee;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}
  .card{background:#1a1d24;padding:2rem;border-radius:8px;min-width:340px;box-shadow:0 4px 24px rgba(0,0,0,.4)}
  h1{margin:0 0 .25rem;font-size:1.25rem}
  .sub{margin:0 0 1rem;color:#888;font-size:.85rem}
  label{display:block;margin-top:.75rem;font-size:.9rem;color:#aaa}
  input{width:100%;box-sizing:border-box;padding:.5rem;margin-top:.25rem;background:#0f1115;color:#eee;border:1px solid #333;border-radius:4px}
  button{margin-top:1.25rem;width:100%;padding:.6rem;background:#10b981;color:#fff;border:0;border-radius:4px;font-weight:600;cursor:pointer}
  button:hover{background:#059669}
  .err{background:#3a1a1d;color:#f87171;padding:.5rem .75rem;border-radius:4px;margin-bottom:1rem;font-size:.9rem}
  .langs{display:flex;gap:.5rem;justify-content:flex-end;margin:0 0 .75rem}
  .langs button{margin:0;width:auto;padding:.25rem .6rem;background:transparent;color:#aaa;border:1px solid #333;font-weight:600}
  .langs button.on{color:#fff;border-color:#6ee7b7}
</style></head><body>
<form class="card" method="POST" action="/register">
  <div class="langs" role="group" aria-label="{{t .Lang "lang.switch"}}">
    <button type="submit" formaction="/lang" formnovalidate name="lang" value="en"{{if eq .Lang "en"}} class="on"{{end}}>EN</button>
    <button type="submit" formaction="/lang" formnovalidate name="lang" value="ru"{{if eq .Lang "ru"}} class="on"{{end}}>RU</button>
    <input type="hidden" name="next" value="{{.Path}}">
  </div>
  <h1>{{t .Lang "reg.title"}}</h1>
  <p class="sub">{{t .Lang "reg.sub"}}</p>
  {{if .Error}}<div class="err">{{.Error}}</div>{{end}}
  <label>{{t .Lang "login.email"}} <input type="email" name="email" value="{{.Email}}" autofocus required></label>
  <label>{{t .Lang "reg.password"}} <input type="password" name="password" minlength="8" required></label>
  <label>{{t .Lang "reg.confirm"}} <input type="password" name="password_confirm" minlength="8" required></label>
  <button type="submit">{{t .Lang "reg.submit"}}</button>
</form>
</body></html>`))

// loginGet renders the login form.
func (s *Server) loginGet(w http.ResponseWriter, r *http.Request) {
	allow, _ := s.noUsersYet()
	_ = loginTmpl.Execute(w, authPage(r, pageData{AllowRegister: allow}))
}

// loginPost validates credentials and issues a session cookie on success.
func (s *Server) loginPost(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	email := strings.TrimSpace(strings.ToLower(r.PostFormValue("email")))
	password := r.PostFormValue("password")

	fail := func(msg string) {
		w.WriteHeader(http.StatusUnauthorized)
		_ = loginTmpl.Execute(w, authPage(r, pageData{Error: msg, Email: email}))
	}

	user, err := s.db.GetUserByEmail(email)
	if errors.Is(err, sql.ErrNoRows) {
		// Run a dummy bcrypt compare to keep response time roughly constant —
		// harder to enumerate valid accounts via timing.
		_ = bcrypt.CompareHashAndPassword([]byte("$2a$12$zz................................................zz"), []byte(password))
		fail(ui.T(ui.Resolve(r), "login.bad"))
		return
	}
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if user.PasswordHash == "" {
		fail(ui.T(ui.Resolve(r), "login.no_pass"))
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		fail(ui.T(ui.Resolve(r), "login.bad"))
		return
	}

	sess, err := s.db.CreateSession(user.ID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	setSessionCookie(w, sess.Token, int(dbpkg.SessionTTL.Seconds()))

	http.Redirect(w, r, safeRedirectPath(r.URL.Query().Get("next")), http.StatusSeeOther)
}

// safeRedirectPath returns a same-origin relative path for post-login redirects.
// Rejects protocol-relative URLs (//evil.com) and backslash tricks.
func safeRedirectPath(next string) string {
	if next == "" {
		return "/dashboard/"
	}
	if !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") {
		return "/dashboard/"
	}
	if strings.Contains(next, "\\") {
		return "/dashboard/"
	}
	return next
}

// logoutPost invalidates the caller's session and clears the cookie.
func (s *Server) logoutPost(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(SessionCookieName); err == nil && c.Value != "" {
		_ = s.db.DeleteSession(c.Value)
	}
	clearSessionCookie(w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// registerGet renders the first-time admin creation form, or redirects to
// /login if a user already exists.
func (s *Server) registerGet(w http.ResponseWriter, r *http.Request) {
	allow, err := s.noUsersYet()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if !allow {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	_ = registerTmpl.Execute(w, authPage(r, pageData{}))
}

// registerPost creates the first admin account. Only works while the users
// table is empty; all subsequent users are provisioned via the admin API.
func (s *Server) registerPost(w http.ResponseWriter, r *http.Request) {
	allow, err := s.noUsersYet()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if !allow {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	email := strings.TrimSpace(strings.ToLower(r.PostFormValue("email")))
	password := r.PostFormValue("password")
	confirm := r.PostFormValue("password_confirm")

	fail := func(msg string) {
		w.WriteHeader(http.StatusBadRequest)
		_ = registerTmpl.Execute(w, authPage(r, pageData{Error: msg, Email: email}))
	}

	if !strings.Contains(email, "@") {
		fail(ui.T(ui.Resolve(r), "reg.email"))
		return
	}
	if len(password) < 8 {
		fail(ui.T(ui.Resolve(r), "reg.short"))
		return
	}
	if password != confirm {
		fail(ui.T(ui.Resolve(r), "reg.mismatch"))
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	user := &dbpkg.User{
		ID:           uuid.NewString(),
		Email:        email,
		Role:         "admin",
		PasswordHash: string(hash),
	}
	if err := s.db.CreateUser(user); err != nil {
		fail(fmt.Sprintf(ui.T(ui.Resolve(r), "reg.create"), err.Error()))
		return
	}
	sess, err := s.db.CreateSession(user.ID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	setSessionCookie(w, sess.Token, int(dbpkg.SessionTTL.Seconds()))
	http.Redirect(w, r, "/dashboard/", http.StatusSeeOther)
}

// noUsersYet returns true iff the users table is empty — used to gate the
// public /register flow.
func (s *Server) noUsersYet() (bool, error) {
	n, err := s.db.CountUsers()
	if err != nil {
		return false, err
	}
	return n == 0, nil
}

// postLang saves the operator language and returns to the same site.
func (s *Server) postLang(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	lang := ui.Normalize(r.PostFormValue("lang"))
	if lang == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	ui.SetLangCookie(w, lang, CookieSecure)
	http.Redirect(w, r, safeLangNext(r), http.StatusSeeOther)
}

func safeLangNext(r *http.Request) string {
	next := r.PostFormValue("next")
	if next == "" {
		next = r.FormValue("next")
	}
	if next == "" || !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") || strings.Contains(next, "\\") || strings.ContainsAny(next, "\r\n") {
		return "/login"
	}
	return next
}
