package ui

import (
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	LangCookie = "svkexe_lang"
	LangEN     = "en"
	LangRU     = "ru"
)

// LangMaxAge is one year, the lifetime of the language cookie.
const LangMaxAge = 365 * 24 * 60 * 60

// Resolve returns the language for this request. A svkexe_lang cookie wins.
// Without one, Russian is used only when Accept-Language prefers ru.
func Resolve(r *http.Request) string {
	if r != nil {
		if c, err := r.Cookie(LangCookie); err == nil {
			if lang := Normalize(c.Value); lang != "" {
				return lang
			}
		}
		if prefersRussian(r.Header.Get("Accept-Language")) {
			return LangRU
		}
	}
	return LangEN
}

// Normalize returns en or ru, or empty when the value is not a supported language.
func Normalize(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case LangEN, "en-us", "en-gb":
		return LangEN
	case LangRU, "ru-ru":
		return LangRU
	default:
		return ""
	}
}

// T returns the string for key in lang. A missing or empty Russian value falls
// back to English. A key missing from both catalogs returns the key, never a blank.
func T(lang, key string) string {
	if lang == LangRU {
		if v := catalog[LangRU][key]; v != "" {
			return v
		}
	}
	if v := catalog[LangEN][key]; v != "" {
		return v
	}
	return key
}

// prefersRussian reports whether the highest-priority Accept-Language tag is Russian.
func prefersRussian(header string) bool {
	bestQ := -1.0
	best := ""
	order := 0
	bestOrder := 0
	for _, part := range strings.Split(header, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		tag, q := part, 1.0
		if i := strings.Index(part, ";"); i >= 0 {
			tag = strings.TrimSpace(part[:i])
			q = parseQ(part[i+1:])
		}
		tag = strings.ToLower(tag)
		if tag == "" || tag == "*" || q <= 0 {
			continue
		}
		order++
		if q > bestQ || (q == bestQ && order < bestOrder) {
			bestQ = q
			best = tag
			bestOrder = order
		}
	}
	return best == "ru" || strings.HasPrefix(best, "ru-")
}

func parseQ(param string) float64 {
	for _, p := range strings.Split(param, ";") {
		p = strings.TrimSpace(p)
		name, val, ok := strings.Cut(p, "=")
		if !ok || strings.TrimSpace(name) != "q" {
			continue
		}
		q, err := strconv.ParseFloat(strings.TrimSpace(val), 64)
		if err != nil || q < 0 {
			return 0
		}
		if q > 1 {
			return 1
		}
		return q
	}
	return 1
}

// SetLangCookie writes the language preference for one year.
func SetLangCookie(w http.ResponseWriter, lang string, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     LangCookie,
		Value:    lang,
		Path:     "/",
		MaxAge:   LangMaxAge,
		SameSite: http.SameSiteLaxMode,
		Secure:   secure,
		Expires:  time.Now().Add(time.Duration(LangMaxAge) * time.Second),
	})
}

// CatalogForTest sets one catalog entry. Tests use it to prove a missing
// Russian value falls back to English.
func CatalogForTest(lang, key, value string) {
	if catalog[lang] == nil {
		catalog[lang] = map[string]string{}
	}
	if value == "" {
		delete(catalog[lang], key)
		return
	}
	catalog[lang][key] = value
}
