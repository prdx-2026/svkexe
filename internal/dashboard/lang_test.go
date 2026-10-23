package dashboard

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/skrashevich/svkexe/internal/ctxkeys"
	"github.com/skrashevich/svkexe/internal/db"
	"github.com/skrashevich/svkexe/ui"
)

func TestMissingCatalogKeyFallsBackToEnglish(t *testing.T) {
	const key = "probe.only_english"
	ui.CatalogForTest(ui.LangEN, key, "English only")
	ui.CatalogForTest(ui.LangRU, key, "")
	t.Cleanup(func() {
		ui.CatalogForTest(ui.LangEN, key, "")
		ui.CatalogForTest(ui.LangRU, key, "")
	})
	if got := ui.T(ui.LangRU, key); got != "English only" {
		t.Fatalf("missing Russian value rendered %q, want English", got)
	}
	if got := ui.T(ui.LangRU, "probe.absent"); got == "" {
		t.Fatal("missing key rendered a blank")
	}
}

func TestResolveLanguage(t *testing.T) {
	cases := []struct {
		cookie, accept, want string
	}{
		{"", "", ui.LangEN},
		{"", "en-US,en;q=0.9,ru;q=0.8", ui.LangEN},
		{"", "ru-RU,ru;q=0.9,en;q=0.8", ui.LangRU},
		{"", "fr-FR,fr;q=0.9", ui.LangEN},
		{"", "en;q=0.4, ru;q=0.9", ui.LangRU},
		{"en", "ru", ui.LangEN},
		{"ru", "en-US", ui.LangRU},
		{"zz", "ru", ui.LangRU},
	}
	for _, tc := range cases {
		r := httptest.NewRequest(http.MethodGet, "/vms", nil)
		if tc.cookie != "" {
			r.AddCookie(&http.Cookie{Name: ui.LangCookie, Value: tc.cookie})
		}
		if tc.accept != "" {
			r.Header.Set("Accept-Language", tc.accept)
		}
		if got := ui.Resolve(r); got != tc.want {
			t.Errorf("cookie %q accept %q: got %s, want %s", tc.cookie, tc.accept, got, tc.want)
		}
	}
}

func TestDashboardRendersEnglishByDefaultAndRussianFromCookie(t *testing.T) {
	database, err := db.Open(filepath.Join(t.TempDir(), "gateway.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	user := &db.User{ID: "u1", Email: "owner@example.com", Role: "admin"}
	if err := database.CreateUser(user); err != nil {
		t.Fatal(err)
	}
	d, err := NewDashboard(database, nil, nil, "example.com", []byte("01234567890123456789012345678901"), nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	router := chi.NewRouter()
	router.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxkeys.User, user)))
		})
	})
	d.RegisterRoutes(router)

	en := httptest.NewRequest(http.MethodGet, "/vms", nil)
	enw := httptest.NewRecorder()
	router.ServeHTTP(enw, en)
	if enw.Code != http.StatusOK {
		t.Fatalf("english page: %d %s", enw.Code, enw.Body.String())
	}
	body := enw.Body.String()
	for _, want := range []string{`<html lang="en"`, "Virtual machines", "Set up your first VM in three steps", "Nothing here yet"} {
		if !strings.Contains(body, want) {
			t.Errorf("english page missing %q", want)
		}
	}
	if strings.Contains(body, "Виртуальные машины") {
		t.Error("english page rendered Russian navigation")
	}

	ru := httptest.NewRequest(http.MethodGet, "/vms", nil)
	ru.AddCookie(&http.Cookie{Name: ui.LangCookie, Value: "ru"})
	ruw := httptest.NewRecorder()
	router.ServeHTTP(ruw, ru)
	if ruw.Code != http.StatusOK {
		t.Fatalf("russian page: %d %s", ruw.Code, ruw.Body.String())
	}
	rbody := ruw.Body.String()
	for _, want := range []string{`<html lang="ru"`, "Виртуальные машины", "Создайте первую VM за три шага", "Пока пусто"} {
		if !strings.Contains(rbody, want) {
			t.Errorf("russian page missing %q", want)
		}
	}

	past := time.Date(2020, 3, 2, 0, 0, 0, 0, time.UTC)
	if got := shortDate(ui.LangEN, past); got != "Mar 02, 2020" {
		t.Errorf("english date %q", got)
	}
	if got := shortDate(ui.LangRU, past); !strings.Contains(got, "мар") || !strings.Contains(got, "2020") {
		t.Errorf("russian date %q", got)
	}
}
