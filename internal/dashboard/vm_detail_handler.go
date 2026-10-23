package dashboard

import (
	"database/sql"
	"net/http"

	"github.com/go-chi/chi/v5"
	dbpkg "github.com/skrashevich/svkexe/internal/db"
	"github.com/skrashevich/svkexe/ui"
)

// viewableVM resolves {id} to a VM the caller may look at: their own, or one
// shared with them. A shared VM comes back marked SharedAccess, which is what
// keeps the owner-only tabs and actions off its page.
func (d *Dashboard) viewableVM(w http.ResponseWriter, r *http.Request) *dbpkg.Container {
	user := userFromCtx(r.Context())
	if user == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return nil
	}
	c, err := d.db.GetContainerByID(chi.URLParam(r, "id"))
	if err == sql.ErrNoRows {
		http.Error(w, "VM not found", http.StatusNotFound)
		return nil
	}
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return nil
	}
	if c.OwnerID == user.ID {
		return c
	}
	if d.db.CanUseContainer(c.ID, user.ID) {
		c.SharedAccess = true
		return c
	}
	http.Error(w, "forbidden", http.StatusForbidden)
	return nil
}

// getVMDetail handles GET /dashboard/vms/{id} — the full VM page.
func (d *Dashboard) getVMDetail(w http.ResponseWriter, r *http.Request) {
	if c := d.viewableVM(w, r); c != nil {
		d.renderVMPage(w, r, c, "", "")
	}
}

// getVMCard handles GET /dashboard/vms/{id}/card — the page's own poll, so a
// VM that is starting or whose agent is working updates without a reload.
func (d *Dashboard) getVMCard(w http.ResponseWriter, r *http.Request) {
	if c := d.viewableVM(w, r); c != nil {
		d.render(w, r, "vm_card", d.cardData(c, ""))
	}
}

func (d *Dashboard) renderVMPage(w http.ResponseWriter, r *http.Request, c *dbpkg.Container, accessError, accessEmail string) {
	data := vmPageData{templateData: d.newData(r), Card: d.cardData(c, translateAccessError(ui.Resolve(r), accessError))}
	data.Card.AccessEmail = accessEmail
	data.Container = c
	d.renderPage(w, r, "vm.html", data)
}

func translateAccessError(lang, msg string) string {
	switch msg {
	case "":
		return ""
	case "enter a valid email address":
		return ui.T(lang, "access.err.email")
	case "enter one SSH public key without authorized_keys options":
		return ui.T(lang, "access.err.key")
	case "SSH certificates are not supported":
		return ui.T(lang, "access.err.cert")
	case "SSH key is already registered or could not be saved":
		return ui.T(lang, "access.err.save")
	case "existing account requires one of its already registered SSH keys":
		return ui.T(lang, "access.err.match")
	case "the owner already has access":
		return ui.T(lang, "access.err.owner")
	default:
		return msg
	}
}
