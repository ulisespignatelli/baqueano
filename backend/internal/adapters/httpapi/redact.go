package httpapi

import (
	"github.com/ulisespignatelli/baqueano/backend/internal/app"
	"github.com/ulisespignatelli/baqueano/backend/internal/domain"
	"github.com/ulisespignatelli/baqueano/backend/internal/notify"
)

// redact oculta los secretos de las organizaciones antes de responder: las URL de webhook son
// credenciales y no tienen por que volver al navegador. Copia: nunca toca lo guardado.
func redact(v any) any {
	switch x := v.(type) {
	case domain.Organization:
		return redactOrg(x)
	case app.Overview:
		x.Orgs = redactSummaries(x.Orgs)
		return x
	case []app.OrgSummary:
		return redactSummaries(x)
	case orgDetail:
		x.Organization = redactOrg(x.Organization)
		return x
	}
	return v
}

func redactSummaries(in []app.OrgSummary) []app.OrgSummary {
	out := make([]app.OrgSummary, len(in))
	for i, o := range in {
		o.Organization = redactOrg(o.Organization)
		out[i] = o
	}
	return out
}

func redactOrg(o domain.Organization) domain.Organization {
	if len(o.Alerts) == 0 {
		return o
	}
	alerts := make([]domain.Alert, len(o.Alerts))
	for i, a := range o.Alerts {
		a.Target = notify.Mask(a.Channel, a.Target)
		alerts[i] = a
	}
	o.Alerts = alerts
	return o
}
