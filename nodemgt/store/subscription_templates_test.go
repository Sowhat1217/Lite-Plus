package store

import (
	"testing"

	"github.com/nuomiiiii/lite/nodemgt/models"
	"github.com/stretchr/testify/require"
)

func TestLegacySubscriptionsMigrateWithoutEnablingAutoOrChangingToken(t *testing.T) {
	st := testDB(t)
	row := models.Subscription{UserID: "legacy-user", Format: "clash", Enabled: true}
	require.NoError(t, st.UpsertSubscription(&row))
	token := row.Token
	require.NoError(t, st.DB().Migrator().DropColumn(&models.Subscription{}, "AutoDetect"))
	require.NoError(t, st.Migrate())
	loaded, err := st.GetSubscriptionByToken(token)
	require.NoError(t, err)
	require.False(t, loaded.AutoDetect)
	require.Equal(t, "clash", loaded.Format)
	require.Equal(t, token, loaded.Token)
}

func TestTemplateBindingsCleanUpWithTheirOwners(t *testing.T) {
	for _, owner := range []string{"user", "subscription", "plan"} {
		t.Run(owner, func(t *testing.T) {
			st := testDB(t)
			user := models.NodeUser{NodeUUID: "n1", Username: owner}
			require.NoError(t, st.UpsertUser(&user))
			row, err := st.EnsureSubscription(user.ID)
			require.NoError(t, err)
			tpl := models.SubscriptionTemplate{Name: "test", Kind: "clash", Content: "proxies: []\n"}
			require.NoError(t, st.UpsertSubscriptionTemplate(&tpl))
			binding := models.SubscriptionTemplateBinding{Scope: "subscription", ScopeID: row.ID, Client: "mihomo", TemplateID: tpl.ID}
			if owner == "plan" {
				plan := models.Plan{Name: "plan"}
				require.NoError(t, st.UpsertPlan(&plan))
				binding.Scope, binding.ScopeID = "plan", plan.ID
			}
			require.NoError(t, st.SetSubscriptionTemplateBinding(&binding))
			switch owner {
			case "user":
				require.NoError(t, st.DeleteUser(user.ID))
			case "subscription":
				require.NoError(t, st.DeleteSubscription(row.ID))
			case "plan":
				require.NoError(t, st.DeletePlan(binding.ScopeID))
			}
			bindings, err := st.ListSubscriptionTemplateBindings()
			require.NoError(t, err)
			require.Empty(t, bindings)
			require.NoError(t, st.DeleteSubscriptionTemplate(tpl.ID))
		})
	}
}
