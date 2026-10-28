package admin

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/pkg/response"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func TestSettingHandler_WindowsADPartialUpdatesAndSecretRedaction(t *testing.T) {
	gin.SetMode(gin.TestMode)
	repo := &settingHandlerRepoStub{values: map[string]string{}}
	svc := service.NewSettingService(repo, &config.Config{Default: config.DefaultConfig{UserConcurrency: 5}})
	handler := NewSettingHandler(svc, nil, nil, nil, nil, nil, nil)

	for _, tt := range []struct {
		name    string
		body    string
		enabled bool
		balance float64
		quotas  string
	}{
		{
			name: "save",
			body: `{
				"windows_ad_enabled": true,
				"windows_ad_provider_name": "Company AD",
				"windows_ad_url": "ldaps://ad.example.com:636",
				"windows_ad_base_dn": "DC=example,DC=com",
				"windows_ad_group_search_base": "OU=Groups,DC=example,DC=com",
				"windows_ad_bind_password": " directory-secret ",
				"auth_source_default_windows_ad_balance": 12.5,
				"auth_source_default_windows_ad_concurrency": 7,
				"auth_source_default_windows_ad_subscriptions": [{"group_id":41,"validity_days":30}],
				"auth_source_default_windows_ad_grant_on_signup": true,
				"auth_source_default_windows_ad_grant_on_first_bind": true,
				"auth_source_default_windows_ad_platform_quotas": {"openai":{"daily":0}}
			}`,
			enabled: true,
			balance: 12.5,
			quotas:  `{"openai":{"daily":0,"weekly":null,"monthly":null}}`,
		},
		{
			name:    "omitted",
			body:    `{"site_name":"Updated"}`,
			enabled: true,
			balance: 12.5,
			quotas:  `{"openai":{"daily":0,"weekly":null,"monthly":null}}`,
		},
		{
			name:    "blank_password",
			body:    `{"windows_ad_bind_password":"","auth_source_default_windows_ad_balance":10}`,
			enabled: true,
			balance: 10,
			quotas:  `{"openai":{"daily":0,"weekly":null,"monthly":null}}`,
		},
		{
			name:    "clear_quotas",
			body:    `{"auth_source_default_windows_ad_platform_quotas":{}}`,
			enabled: true,
			balance: 10,
			quotas:  `{}`,
		},
		{
			name:    "disable",
			body:    `{"windows_ad_enabled":false}`,
			balance: 10,
			quotas:  `{}`,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(rec)
			c.Request = httptest.NewRequest(http.MethodPut, "/api/v1/admin/settings", bytes.NewBufferString(tt.body))
			c.Request.Header.Set("Content-Type", "application/json")
			handler.UpdateSettings(c)
			require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
			require.Equal(t, " directory-secret ", repo.values[service.SettingKeyWindowsADBindPassword])
			require.JSONEq(t, tt.quotas, repo.values[service.SettingKeyAuthSourcePlatformQuotas("windows_ad")])
			require.Equal(t, "7", repo.values[service.SettingKeyAuthSourceDefaultWindowsADConcurrency])
			require.Equal(t, "true", repo.values[service.SettingKeyAuthSourceDefaultWindowsADGrantOnSignup])
			require.Equal(t, "true", repo.values[service.SettingKeyAuthSourceDefaultWindowsADGrantOnFirstBind])

			var payload response.Response
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &payload))
			data, ok := payload.Data.(map[string]any)
			require.True(t, ok)
			require.Equal(t, tt.enabled, data["windows_ad_enabled"])
			require.Equal(t, "Company AD", data["windows_ad_provider_name"])
			require.Equal(t, "OU=Groups,DC=example,DC=com", data["windows_ad_group_search_base"])
			require.Equal(t, true, data["windows_ad_bind_password_configured"])
			require.Equal(t, tt.balance, data["auth_source_default_windows_ad_balance"])
			require.Equal(t, float64(7), data["auth_source_default_windows_ad_concurrency"])
			require.NotContains(t, data, "windows_ad_bind_password")
			require.NotContains(t, rec.Body.String(), "directory-secret")
		})
	}
}

func TestSettingHandler_WindowsADAuditNamesChangesWithoutSecrets(t *testing.T) {
	zero := 0.0
	before := &service.SystemSettings{}
	after := &service.SystemSettings{WindowsADEnabled: true, WindowsADGroupSearchBase: "OU=Groups"}
	defaultsBefore := &service.AuthSourceDefaultSettings{}
	defaultsAfter := &service.AuthSourceDefaultSettings{
		WindowsAD: service.ProviderDefaultGrantSettings{
			Balance:        10,
			PlatformQuotas: map[string]*service.DefaultPlatformQuotaSetting{"openai": {DailyLimitUSD: &zero}},
		},
	}
	changed := diffSettings(before, after, defaultsBefore, defaultsAfter, UpdateSettingsRequest{WindowsADBindPassword: "directory-secret"})
	require.Contains(t, changed, service.SettingKeyWindowsADEnabled)
	require.Contains(t, changed, service.SettingKeyWindowsADGroupSearchBase)
	require.Contains(t, changed, service.SettingKeyWindowsADBindPassword)
	require.Contains(t, changed, service.SettingKeyAuthSourceDefaultWindowsADBalance)
	require.Contains(t, changed, service.SettingKeyAuthSourcePlatformQuotas("windows_ad"))
	require.NotContains(t, changed, "directory-secret")
}
