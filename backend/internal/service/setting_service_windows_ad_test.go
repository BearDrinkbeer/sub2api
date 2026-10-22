//go:build unit

package service

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/stretchr/testify/require"
)

func TestWindowsADEnabledRequiresDatabaseOptIn(t *testing.T) {
	for _, tt := range []struct {
		name          string
		configEnabled bool
		stored        map[string]string
		want          bool
	}{
		{name: "missing", configEnabled: true},
		{name: "missing_with_config_disabled"},
		{name: "empty", configEnabled: true, stored: map[string]string{SettingKeyWindowsADEnabled: ""}},
		{name: "disabled", configEnabled: true, stored: map[string]string{SettingKeyWindowsADEnabled: "false"}},
		{name: "malformed", configEnabled: true, stored: map[string]string{SettingKeyWindowsADEnabled: "TRUE"}},
		{name: "enabled", configEnabled: true, stored: map[string]string{SettingKeyWindowsADEnabled: "true"}, want: true},
		{name: "enabled_with_config_disabled", stored: map[string]string{SettingKeyWindowsADEnabled: "true"}, want: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			repo := newMockSettingRepo()
			for key, value := range tt.stored {
				repo.data[key] = value
			}
			svc := NewSettingService(repo, &config.Config{
				WindowsAD: config.WindowsADConfig{Enabled: tt.configEnabled, ProviderName: "Company AD"},
			})
			ctx := context.Background()
			admin, err := svc.GetAllSettings(ctx)
			require.NoError(t, err)
			actual, err := svc.GetWindowsADConfig(ctx)
			require.NoError(t, err)
			public, err := svc.GetPublicSettings(ctx)
			require.NoError(t, err)
			injection, err := svc.GetPublicSettingsForInjection(ctx)
			require.NoError(t, err)
			raw, err := json.Marshal(injection)
			require.NoError(t, err)
			var injected map[string]any
			require.NoError(t, json.Unmarshal(raw, &injected))

			require.Equal(t, tt.want, admin.WindowsADEnabled)
			require.Equal(t, tt.want, actual.Enabled)
			require.Equal(t, tt.want, public.WindowsADEnabled)
			require.Equal(t, tt.want, injected["windows_ad_enabled"])
			require.Equal(t, "Company AD", admin.WindowsADProviderName)
			require.Equal(t, "Company AD", public.WindowsADProviderName)
			require.Equal(t, "Company AD", injected["windows_ad_provider_name"])
		})
	}
}

func TestWindowsADInitializeDefaultsRemainDisabled(t *testing.T) {
	repo := newMockSettingRepo()
	repo.getValueErr = ErrSettingNotFound
	svc := NewSettingService(repo, &config.Config{WindowsAD: config.WindowsADConfig{Enabled: true}})
	require.NoError(t, svc.InitializeDefaultSettings(context.Background()))
	require.Equal(t, "false", repo.data[SettingKeyWindowsADEnabled])
	require.Equal(t, "Windows AD", repo.data[SettingKeyWindowsADProviderName])
	require.Equal(t, "5", repo.data[SettingKeyAuthSourceDefaultWindowsADConcurrency])
	require.Equal(t, "[]", repo.data[SettingKeyAuthSourceDefaultWindowsADSubscriptions])
	require.Equal(t, "false", repo.data[SettingKeyAuthSourceDefaultWindowsADGrantOnSignup])
	require.Equal(t, "false", repo.data[SettingKeyAuthSourceDefaultWindowsADGrantOnFirstBind])
}

func TestWindowsADBindPasswordPreservesWhitespace(t *testing.T) {
	for _, stored := range []string{"", " stored password "} {
		repo := newMockSettingRepo()
		if stored != "" {
			repo.data[SettingKeyWindowsADBindPassword] = stored
		}
		svc := NewSettingService(repo, &config.Config{
			WindowsAD: config.WindowsADConfig{BindPassword: " config password "},
		})
		cfg, err := svc.GetWindowsADConfig(context.Background())
		require.NoError(t, err)
		expected := stored
		if expected == "" {
			expected = " config password "
		}
		require.Equal(t, expected, cfg.BindPassword)
	}
}

func TestWindowsADDefaultGrantsRoundTripAndQuotaPatch(t *testing.T) {
	repo := newMockSettingRepo()
	svc := NewSettingService(repo, &config.Config{Default: config.DefaultConfig{UserConcurrency: 5}})
	ctx := context.Background()
	zero := 0.0
	grants := ProviderDefaultGrantSettings{
		Balance:          12.5,
		Concurrency:      7,
		Subscriptions:    []DefaultSubscriptionSetting{{GroupID: 41, ValidityDays: 30}},
		GrantOnSignup:    true,
		GrantOnFirstBind: true,
		PlatformQuotas:   map[string]*DefaultPlatformQuotaSetting{"openai": {DailyLimitUSD: &zero}},
	}
	require.NoError(t, svc.UpdateAuthSourceDefaultSettings(ctx, &AuthSourceDefaultSettings{WindowsAD: grants}))
	got, err := svc.GetAuthSourceDefaultSettings(ctx)
	require.NoError(t, err)
	require.Equal(t, grants, got.WindowsAD)
	for _, firstBind := range []bool{false, true} {
		resolved, enabled, err := svc.ResolveAuthSourceGrantSettings(ctx, "windows_ad", firstBind)
		require.NoError(t, err)
		require.True(t, enabled)
		require.Equal(t, grants.Balance, resolved.Balance)
		require.Equal(t, grants.Concurrency, resolved.Concurrency)
		require.Equal(t, grants.Subscriptions, resolved.Subscriptions)
	}

	grants.PlatformQuotas = nil
	require.NoError(t, svc.UpdateAuthSourceDefaultSettings(ctx, &AuthSourceDefaultSettings{WindowsAD: grants}))
	got, err = svc.GetAuthSourceDefaultSettings(ctx)
	require.NoError(t, err)
	require.Equal(t, 0.0, *got.WindowsAD.PlatformQuotas["openai"].DailyLimitUSD)

	grants.PlatformQuotas = map[string]*DefaultPlatformQuotaSetting{}
	require.NoError(t, svc.UpdateAuthSourceDefaultSettings(ctx, &AuthSourceDefaultSettings{WindowsAD: grants}))
	require.Equal(t, "{}", repo.data[SettingKeyAuthSourcePlatformQuotas("windows_ad")])
	got, err = svc.GetAuthSourceDefaultSettings(ctx)
	require.NoError(t, err)
	require.Empty(t, got.WindowsAD.PlatformQuotas)
}

func TestWindowsADDefaultGrantsValidateSubscriptionsAndQuotas(t *testing.T) {
	negative := -1.0
	for _, tt := range []struct {
		name   string
		grants ProviderDefaultGrantSettings
	}{
		{
			name: "duplicate_subscription",
			grants: ProviderDefaultGrantSettings{Subscriptions: []DefaultSubscriptionSetting{
				{GroupID: 41, ValidityDays: 7},
				{GroupID: 41, ValidityDays: 30},
			}},
		},
		{
			name: "unknown_platform",
			grants: ProviderDefaultGrantSettings{PlatformQuotas: map[string]*DefaultPlatformQuotaSetting{
				"unknown": {},
			}},
		},
		{
			name: "negative_limit",
			grants: ProviderDefaultGrantSettings{PlatformQuotas: map[string]*DefaultPlatformQuotaSetting{
				"openai": {DailyLimitUSD: &negative},
			}},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			repo := newMockSettingRepo()
			svc := NewSettingService(repo, &config.Config{})
			err := svc.UpdateAuthSourceDefaultSettings(context.Background(), &AuthSourceDefaultSettings{WindowsAD: tt.grants})
			require.Error(t, err)
			require.Empty(t, repo.data)
		})
	}
}
