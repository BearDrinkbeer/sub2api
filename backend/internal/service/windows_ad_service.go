package service

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/mail"
	"strings"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
	"github.com/go-ldap/ldap/v3"
)

type WindowsADUser struct {
	Subject     string
	Email       string
	Username    string
	DisplayName string
	Claims      map[string]any
}

type WindowsADAuthenticator interface {
	Authenticate(ctx context.Context, cfg config.WindowsADConfig, username, password string) (*WindowsADUser, error)
}

type LDAPWindowsADAuthenticator struct {
	DialTimeout time.Duration
}

func (a LDAPWindowsADAuthenticator) Authenticate(ctx context.Context, cfg config.WindowsADConfig, username, password string) (*WindowsADUser, error) {
	username = strings.TrimSpace(username)
	password = strings.TrimSpace(password)
	if !cfg.Enabled {
		return nil, infraerrors.Forbidden("WINDOWS_AD_DISABLED", "windows ad login is disabled")
	}
	if username == "" || password == "" {
		return nil, infraerrors.Unauthorized("INVALID_CREDENTIALS", "invalid username or password")
	}
	if strings.TrimSpace(cfg.URL) == "" || strings.TrimSpace(cfg.BaseDN) == "" {
		return nil, infraerrors.ServiceUnavailable("WINDOWS_AD_NOT_CONFIGURED", "windows ad login is not configured")
	}

	tlsConfig := &tls.Config{InsecureSkipVerify: cfg.SkipTLSVerify}
	conn, err := ldap.DialURL(strings.TrimSpace(cfg.URL), ldap.DialWithTLSConfig(tlsConfig))
	if err != nil {
		logWindowsADFailure("connect", cfg, "", err, nil)
		return nil, infraerrors.ServiceUnavailable("WINDOWS_AD_CONNECT_FAILED", "failed to connect windows ad").WithCause(err)
	}
	defer func() { _ = conn.Close() }()
	conn.SetTimeout(firstPositiveDuration(a.DialTimeout, 5*time.Second))

	if cfg.StartTLS && !strings.HasPrefix(strings.ToLower(strings.TrimSpace(cfg.URL)), "ldaps://") {
		if err := conn.StartTLS(tlsConfig); err != nil {
			logWindowsADFailure("start_tls", cfg, "", err, nil)
			return nil, infraerrors.ServiceUnavailable("WINDOWS_AD_TLS_FAILED", "failed to start windows ad tls").WithCause(err)
		}
	}

	if bindDN := strings.TrimSpace(cfg.BindDN); bindDN != "" {
		if err := conn.Bind(bindDN, cfg.BindPassword); err != nil {
			logWindowsADFailure("service_bind", cfg, "", err, nil)
			return nil, infraerrors.ServiceUnavailable("WINDOWS_AD_BIND_FAILED", "failed to bind windows ad service account").WithCause(err)
		}
	}

	filter := buildWindowsADUserFilter(cfg.UserFilter, username)
	attrs := windowsADAttributes(cfg)
	searchBase := strings.TrimSpace(cfg.UserSearchBase)
	if searchBase == "" {
		searchBase = strings.TrimSpace(cfg.BaseDN)
	}
	req := ldap.NewSearchRequest(
		searchBase,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		2,
		10,
		false,
		filter,
		attrs,
		nil,
	)
	res, err := conn.Search(req)
	if err != nil {
		logWindowsADFailure("user_search", cfg, searchBase, err, map[string]any{
			"filter_template": normalizeWindowsADUserFilterTemplate(cfg.UserFilter),
		})
		return nil, infraerrors.Unauthorized("INVALID_CREDENTIALS", "invalid username or password").WithCause(err)
	}
	if len(res.Entries) != 1 {
		logWindowsADFailure("user_search_result", cfg, searchBase, nil, map[string]any{
			"entries":         len(res.Entries),
			"filter_template": normalizeWindowsADUserFilterTemplate(cfg.UserFilter),
		})
		return nil, infraerrors.Unauthorized("INVALID_CREDENTIALS", "invalid username or password")
	}
	entry := res.Entries[0]
	if err := conn.Bind(entry.DN, password); err != nil {
		logWindowsADFailure("user_bind", cfg, searchBase, err, map[string]any{
			"user_dn": entry.DN,
		})
		return nil, infraerrors.Unauthorized("INVALID_CREDENTIALS", "invalid username or password").WithCause(err)
	}

	user := windowsADUserFromEntry(cfg, entry, username)
	if user.Subject == "" {
		return nil, infraerrors.ServiceUnavailable("WINDOWS_AD_SUBJECT_MISSING", "windows ad user identity is missing")
	}
	return user, nil
}

func firstPositiveDuration(values ...time.Duration) time.Duration {
	for _, value := range values {
		if value > 0 {
			return value
		}
	}
	return 0
}

func buildWindowsADUserFilter(template, username string) string {
	template = normalizeWindowsADUserFilterTemplate(template)
	if template == "" {
		template = defaultWindowsADUserFilter
	}
	escaped := ldap.EscapeFilter(strings.TrimSpace(username))
	if strings.Contains(template, "{{username}}") {
		return strings.ReplaceAll(template, "{{username}}", escaped)
	}
	if strings.Contains(template, "{username}") {
		return strings.ReplaceAll(template, "{username}", escaped)
	}
	return fmt.Sprintf("(&(%s)(|(sAMAccountName=%s)(userPrincipalName=%s)))", template, escaped, escaped)
}

func normalizeWindowsADUserFilterTemplate(template string) string {
	template = strings.TrimSpace(template)
	if template == "" {
		return ""
	}
	return strings.ReplaceAll(template, "{{ username }}", "{{username}}")
}

func logWindowsADFailure(stage string, cfg config.WindowsADConfig, searchBase string, err error, extra map[string]any) {
	attrs := []any{
		"component", "service.windows_ad",
		"stage", stage,
		"url", strings.TrimSpace(cfg.URL),
		"base_dn", strings.TrimSpace(cfg.BaseDN),
		"user_search_base", strings.TrimSpace(searchBase),
		"start_tls", cfg.StartTLS,
	}
	if err != nil {
		attrs = append(attrs, "error", err.Error())
		if code, ok := windowsADLDAPResultCode(err); ok {
			attrs = append(attrs, "ldap_result_code", code)
		}
	}
	for key, value := range extra {
		attrs = append(attrs, key, value)
	}
	slog.Warn("windows_ad.authentication_failed", attrs...)
}

func windowsADLDAPResultCode(err error) (uint16, bool) {
	var ldapErr *ldap.Error
	if errors.As(err, &ldapErr) && ldapErr != nil {
		return ldapErr.ResultCode, true
	}
	return 0, false
}

func windowsADAttributes(cfg config.WindowsADConfig) []string {
	keys := []string{"dn", "objectGUID", "objectSid"}
	for _, value := range []string{cfg.IDAttribute, cfg.EmailAttribute, cfg.UsernameAttribute, cfg.DisplayAttribute, "mail", "userPrincipalName", "sAMAccountName", "displayName"} {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		seen := false
		for _, existing := range keys {
			if strings.EqualFold(existing, value) {
				seen = true
				break
			}
		}
		if !seen {
			keys = append(keys, value)
		}
	}
	return keys
}

func windowsADUserFromEntry(cfg config.WindowsADConfig, entry *ldap.Entry, fallbackUsername string) *WindowsADUser {
	emailAttr := firstNonEmpty(cfg.EmailAttribute, "mail")
	usernameAttr := firstNonEmpty(cfg.UsernameAttribute, "sAMAccountName")
	displayAttr := firstNonEmpty(cfg.DisplayAttribute, "displayName")
	idAttr := firstNonEmpty(cfg.IDAttribute, "objectGUID")
	email := strings.TrimSpace(entry.GetAttributeValue(emailAttr))
	username := firstNonEmpty(entry.GetAttributeValue(usernameAttr), entry.GetAttributeValue("userPrincipalName"), entry.GetAttributeValue("sAMAccountName"), fallbackUsername)
	displayName := firstNonEmpty(entry.GetAttributeValue(displayAttr), entry.GetAttributeValue("displayName"), username)
	subject := windowsADSubject(entry, idAttr)
	if email == "" || !looksLikeEmail(email) {
		email = windowsADSyntheticEmail(subject)
	}
	return &WindowsADUser{
		Subject:     subject,
		Email:       strings.ToLower(strings.TrimSpace(email)),
		Username:    username,
		DisplayName: displayName,
		Claims: map[string]any{
			"dn":           entry.DN,
			"username":     username,
			"display_name": displayName,
			"email":        strings.ToLower(strings.TrimSpace(email)),
		},
	}
}

func windowsADSubject(entry *ldap.Entry, idAttr string) string {
	if raw := entry.GetRawAttributeValue(idAttr); len(raw) > 0 {
		return strings.ToLower(idAttr) + ":" + hex.EncodeToString(raw)
	}
	if value := strings.TrimSpace(entry.GetAttributeValue(idAttr)); value != "" {
		return strings.ToLower(idAttr) + ":" + value
	}
	if raw := entry.GetRawAttributeValue("objectSid"); len(raw) > 0 {
		return "objectsid:" + hex.EncodeToString(raw)
	}
	if strings.TrimSpace(entry.DN) != "" {
		return "dn:" + strings.ToLower(strings.TrimSpace(entry.DN))
	}
	return ""
}

func looksLikeEmail(value string) bool {
	_, err := mail.ParseAddress(strings.TrimSpace(value))
	return err == nil
}

func windowsADSyntheticEmail(subject string) string {
	normalized := strings.NewReplacer(":", "-", "\\", "-", "/", "-", "@", "-").Replace(strings.ToLower(strings.TrimSpace(subject)))
	if normalized == "" {
		normalized = "unknown"
	}
	if len(normalized) > 180 {
		normalized = normalized[:180]
	}
	return normalized + WindowsADSyntheticEmailDomain
}

func (s *SettingService) GetWindowsADConfig(ctx context.Context) (config.WindowsADConfig, error) {
	if s == nil {
		return config.WindowsADConfig{}, infraerrors.ServiceUnavailable("CONFIG_NOT_READY", "config not loaded")
	}
	effective := config.WindowsADConfig{}
	if s.cfg != nil {
		effective = s.cfg.WindowsAD
	}
	keys := []string{
		SettingKeyWindowsADEnabled,
		SettingKeyWindowsADProviderName,
		SettingKeyWindowsADURL,
		SettingKeyWindowsADBaseDN,
		SettingKeyWindowsADUserSearchBase,
		SettingKeyWindowsADGroupSearchBase,
		SettingKeyWindowsADBindDN,
		SettingKeyWindowsADBindPassword,
		SettingKeyWindowsADUserFilter,
		SettingKeyWindowsADEmailAttribute,
		SettingKeyWindowsADUsernameAttribute,
		SettingKeyWindowsADDisplayAttribute,
		SettingKeyWindowsADIDAttribute,
		SettingKeyWindowsADStartTLS,
		SettingKeyWindowsADSkipTLSVerify,
	}
	settings, err := s.settingRepo.GetMultiple(ctx, keys)
	if err != nil {
		return config.WindowsADConfig{}, fmt.Errorf("get windows ad settings: %w", err)
	}
	effective.Enabled = boolSettingOrDefault(settings, SettingKeyWindowsADEnabled, false)
	effective.ProviderName = firstNonEmpty(settings[SettingKeyWindowsADProviderName], effective.ProviderName, defaultWindowsADProviderName)
	effective.URL = firstNonEmpty(settings[SettingKeyWindowsADURL], effective.URL)
	effective.BaseDN = firstNonEmpty(settings[SettingKeyWindowsADBaseDN], effective.BaseDN)
	effective.UserSearchBase = firstNonEmpty(settings[SettingKeyWindowsADUserSearchBase], effective.UserSearchBase, effective.BaseDN)
	effective.GroupSearchBase = firstNonEmpty(settings[SettingKeyWindowsADGroupSearchBase], effective.GroupSearchBase)
	effective.BindDN = firstNonEmpty(settings[SettingKeyWindowsADBindDN], effective.BindDN)
	effective.BindPassword = firstNonEmpty(settings[SettingKeyWindowsADBindPassword], effective.BindPassword)
	effective.UserFilter = firstNonEmpty(settings[SettingKeyWindowsADUserFilter], effective.UserFilter, defaultWindowsADUserFilter)
	effective.EmailAttribute = firstNonEmpty(settings[SettingKeyWindowsADEmailAttribute], effective.EmailAttribute, "mail")
	effective.UsernameAttribute = firstNonEmpty(settings[SettingKeyWindowsADUsernameAttribute], effective.UsernameAttribute, "sAMAccountName")
	effective.DisplayAttribute = firstNonEmpty(settings[SettingKeyWindowsADDisplayAttribute], effective.DisplayAttribute, "displayName")
	effective.IDAttribute = firstNonEmpty(settings[SettingKeyWindowsADIDAttribute], effective.IDAttribute, "objectGUID")
	effective.StartTLS = boolSettingOrDefault(settings, SettingKeyWindowsADStartTLS, effective.StartTLS)
	effective.SkipTLSVerify = boolSettingOrDefault(settings, SettingKeyWindowsADSkipTLSVerify, effective.SkipTLSVerify)
	return effective, nil
}
