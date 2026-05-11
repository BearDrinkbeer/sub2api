package handler

import (
	"strings"

	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
	"github.com/Wei-Shaw/sub2api/internal/pkg/ip"
	"github.com/Wei-Shaw/sub2api/internal/pkg/response"
	"github.com/Wei-Shaw/sub2api/internal/service"

	"github.com/gin-gonic/gin"
)

type WindowsADLoginRequest struct {
	Username       string `json:"username" binding:"required"`
	Password       string `json:"password" binding:"required"`
	TurnstileToken string `json:"turnstile_token"`
	InvitationCode string `json:"invitation_code"`
	AffCode        string `json:"aff_code"`
}

// WindowsADLogin handles Windows Active Directory username/password login.
// POST /api/v1/auth/windows-ad/login
func (h *AuthHandler) WindowsADLogin(c *gin.Context) {
	var req WindowsADLoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "Invalid request: "+err.Error())
		return
	}
	if h == nil || h.settingSvc == nil || h.authService == nil {
		response.ErrorFrom(c, infraerrors.ServiceUnavailable("WINDOWS_AD_NOT_READY", "windows ad login is not ready"))
		return
	}
	if err := h.authService.VerifyTurnstile(c.Request.Context(), req.TurnstileToken, ip.GetClientIP(c)); err != nil {
		response.ErrorFrom(c, err)
		return
	}

	cfg, err := h.settingSvc.GetWindowsADConfig(c.Request.Context())
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	adUser, err := service.LDAPWindowsADAuthenticator{}.Authenticate(c.Request.Context(), cfg, req.Username, req.Password)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}

	tokenPair, user, err := h.authService.LoginOrRegisterVerifiedEmailOAuthWithInvitation(c.Request.Context(), service.EmailOAuthIdentityInput{
		ProviderType:    "windows_ad",
		ProviderKey:     strings.TrimSpace(cfg.BaseDN),
		ProviderSubject: adUser.Subject,
		Email:           adUser.Email,
		EmailVerified:   true,
		Username:        adUser.Username,
		DisplayName:     adUser.DisplayName,
		UpstreamMetadata: map[string]any{
			"provider_name": strings.TrimSpace(cfg.ProviderName),
			"ad_claims":     adUser.Claims,
		},
	}, req.InvitationCode, req.AffCode)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	_ = tokenPair

	if err := h.ensureBackendModeAllowsUser(c.Request.Context(), user); err != nil {
		response.ErrorFrom(c, err)
		return
	}
	if h.totpService != nil && h.settingSvc.IsTotpEnabled(c.Request.Context()) && user.TotpEnabled {
		tempToken, err := h.totpService.CreateLoginSession(c.Request.Context(), user.ID, user.Email)
		if err != nil {
			response.InternalError(c, "Failed to create 2FA session")
			return
		}
		response.Success(c, TotpLoginResponse{
			Requires2FA:     true,
			TempToken:       tempToken,
			UserEmailMasked: service.MaskEmail(user.Email),
		})
		return
	}
	h.authService.RecordSuccessfulLogin(c.Request.Context(), user.ID)
	h.respondWithTokenPair(c, user)
}
