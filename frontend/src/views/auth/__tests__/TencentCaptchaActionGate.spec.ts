import { defineComponent, h } from 'vue'
import { flushPromises, mount } from '@vue/test-utils'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import LoginView from '@/views/auth/LoginView.vue'

const loginMock = vi.fn()
const loginWindowsADMock = vi.fn()
const loginWithPasskeyMock = vi.fn()
const getPublicSettingsMock = vi.fn()
const startOAuthLoginMock = vi.fn()
const verifyActionMock = vi.fn()
const captchaResetMock = vi.fn()
const locationState = { href: 'http://localhost/login' }

vi.mock('vue-router', () => ({
  useRouter: () => ({
    currentRoute: { value: { query: {} } },
    push: vi.fn()
  })
}))

vi.mock('vue-i18n', async () => {
  const actual = await vi.importActual<typeof import('vue-i18n')>('vue-i18n')
  return {
    ...actual,
    useI18n: () => ({
      t: (key: string) => key
    })
  }
})

vi.mock('@/stores', () => ({
  useAuthStore: () => ({
    login: (...args: unknown[]) => loginMock(...args),
    loginWindowsAD: (...args: unknown[]) => loginWindowsADMock(...args),
    loginWithPasskey: (...args: unknown[]) => loginWithPasskeyMock(...args)
  }),
  useAppStore: () => ({
    showError: vi.fn(),
    showSuccess: vi.fn(),
    showWarning: vi.fn()
  })
}))

vi.mock('@/api/auth', async () => {
  const actual = await vi.importActual<typeof import('@/api/auth')>('@/api/auth')
  return {
    ...actual,
    getPublicSettings: (...args: unknown[]) => getPublicSettingsMock(...args),
    startOAuthLogin: (...args: unknown[]) => startOAuthLoginMock(...args),
    isTotp2FARequired: () => false,
    isWeChatWebOAuthEnabled: () => false
  }
})

const CaptchaChallengeStub = defineComponent({
  setup(_, { expose }) {
    expose({
      verifyAction: verifyActionMock,
      reset: captchaResetMock
    })
    return () => h('div')
  }
})

const OAuthButtonStub = defineComponent({
  emits: ['start'],
  setup(_, { emit }) {
    return () => h('button', {
      type: 'button',
      'data-testid': 'oauth-start',
      onClick: () => emit('start', {
        provider: 'github',
        params: { redirect: '/dashboard' }
      })
    })
  }
})

function mountLogin() {
  return mount(LoginView, {
    global: {
      stubs: {
        AuthLayout: { template: '<div><slot /><slot name="footer" /></div>' },
        RouterLink: true,
        TurnstileWidget: CaptchaChallengeStub,
        Icon: true,
        LoginAgreementPrompt: true,
        TotpLoginModal: true,
        EmailOAuthButtons: OAuthButtonStub,
        LinuxDoOAuthSection: true,
        DingTalkOAuthSection: true,
        OidcOAuthSection: true,
        WechatOAuthSection: true
      }
    }
  })
}

describe('Tencent captcha action gate', () => {
  beforeEach(() => {
    loginMock.mockReset()
    loginWindowsADMock.mockReset()
    loginWithPasskeyMock.mockReset()
    getPublicSettingsMock.mockReset()
    startOAuthLoginMock.mockReset()
    verifyActionMock.mockReset()
    captchaResetMock.mockReset()
    getPublicSettingsMock.mockResolvedValue({
      turnstile_enabled: false,
      turnstile_site_key: '',
      tencent_captcha_enabled: true,
      tencent_captcha_app_id: 'tencent-app-id',
      backend_mode_enabled: false,
      password_reset_enabled: false,
      passkey_enabled: true,
      github_oauth_enabled: true,
      google_oauth_enabled: false
    })
    loginMock.mockResolvedValue({})
    loginWindowsADMock.mockResolvedValue({})
    loginWithPasskeyMock.mockResolvedValue({})
    startOAuthLoginMock.mockResolvedValue({ authorize_url: 'https://github.example/authorize' })
    verifyActionMock.mockResolvedValue({ token: 'ticket-1', randstr: '@rand-1' })
    Object.defineProperty(window, 'PublicKeyCredential', {
      configurable: true,
      value: class PublicKeyCredential {}
    })
    locationState.href = 'http://localhost/login'
    Object.defineProperty(window, 'location', {
      configurable: true,
      value: locationState
    })
  })

  it('clicking login opens Tencent captcha before calling login', async () => {
    const wrapper = mountLogin()
    await flushPromises()
    await wrapper.get('#email').setValue('user@example.com')
    await wrapper.get('#password').setValue('secret-123')

    await wrapper.get('form').trigger('submit')
    await flushPromises()

    expect(verifyActionMock).toHaveBeenCalledOnce()
    expect(loginMock).toHaveBeenCalledWith(expect.objectContaining({
      tencent_captcha_ticket: 'ticket-1',
      tencent_captcha_randstr: '@rand-1'
    }))
  })

  it('does not call login when Tencent captcha is closed', async () => {
    verifyActionMock.mockResolvedValue(null)
    const wrapper = mountLogin()
    await flushPromises()
    await wrapper.get('#email').setValue('user@example.com')
    await wrapper.get('#password').setValue('secret-123')

    await wrapper.get('form').trigger('submit')
    await flushPromises()

    expect(verifyActionMock).toHaveBeenCalledOnce()
    expect(loginMock).not.toHaveBeenCalled()
  })

  it('does not open Tencent captcha when login form validation fails', async () => {
    const wrapper = mountLogin()
    await flushPromises()

    await wrapper.get('form').trigger('submit')
    await flushPromises()

    expect(verifyActionMock).not.toHaveBeenCalled()
    expect(loginMock).not.toHaveBeenCalled()
  })

  it('starts OAuth through the Tencent gate before navigating', async () => {
    const wrapper = mountLogin()
    await flushPromises()

    await wrapper.get('[data-testid="oauth-start"]').trigger('click')
    await flushPromises()

    expect(verifyActionMock).toHaveBeenCalledOnce()
    expect(startOAuthLoginMock).toHaveBeenCalledWith(
      { provider: 'github', params: { redirect: '/dashboard' } },
      {
        tencent_captcha_ticket: 'ticket-1',
        tencent_captcha_randstr: '@rand-1'
      }
    )
    expect(locationState.href).toBe('https://github.example/authorize')
    expect(captchaResetMock).toHaveBeenCalledOnce()
  })

  it('does not start OAuth when Tencent captcha is closed', async () => {
    verifyActionMock.mockResolvedValue(null)
    const wrapper = mountLogin()
    await flushPromises()

    await wrapper.get('[data-testid="oauth-start"]').trigger('click')
    await flushPromises()

    expect(startOAuthLoginMock).not.toHaveBeenCalled()
    expect(locationState.href).toBe('http://localhost/login')
  })

  it('passes a fresh Tencent proof to Passkey login', async () => {
    const wrapper = mountLogin()
    await flushPromises()

    await wrapper.get('button.btn-secondary.w-full').trigger('click')
    await flushPromises()

    expect(verifyActionMock).toHaveBeenCalledOnce()
    expect(loginWithPasskeyMock).toHaveBeenCalledWith({
      tencent_captcha_ticket: 'ticket-1',
      tencent_captcha_randstr: '@rand-1'
    })
    expect(captchaResetMock).toHaveBeenCalledOnce()
  })

  it('does not invoke Passkey when Tencent captcha is closed', async () => {
    verifyActionMock.mockResolvedValue(null)
    const wrapper = mountLogin()
    await flushPromises()

    await wrapper.get('button.btn-secondary.w-full').trigger('click')
    await flushPromises()

    expect(loginWithPasskeyMock).not.toHaveBeenCalled()
  })

  it.each([
    {
      provider: 'Tencent',
      settings: { tencent_captcha_enabled: true, tencent_captcha_app_id: 'tencent-app-id' },
      proof: { token: 'ticket-1', randstr: '@rand-1' },
      requestProof: { tencent_captcha_ticket: 'ticket-1', tencent_captcha_randstr: '@rand-1' }
    },
    {
      provider: 'Aliyun',
      settings: {
        aliyun_captcha_enabled: true,
        aliyun_captcha_scene_id: 'aliyun-scene-id',
        aliyun_captcha_prefix: 'aliyun-prefix'
      },
      proof: { token: 'aliyun-verify-param', randstr: '' },
      requestProof: { turnstile_token: 'aliyun-verify-param' }
    }
  ])('passes a fresh $provider proof to AD login', async ({ settings, proof, requestProof }) => {
    getPublicSettingsMock.mockResolvedValueOnce({
      ...settings,
      windows_ad_enabled: true,
      backend_mode_enabled: false,
      turnstile_enabled: false
    })
    verifyActionMock.mockResolvedValueOnce(proof)
    const wrapper = mountLogin()
    await flushPromises()
    const form = wrapper.get('form[aria-label="Windows AD"]')
    await form.get('input[type="text"]').setValue(' domain-user ')
    await form.get('input[type="password"]').setValue('domain-password')

    await form.trigger('submit')
    await flushPromises()

    expect(verifyActionMock).toHaveBeenCalledOnce()
    expect(loginWindowsADMock).toHaveBeenCalledWith(expect.objectContaining({
      username: 'domain-user', password: 'domain-password', ...requestProof
    }))
    expect(loginMock).not.toHaveBeenCalled()
    expect(captchaResetMock).toHaveBeenCalledOnce()
    expect(form.get<HTMLInputElement>('input[type="password"]').element.value).toBe('')
    wrapper.unmount()
  })

  it('submits AD login without loading or invoking captcha when all captcha providers are disabled', async () => {
    getPublicSettingsMock.mockResolvedValueOnce({
      windows_ad_enabled: true,
      backend_mode_enabled: false,
      turnstile_enabled: false,
      tencent_captcha_enabled: false,
      aliyun_captcha_enabled: false
    })
    const wrapper = mountLogin()
    await flushPromises()
    const form = wrapper.get('form[aria-label="Windows AD"]')
    await form.get('input[type="text"]').setValue('domain-user')
    await form.get('input[type="password"]').setValue('domain-password')

    await form.trigger('submit')
    await flushPromises()

    expect(wrapper.findComponent(CaptchaChallengeStub).exists()).toBe(false)
    expect(verifyActionMock).not.toHaveBeenCalled()
    expect(loginWindowsADMock).toHaveBeenCalledWith({
      username: 'domain-user',
      password: 'domain-password',
      turnstile_token: undefined,
      tencent_captcha_ticket: undefined,
      tencent_captcha_randstr: undefined
    })
    expect(loginMock).not.toHaveBeenCalled()
    wrapper.unmount()
  })

  it('does not submit AD credentials when the action captcha is cancelled', async () => {
    getPublicSettingsMock.mockResolvedValueOnce({
      windows_ad_enabled: true,
      tencent_captcha_enabled: true,
      tencent_captcha_app_id: 'tencent-app-id',
      turnstile_enabled: false,
      backend_mode_enabled: false
    })
    verifyActionMock.mockResolvedValueOnce(null)
    const wrapper = mountLogin()
    await flushPromises()
    const form = wrapper.get('form[aria-label="Windows AD"]')
    await form.get('input[type="text"]').setValue('domain-user')
    await form.get('input[type="password"]').setValue('domain-password')

    await form.trigger('submit')
    await flushPromises()

    expect(loginWindowsADMock).not.toHaveBeenCalled()
    expect(captchaResetMock).toHaveBeenCalledOnce()
    wrapper.unmount()
  })

  it.each(['modal', 'checkbox'])('requires agreement consent before AD login in %s mode', async (mode) => {
    localStorage.removeItem('sub2api_login_agreement_consent')
    getPublicSettingsMock.mockResolvedValueOnce({
      windows_ad_enabled: true,
      backend_mode_enabled: false,
      login_agreement_enabled: true,
      login_agreement_mode: mode,
      login_agreement_revision: 'ad-agreement-revision',
      login_agreement_documents: [{ id: 'terms', title: 'Terms' }]
    })
    const wrapper = mountLogin()
    await flushPromises()
    const form = wrapper.get('form[aria-label="Windows AD"]')

    expect(form.get('button[type="submit"]').attributes('disabled')).toBeDefined()
    await form.trigger('submit')
    await flushPromises()

    expect(verifyActionMock).not.toHaveBeenCalled()
    expect(loginWindowsADMock).not.toHaveBeenCalled()
    wrapper.unmount()
  })
})
