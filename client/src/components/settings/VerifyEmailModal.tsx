import { X } from 'lucide-react'
import { useState, useEffect } from 'react'
import { createPortal } from 'react-dom'
import { useAuthStore } from '@/store/authStore'
import { apiService } from '@/services/api.service'
import './VerifyEmailModal.css'

interface VerifyEmailModalProps {
    isOpen: boolean
    onClose: () => void
    onSuccess: () => void
}

type Step = 'password' | 'code'

export function VerifyEmailModal({ isOpen, onClose, onSuccess }: VerifyEmailModalProps) {
    const { user } = useAuthStore()

    const [step, setStep] = useState<Step>('password')
    const [isMounted, setIsMounted] = useState(false)
    const [isAnimated, setIsAnimated] = useState(false)

    const [password, setPassword] = useState('')
    const [code, setCode] = useState('')

    const [isLoading, setIsLoading] = useState(false)
    const [error, setError] = useState('')
    const [cooldown, setCooldown] = useState(0)

    // Анимация монтирования
    useEffect(() => {
        if (isOpen) {
            setIsMounted(true)
            requestAnimationFrame(() => {
                requestAnimationFrame(() => {
                    setIsAnimated(true)
                })
            })
        } else if (isMounted) {
            setIsAnimated(false)
            const timer = setTimeout(() => {
                setIsMounted(false)
                setStep('password')
                setPassword('')
                setCode('')
                setError('')
                setCooldown(0)
            }, 300)
            return () => clearTimeout(timer)
        }
    }, [isOpen, isMounted])

    // Cooldown таймер
    useEffect(() => {
        if (cooldown > 0) {
            const timer = setTimeout(() => setCooldown(cooldown - 1), 1000)
            return () => clearTimeout(timer)
        }
    }, [cooldown])

    if (!isMounted) return null

    // Шаг 1: Проверка пароля и отправка кода
    const handlePasswordSubmit = async (e: React.FormEvent) => {
        e.preventDefault()
        setError('')
        setIsLoading(true)

        try {
            // Проверяем пароль через обычный login (но не сохраняем токен)
            const loginResponse = await apiService.login({
                username: user!.username,
                password: password
            })

            if (loginResponse.success) {
                // Пароль верный, отправляем код для верификации
                const sendResponse = await apiService.sendVerificationCode(user!.username)

                if (sendResponse.success) {
                    setStep('code')
                    setCooldown(30)
                } else {
                    setError(sendResponse.error || 'Failed to send code')
                }
            } else {
                setError('Invalid password')
            }
        } catch (error) {
            setError('Network error')
        } finally {
            setIsLoading(false)
        }
    }

    // Повторная отправка кода
    const handleResendCode = async () => {
        setError('')
        setIsLoading(true)

        try {
            const response = await apiService.sendVerificationCode(user!.username)

            if (response.success) {
                setCooldown(60)
            } else {
                setError(response.error || 'Failed to send code')
            }
        } catch (error) {
            setError('Network error')
        } finally {
            setIsLoading(false)
        }
    }

    // Шаг 2: Проверка кода
    const handleCodeSubmit = async (e: React.FormEvent) => {
        e.preventDefault()
        setError('')
        setIsLoading(true)

        try {
            const response = await apiService.verifyEmail(user!.username, code)

            if (response.success) {
                onSuccess()
                onClose()
            } else {
                setError(response.error || 'Invalid code')
            }
        } catch (error) {
            setError('Network error')
        } finally {
            setIsLoading(false)
        }
    }

    const renderStep = () => {
        switch (step) {
            case 'password':
                return (
                    <form onSubmit={handlePasswordSubmit} className="verify-email-form">
                        <div className="verify-email-info">
                            <div className="verify-email-icon">🔐</div>
                            <h3>Verify Your Identity</h3>
                            <p>Enter your password to receive a verification code</p>
                        </div>

                        <div className="verify-email-current">
                            <span className="verify-email-label">Email to verify:</span>
                            <span className="verify-email-value">{user?.email}</span>
                        </div>

                        {error && <div className="verify-email-error">{error}</div>}

                        <div className="form-group">
                            <label className="form-label">Password</label>
                            <input
                                type="password"
                                className="form-input"
                                value={password}
                                onChange={(e) => setPassword(e.target.value)}
                                placeholder="Enter your password"
                                disabled={isLoading}
                                autoFocus
                            />
                        </div>

                        <div className="verify-email-actions">
                            <button type="button" className="settings-btn settings-btn-secondary" onClick={onClose}>
                                Cancel
                            </button>
                            <button type="submit" className="settings-btn settings-btn-primary" disabled={isLoading || !password}>
                                {isLoading ? 'Sending...' : 'Send Code'}
                            </button>
                        </div>
                    </form>
                )

            case 'code':
                return (
                    <form onSubmit={handleCodeSubmit} className="verify-email-form">
                        <div className="verify-email-info">
                            <div className="verify-email-icon">📧</div>
                            <h3>Check your email</h3>
                            <p>We sent a 6-digit code to <strong>{user?.email}</strong></p>
                        </div>

                        {error && <div className="verify-email-error">{error}</div>}

                        <div className="form-group">
                            <label className="form-label">Verification Code</label>
                            <input
                                type="text"
                                className="form-input verify-code-input"
                                value={code}
                                onChange={(e) => setCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                                placeholder="000000"
                                maxLength={6}
                                disabled={isLoading}
                                autoFocus
                            />
                        </div>

                        <button
                            type="submit"
                            className="settings-btn settings-btn-primary verify-submit-btn"
                            disabled={isLoading || code.length !== 6}
                        >
                            {isLoading ? 'Verifying...' : 'Verify Email'}
                        </button>

                        <div className="verify-email-resend">
                            {cooldown > 0 ? (
                                <span className="resend-disabled">Resend code in {cooldown}s</span>
                            ) : (
                                <button
                                    type="button"
                                    className="resend-button"
                                    onClick={handleResendCode}
                                    disabled={isLoading}
                                >
                                    Resend code
                                </button>
                            )}
                        </div>

                        <button
                            type="button"
                            className="verify-back-button"
                            onClick={() => setStep('password')}
                        >
                            ← Back
                        </button>
                    </form>
                )
        }
    }

    return createPortal(
        <>
            {/* Overlay */}
            <div
                className={`verify-email-overlay ${isAnimated ? 'visible' : ''}`}
                onClick={onClose}
            />

            {/* Modal */}
            <div className={`verify-email-modal ${isAnimated ? 'open' : ''}`}>
                {/* Header */}
                <div className="verify-email-header">
                    <h2>Verify Email</h2>
                    <button className="verify-email-close" onClick={onClose}>
                        <X size={24} />
                    </button>
                </div>

                {/* Content */}
                <div className="verify-email-content">
                    {renderStep()}
                </div>
            </div>
        </>,
        document.body
    )
}