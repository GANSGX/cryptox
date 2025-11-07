import { X } from 'lucide-react'
import { useState, useEffect } from 'react'
import { createPortal } from 'react-dom'
import { useAuthStore } from '@/store/authStore'
import { apiService } from '@/services/api.service'
import './ChangeEmailModal.css'

interface ChangeEmailModalProps {
    isOpen: boolean
    onClose: () => void
    onSuccess: () => void
}

type Step = 'password' | 'verify-current' | 'new-email'

export function ChangeEmailModal({ isOpen, onClose, onSuccess }: ChangeEmailModalProps) {
    const { user } = useAuthStore()

    const [step, setStep] = useState<Step>('password')
    const [isMounted, setIsMounted] = useState(false)
    const [isAnimated, setIsAnimated] = useState(false)

    const [password, setPassword] = useState('')
    const [code, setCode] = useState('')
    const [newEmail, setNewEmail] = useState('')

    const [isLoading, setIsLoading] = useState(false)
    const [error, setError] = useState('')

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
                // Сброс состояния при закрытии
                setStep('password')
                setPassword('')
                setCode('')
                setNewEmail('')
                setError('')
            }, 300)
            return () => clearTimeout(timer)
        }
    }, [isOpen, isMounted])

    if (!isMounted) return null

    // Шаг 1: Проверка пароля
    const handlePasswordSubmit = async (e: React.FormEvent) => {
        e.preventDefault()
        setError('')
        setIsLoading(true)

        try {
            // TODO: API запрос на проверку пароля и отправку кода на текущую почту
            const response = await apiService.verifyPasswordAndSendCode(user!.username, password)

            if (response.success) {
                setStep('verify-current')
            } else {
                setError(response.error || 'Invalid password')
            }
        } catch (error) {
            setError('Network error')
        } finally {
            setIsLoading(false)
        }
    }

    // Шаг 2: Проверка кода с текущей почты
    const handleCodeSubmit = async (e: React.FormEvent) => {
        e.preventDefault()
        setError('')
        setIsLoading(true)

        try {
            // TODO: API запрос на проверку кода
            const response = await apiService.verifyCurrentEmailCode(user!.username, code)

            if (response.success) {
                setStep('new-email')
            } else {
                setError(response.error || 'Invalid code')
            }
        } catch (error) {
            setError('Network error')
        } finally {
            setIsLoading(false)
        }
    }

    // Шаг 3: Изменение почты
    const handleNewEmailSubmit = async (e: React.FormEvent) => {
        e.preventDefault()
        setError('')
        setIsLoading(true)

        try {
            // TODO: API запрос на изменение почты
            const response = await apiService.changeEmail(user!.username, newEmail)

            if (response.success) {
                onSuccess()
                onClose()
            } else {
                setError(response.error || 'Failed to change email')
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
                    <form onSubmit={handlePasswordSubmit} className="change-email-form">
                        <div className="change-email-step-info">
                            <h3>Verify Your Identity</h3>
                            <p>Enter your password to continue</p>
                        </div>

                        <div className="change-email-current">
                            <span className="change-email-label">Current email:</span>
                            <span className="change-email-value">{user?.email}</span>
                        </div>

                        {error && <div className="change-email-error">{error}</div>}

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

                        <div className="change-email-actions">
                            <button type="button" className="settings-btn settings-btn-secondary" onClick={onClose}>
                                Cancel
                            </button>
                            <button type="submit" className="settings-btn settings-btn-primary" disabled={isLoading || !password}>
                                {isLoading ? 'Verifying...' : 'Continue'}
                            </button>
                        </div>
                    </form>
                )

            case 'verify-current':
                return (
                    <form onSubmit={handleCodeSubmit} className="change-email-form">
                        <div className="change-email-step-info">
                            <h3>Verify Current Email</h3>
                            <p>We sent a 6-digit code to <strong>{user?.email}</strong></p>
                        </div>

                        {error && <div className="change-email-error">{error}</div>}

                        <div className="form-group">
                            <label className="form-label">Verification Code</label>
                            <input
                                type="text"
                                className="form-input"
                                value={code}
                                onChange={(e) => setCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                                placeholder="000000"
                                maxLength={6}
                                disabled={isLoading}
                                autoFocus
                            />
                        </div>

                        <div className="change-email-actions">
                            <button type="button" className="settings-btn settings-btn-secondary" onClick={() => setStep('password')}>
                                Back
                            </button>
                            <button type="submit" className="settings-btn settings-btn-primary" disabled={isLoading || code.length !== 6}>
                                {isLoading ? 'Verifying...' : 'Verify'}
                            </button>
                        </div>
                    </form>
                )

            case 'new-email':
                return (
                    <form onSubmit={handleNewEmailSubmit} className="change-email-form">
                        <div className="change-email-step-info">
                            <h3>Enter New Email</h3>
                            <p>Your new email will need to be verified</p>
                        </div>

                        {error && <div className="change-email-error">{error}</div>}

                        <div className="form-group">
                            <label className="form-label">New Email Address</label>
                            <input
                                type="email"
                                className="form-input"
                                value={newEmail}
                                onChange={(e) => setNewEmail(e.target.value.toLowerCase())}
                                placeholder="newemail@example.com"
                                disabled={isLoading}
                                autoFocus
                            />
                        </div>

                        <div className="change-email-actions">
                            <button type="button" className="settings-btn settings-btn-secondary" onClick={() => setStep('verify-current')}>
                                Back
                            </button>
                            <button type="submit" className="settings-btn settings-btn-primary" disabled={isLoading || !newEmail}>
                                {isLoading ? 'Changing...' : 'Change Email'}
                            </button>
                        </div>
                    </form>
                )
        }
    }

    return createPortal(
        <>
            {/* Overlay */}
            <div
                className={`change-email-overlay ${isAnimated ? 'visible' : ''}`}
                onClick={onClose}
            />

            {/* Modal */}
            <div className={`change-email-modal ${isAnimated ? 'open' : ''}`}>
                {/* Header */}
                <div className="change-email-header">
                    <h2>Change Email</h2>
                    <button className="change-email-close" onClick={onClose}>
                        <X size={24} />
                    </button>
                </div>

                {/* Content */}
                <div className="change-email-content">
                    {renderStep()}
                </div>
            </div>
        </>,
        document.body
    )
}