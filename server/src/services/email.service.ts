import { Resend } from 'resend'
import { env } from '../config/env.js'

const resend = new Resend(env.RESEND_API_KEY)

export class EmailService {
  /**
   * Отправка кода подтверждения email
   */
  static async sendVerificationCode(email: string, code: string): Promise<boolean> {
    try {
      // В development режиме можно отправлять только на подтверждённый домен
      // Resend требует верификацию домена для production
      const { error } = await resend.emails.send({
        from: 'CryptoX <onboarding@resend.dev>', // Используем тестовый домен Resend
        to: email,
        subject: 'Подтверждение email в CryptoX',
        html: `
          <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <h2>🔐 Подтверждение email</h2>
            <p>Ваш код подтверждения:</p>
            <div style="background: #f4f4f4; padding: 20px; text-align: center; font-size: 32px; font-weight: bold; letter-spacing: 5px; margin: 20px 0;">
              ${code}
            </div>
            <p>Код действителен в течение 10 минут.</p>
            <p style="color: #666; font-size: 12px;">Если вы не регистрировались в CryptoX, проигнорируйте это письмо.</p>
          </div>
        `,
      })

      if (error) {
        console.error('Email send error:', error)
        return false
      }

      return true
    } catch (error) {
      console.error('Email service error:', error)
      return false
    }
  }

  /**
   * Отправка ссылки восстановления пароля (для будущего)
   */
  static async sendPasswordRecovery(email: string, token: string): Promise<boolean> {
    try {
      const recoveryLink = `${env.CORS_ORIGIN}/reset-password?token=${token}`

      const { error } = await resend.emails.send({
        from: 'CryptoX <onboarding@resend.dev>',
        to: email,
        subject: 'Восстановление пароля CryptoX',
        html: `
          <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <h2>🔑 Восстановление пароля</h2>
            <p>Вы запросили восстановление пароля.</p>
            <p>Перейдите по ссылке ниже:</p>
            <a href="${recoveryLink}" style="display: inline-block; background: #007bff; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; margin: 20px 0;">
              Восстановить пароль
            </a>
            <p>Ссылка действительна 1 час.</p>
            <p style="color: #666; font-size: 12px;">Если вы не запрашивали восстановление, проигнорируйте это письмо.</p>
          </div>
        `,
      })

      if (error) {
        console.error('Email send error:', error)
        return false
      }

      return true
    } catch (error) {
      console.error('Email service error:', error)
      return false
    }
  }
}