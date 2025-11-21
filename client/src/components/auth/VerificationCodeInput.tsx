import { useRef, useEffect, KeyboardEvent, ClipboardEvent } from 'react'
import './VerificationCodeInput.css'

interface VerificationCodeInputProps {
  value: string
  onChange: (value: string) => void
  disabled?: boolean
  autoFocus?: boolean
}

export function VerificationCodeInput({
  value,
  onChange,
  disabled = false,
  autoFocus = false,
}: VerificationCodeInputProps) {
  const inputRefs = useRef<(HTMLInputElement | null)[]>([])

  const digits = value.padEnd(6, ' ').split('').slice(0, 6)

  useEffect(() => {
    if (autoFocus && inputRefs.current[0]) {
      inputRefs.current[0].focus()
    }
  }, [autoFocus])

  // Автоматический фокус на следующее поле при заполнении
  useEffect(() => {
    const currentLength = value.replace(/\s/g, '').length
    if (currentLength < 6 && inputRefs.current[currentLength]) {
      inputRefs.current[currentLength]?.focus()
    }
  }, [value])

  const handleChange = (index: number, inputValue: string) => {
    const digit = inputValue.replace(/\D/g, '').slice(-1) // Только последняя цифра

    if (digit) {
      const newDigits = [...digits]
      newDigits[index] = digit
      const newValue = newDigits.join('').replace(/\s/g, '')
      onChange(newValue)

      // Переход на следующее поле
      if (index < 5) {
        inputRefs.current[index + 1]?.focus()
      }
    }
  }

  const handleKeyDown = (index: number, e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Backspace') {
      e.preventDefault()

      const newDigits = [...digits]

      if (digits[index] !== ' ') {
        // Удаляем текущую цифру
        newDigits[index] = ' '
        onChange(newDigits.join('').replace(/\s/g, ''))
      } else if (index > 0) {
        // Переходим назад и удаляем предыдущую
        newDigits[index - 1] = ' '
        onChange(newDigits.join('').replace(/\s/g, ''))
        inputRefs.current[index - 1]?.focus()
      }
    } else if (e.key === 'ArrowLeft' && index > 0) {
      inputRefs.current[index - 1]?.focus()
    } else if (e.key === 'ArrowRight' && index < 5) {
      inputRefs.current[index + 1]?.focus()
    }
  }

  const handlePaste = (e: ClipboardEvent<HTMLInputElement>) => {
    e.preventDefault()
    const pastedData = e.clipboardData.getData('text').replace(/\D/g, '').slice(0, 6)
    onChange(pastedData)
  }

  return (
    <div className="verification-code-input">
      {digits.map((digit, index) => (
        <input
          key={index}
          ref={(el) => { inputRefs.current[index] = el }}
          type="text"
          inputMode="numeric"
          maxLength={1}
          value={digit === ' ' ? '' : digit}
          onChange={(e) => handleChange(index, e.target.value)}
          onKeyDown={(e) => handleKeyDown(index, e)}
          onPaste={handlePaste}
          disabled={disabled}
          className={`code-digit ${digit !== ' ' ? 'filled' : ''}`}
          autoComplete="off"
        />
      ))}
    </div>
  )
}
