import { createContext, useContext, useEffect, ReactNode } from 'react'

type Theme = 'dark'

interface ThemeContextType {
  theme: Theme
  toggleTheme: () => void
}

const ThemeContext = createContext<ThemeContextType | undefined>(undefined)

export function ThemeProvider({ children }: { children: ReactNode }) {
  const theme: Theme = 'dark' // Всегда тёмная тема

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', 'dark')
  }, [])

  const toggleTheme = () => {
    // Ничего не делаем, но функцию оставляем для совместимости
  }

  return (
    <ThemeContext.Provider value={{ theme, toggleTheme }}>
      {children}
    </ThemeContext.Provider>
  )
}

export function useTheme() {
  const context = useContext(ThemeContext)
  if (!context) {
    throw new Error('useTheme must be used within ThemeProvider')
  }
  return context
}