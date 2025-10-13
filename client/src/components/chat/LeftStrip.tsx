import { Menu } from 'lucide-react'

interface LeftStripProps {
  onBurgerClick: () => void
}

export function LeftStrip({ onBurgerClick }: LeftStripProps) {
  return (
    <div className="left-strip">
      <button 
        className="burger-button" 
        onClick={onBurgerClick}
        title="Menu"
      >
        <Menu size={24} />
      </button>
    </div>
  )
}