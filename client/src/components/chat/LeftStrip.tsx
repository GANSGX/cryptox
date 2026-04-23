import { List } from "@phosphor-icons/react";

interface LeftStripProps {
  onBurgerClick: () => void;
}

export function LeftStrip({ onBurgerClick }: LeftStripProps) {
  return (
    <div className="left-strip">
      <button className="burger-button" onClick={onBurgerClick} title="Menu">
        <List size={24} />
      </button>
    </div>
  );
}
