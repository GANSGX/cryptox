import { useEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { Pencil, Trash2 } from "lucide-react";
import "./ContextMenu.css";

export interface ContextMenuItem {
  label: string;
  onClick: () => void;
  icon?: "edit" | "delete";
  danger?: boolean;
  disabled?: boolean;
}

interface ContextMenuProps {
  x: number;
  y: number;
  items: ContextMenuItem[];
  onClose: () => void;
}

const IconMap = {
  edit: Pencil,
  delete: Trash2,
};

export function ContextMenu({ x, y, items, onClose }: ContextMenuProps) {
  const menuRef = useRef<HTMLDivElement>(null);
  const [position, setPosition] = useState({ x: 0, y: 0 });
  const [isPositioned, setIsPositioned] = useState(false);

  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (menuRef.current && !menuRef.current.contains(event.target as Node)) {
        onClose();
      }
    };

    const handleEscape = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        onClose();
      }
    };

    document.addEventListener("mousedown", handleClickOutside);
    document.addEventListener("keydown", handleEscape);

    return () => {
      document.removeEventListener("mousedown", handleClickOutside);
      document.removeEventListener("keydown", handleEscape);
    };
  }, [onClose]);

  // Simple positioning like in Telegram - right at cursor, adjust only if goes off-screen
  useEffect(() => {
    setIsPositioned(false);

    // Small delay to let menu render
    const timer = setTimeout(() => {
      if (!menuRef.current) return;

      const menu = menuRef.current;
      const rect = menu.getBoundingClientRect();
      const viewportWidth = window.innerWidth;
      const viewportHeight = window.innerHeight;

      const menuWidth = rect.width;
      const menuHeight = rect.height;
      const edgePadding = 80; // Отступ от краёв экрана

      // Умное позиционирование:
      // Если клик в правой половине экрана (свои сообщения) - меню слева
      // Если клик в левой половине экрана (сообщения оппонента) - меню справа
      const isRightSide = x > viewportWidth / 2;

      let finalX = isRightSide ? x - menuWidth - 20 : x + 20; // +20px отступ от курсора
      let finalY = y;

      // Дополнительная проверка близости к краям
      if (finalX + menuWidth > viewportWidth - edgePadding) {
        // Слишком близко к правому краю - сдвигаем ещё левее
        finalX = viewportWidth - menuWidth - edgePadding;
      }
      if (finalX < edgePadding) {
        // Слишком близко к левому краю - сдвигаем правее
        finalX = edgePadding;
      }

      // Проверка выхода за границы по Y
      if (finalY + menuHeight > viewportHeight) {
        finalY = y - menuHeight; // Show above cursor
      }

      // Safety: keep minimum padding from edges
      finalX = Math.max(20, Math.min(finalX, viewportWidth - menuWidth - 20));
      finalY = Math.max(20, Math.min(finalY, viewportHeight - menuHeight - 20));

      setPosition({ x: finalX, y: finalY });
      setIsPositioned(true);
    }, 0);

    return () => clearTimeout(timer);
  }, [x, y]);

  return createPortal(
    <div
      ref={menuRef}
      className="context-menu"
      style={{
        left: `${position.x}px`,
        top: `${position.y}px`,
        opacity: isPositioned ? 1 : 0,
        pointerEvents: isPositioned ? "auto" : "none",
      }}
      onClick={(e) => e.stopPropagation()}
    >
      {items.map((item, index) => {
        const Icon = item.icon ? IconMap[item.icon] : null;
        return (
          <button
            key={index}
            className={`context-menu-item ${item.danger ? "danger" : ""} ${item.disabled ? "disabled" : ""}`}
            onClick={() => {
              if (!item.disabled) {
                item.onClick();
                onClose();
              }
            }}
            disabled={item.disabled}
          >
            {Icon && (
              <span className="context-menu-icon">
                <Icon size={18} strokeWidth={2} />
              </span>
            )}
            <span className="context-menu-label">{item.label}</span>
          </button>
        );
      })}
    </div>,
    document.body,
  );
}
