import { useState, useEffect } from "react";
import { apiService } from "@/services/api.service";
import { socketService } from "@/services/socket.service";

interface Session {
  id: string;
  device_info: Record<string, unknown>;
  ip_address: string;
  created_at: string;
  last_active: string;
  is_current: boolean;
  is_primary: boolean; // Главное устройство (первое, нельзя удалить)
  seconds_ago: number; // Разница в секундах, вычисленная на сервере
}

export function useSessions() {
  const [sessions, setSessions] = useState<Session[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState("");

  // Загрузка сессий
  const loadSessions = async () => {
    try {
      const response = await apiService.getSessions();

      if (response.success && response.sessions) {
        setSessions(response.sessions);
        setError("");
      } else {
        setError(response.error || "Failed to load sessions");
      }
    } catch {
      setError("Network error");
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    // Загружаем список при монтировании
    loadSessions();

    // WebSocket: обновление списка сессий
    const handleSessionsUpdated = () => {
      loadSessions();
    };

    // Подписываемся только на sessions:updated
    socketService.onSessionsUpdated(handleSessionsUpdated);

    // Отписываемся при размонтировании
    return () => {
      socketService.offSessionsUpdated(handleSessionsUpdated);
    };
  }, []);

  return {
    sessions,
    isLoading,
    error,
    reload: loadSessions,
  };
}
