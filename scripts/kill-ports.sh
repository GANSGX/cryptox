#!/bin/bash

# Kill processes on ports used by CryptoX

echo "🔍 Checking for processes on ports..."

# Port 3001 (Server)
PID_3001=$(netstat -ano | grep ':3001' | grep 'LISTENING' | awk '{print $5}' | head -1)
if [ ! -z "$PID_3001" ]; then
    echo "  Killing process $PID_3001 on port 3001..."
    taskkill //F //PID $PID_3001 2>/dev/null || kill -9 $PID_3001 2>/dev/null
    echo "  ✅ Port 3001 cleared"
else
    echo "  ✅ Port 3001 is free"
fi

# Port 5173 (Client)
PID_5173=$(netstat -ano | grep ':5173' | grep 'LISTENING' | awk '{print $5}' | head -1)
if [ ! -z "$PID_5173" ]; then
    echo "  Killing process $PID_5173 on port 5173..."
    taskkill //F //PID $PID_5173 2>/dev/null || kill -9 $PID_5173 2>/dev/null
    echo "  ✅ Port 5173 cleared"
else
    echo "  ✅ Port 5173 is free"
fi

echo ""
echo "✨ All ports cleared! You can now run 'pnpm dev:all'"
