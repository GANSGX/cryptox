#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BLUE}╔════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║   CryptoX Project Setup Script        ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════╝${NC}"
echo ""

# Check Node.js
if ! command -v node &> /dev/null; then
    echo -e "${RED}✗ Node.js is not installed${NC}"
    echo -e "  Please install Node.js 20+ from https://nodejs.org/"
    exit 1
fi
echo -e "${GREEN}✓ Node.js $(node --version) found${NC}"

# Check pnpm
if ! command -v pnpm &> /dev/null; then
    echo -e "${YELLOW}⚠️  pnpm not found. Installing...${NC}"
    npm install -g pnpm
    echo -e "${GREEN}✓ pnpm installed${NC}"
else
    echo -e "${GREEN}✓ pnpm $(pnpm --version) found${NC}"
fi

# Check Docker
if ! command -v docker &> /dev/null; then
    echo -e "${RED}✗ Docker is not installed${NC}"
    echo -e "  Please install Docker from https://www.docker.com/"
    exit 1
fi
echo -e "${GREEN}✓ Docker $(docker --version | cut -d ' ' -f 3 | tr -d ',') found${NC}"

# Check Docker Compose
if ! command -v docker-compose &> /dev/null; then
    echo -e "${RED}✗ Docker Compose is not installed${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Docker Compose found${NC}"

echo ""
echo -e "${BLUE}📦 Installing dependencies...${NC}"

# Install root dependencies (if exists)
if [ -f "package.json" ]; then
    pnpm install
fi

# Install server dependencies
echo -e "${BLUE}   → Installing server dependencies...${NC}"
cd server && pnpm install && cd ..
echo -e "${GREEN}   ✓ Server dependencies installed${NC}"

# Install client dependencies
echo -e "${BLUE}   → Installing client dependencies...${NC}"
cd client && pnpm install && cd ..
echo -e "${GREEN}   ✓ Client dependencies installed${NC}"

echo ""
echo -e "${BLUE}⚙️  Setting up environment files...${NC}"

# Setup server .env
if [ ! -f "server/.env" ]; then
    if [ -f "server/.env.example" ]; then
        cp server/.env.example server/.env
        echo -e "${GREEN}   ✓ Created server/.env${NC}"
        echo -e "${YELLOW}   ⚠️  Please edit server/.env and add your API keys${NC}"
    else
        echo -e "${YELLOW}   ⚠️  server/.env.example not found${NC}"
    fi
else
    echo -e "${GREEN}   ✓ server/.env already exists${NC}"
fi

# Setup client .env
if [ ! -f "client/.env" ]; then
    if [ -f "client/.env.example" ]; then
        cp client/.env.example client/.env
        echo -e "${GREEN}   ✓ Created client/.env${NC}"
    else
        echo -e "${YELLOW}   ⚠️  client/.env.example not found${NC}"
    fi
else
    echo -e "${GREEN}   ✓ client/.env already exists${NC}"
fi

echo ""
echo -e "${BLUE}🐳 Starting Docker containers...${NC}"
docker-compose up -d

# Wait for services
echo -e "${BLUE}⏳ Waiting for services to be healthy...${NC}"
sleep 5

# Check if PostgreSQL is ready
if docker exec cryptox_postgres pg_isready -U cryptox_user > /dev/null 2>&1; then
    echo -e "${GREEN}   ✓ PostgreSQL is ready${NC}"
else
    echo -e "${YELLOW}   ⚠️  PostgreSQL is not ready yet${NC}"
fi

# Check if Redis is ready
if docker exec cryptox_redis redis-cli ping > /dev/null 2>&1; then
    echo -e "${GREEN}   ✓ Redis is ready${NC}"
else
    echo -e "${YELLOW}   ⚠️  Redis is not ready yet${NC}"
fi

echo ""
echo -e "${BLUE}🗄️  Running database migrations...${NC}"
cd server && pnpm migrate && cd ..
echo -e "${GREEN}   ✓ Migrations completed${NC}"

echo ""
echo -e "${GREEN}╔════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║   ✨ Setup Complete! ✨              ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════╝${NC}"
echo ""
echo -e "${BLUE}📝 Next steps:${NC}"
echo -e "   1. Edit ${YELLOW}server/.env${NC} with your API keys"
echo -e "   2. Run ${GREEN}pnpm dev:all${NC} to start development"
echo -e "   3. Open ${BLUE}http://localhost:5173${NC} in your browser"
echo ""
echo -e "${BLUE}🔗 Useful commands:${NC}"
echo -e "   ${GREEN}pnpm dev:all${NC}        - Start everything with hot reload"
echo -e "   ${GREEN}pnpm test${NC}            - Run tests"
echo -e "   ${GREEN}docker-compose logs -f${NC} - View logs"
echo ""
