#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${BLUE}🚀 Starting CryptoX Development Environment${NC}"
echo ""

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo -e "${YELLOW}⚠️  Docker is not running. Please start Docker and try again.${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Docker is running${NC}"

# Check if .env files exist
if [ ! -f "server/.env" ]; then
    echo -e "${YELLOW}⚠️  server/.env not found. Creating from example...${NC}"
    if [ -f "server/.env.example" ]; then
        cp server/.env.example server/.env
        echo -e "${GREEN}✓ Created server/.env${NC}"
    else
        echo -e "${YELLOW}⚠️  Please create server/.env manually${NC}"
    fi
fi

if [ ! -f "client/.env" ]; then
    echo -e "${YELLOW}⚠️  client/.env not found. Creating from example...${NC}"
    if [ -f "client/.env.example" ]; then
        cp client/.env.example client/.env
        echo -e "${GREEN}✓ Created client/.env${NC}"
    else
        echo -e "${YELLOW}⚠️  Please create client/.env manually${NC}"
    fi
fi

echo ""
echo -e "${BLUE}🐳 Starting Docker containers...${NC}"

# Start Docker Compose
docker-compose -f docker-compose.dev.yml up --build

# Note: Use Ctrl+C to stop
