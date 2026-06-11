.PHONY: help build up down logs test shell clean

help:
	@echo "Available commands:"
	@echo "  make build   - Build Docker images"
	@echo "  make up      - Start all services"
	@echo "  make down    - Stop all services"
	@echo "  make logs    - View logs"
	@echo "  make test    - Run tests"
	@echo "  make shell   - Enter orchestrator container"
	@echo "  make clean   - Remove volumes and clean data"

build:
	docker-compose build

up:
	docker-compose up -d

down:
	docker-compose down

logs:
	docker-compose logs -f

test:
	docker-compose run --rm orchestrator pytest tests/ -v --cov=python

shell:
	docker-compose exec orchestrator /bin/bash

clean:
	docker-compose down -v
	rm -rf ./output/*