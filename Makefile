.PHONY: up down

DOCKER_COMPOSE := docker compose

up:
	@if [ -f docker-compose.yml ] || [ -f docker-compose.yaml ]; then \
		$(DOCKER_COMPOSE) up -d --build; \
		echo "Stack up."; \
	else \
		echo "ERROR: no docker-compose.yml found in repository. Nothing to start."; exit 1; \
	fi

down:
	@if [ -f docker-compose.yml ] || [ -f docker-compose.yaml ]; then \
		$(DOCKER_COMPOSE) down; \
	else \
		echo "Nothing to stop (no docker-compose.yml)."; \
	fi

.PHONY: run

run:
	sudo .venv/bin/sentinel run -c config/pulse.yaml
