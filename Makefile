build:
	docker compose -f docker/docker-compose.yml build

run:
	docker compose -f docker/docker-compose.yml up -d

shell:
	docker compose -f docker/docker-compose.yml exec neuralkali-agent /bin/bash

test:
	python -m pytest -q

clean:
	docker compose -f docker/docker-compose.yml down --rmi local --volumes --remove-orphans
