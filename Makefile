.PHONY: build up down test security ci clean act-list act-test act-repo

build:
	docker compose build

up:
	docker compose up -d --build

down:
	docker compose down --remove-orphans

test:
	docker compose run --rm ci test

security:
	docker compose run --rm ci security

ci:
	docker compose run --rm ci all

clean:
	docker compose down -v --remove-orphans

# GitHub Actions in Docker through nektos/act; settings live in .actrc.
act-list:
	act -l

# Contract tests need no token; the lint job calls the GitHub API.
act-test:
	act -W .github/workflows/ci-repo.yml -j test

act-repo:
	act -W .github/workflows/ci-repo.yml -s GITHUB_TOKEN="$${GITHUB_TOKEN:-$$(gh auth token 2>/dev/null)}"
