# Convenience wrapper for the Tutor LMS method_map lab.
WP_PORT ?= 8099
TARGET  ?= http://localhost:$(WP_PORT)

.PHONY: up down poc scope escalate logs

up:            ## start the lab and provision WordPress + Tutor LMS 4.0.4
	cd lab && WP_PORT=$(WP_PORT) docker compose up -d db wp
	cd lab && WP_PORT=$(WP_PORT) docker compose run --rm setup

down:          ## tear down the lab and delete volumes
	cd lab && WP_PORT=$(WP_PORT) docker compose down -v

poc:           ## run the read-only PoC (both routes, scope probe)
	python3 poc/tutor_methodmap_poc.py $(TARGET) --scope-probe

escalate:      ## run the account-creation escalation (writes a subscriber; delete it afterward)
	python3 poc/tutor_methodmap_poc.py $(TARGET) --create-user --i-understand-this-creates-a-user

logs:          ## follow WordPress container logs
	cd lab && WP_PORT=$(WP_PORT) docker compose logs -f wp
