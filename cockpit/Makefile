.PHONY: all build check check-source test watch clean install-deps bootstrap-lock

all: build

install-deps:
	npm ci --no-audit --no-fund

# Development-only helper for a source tree that intentionally lacks a lockfile.
bootstrap-lock:
	npm install --package-lock-only --ignore-scripts --no-audit --no-fund

build:
	npm run build

check:
	npm run check
	npm test

check-source:
	npm run check:source
	npm test

test:
	npm test

watch:
	npm run watch

clean:
	rm -rf dist
