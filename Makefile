.PHONY: typecheck build test api-check package-check test-live

typecheck:
	pnpm typecheck

build:
	pnpm build

test:
	pnpm test

api-check:
	pnpm api:check

package-check:
	pnpm package:check

test-live:
	pnpm test:live
