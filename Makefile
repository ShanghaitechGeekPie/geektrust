.PHONY: web build

# Build the frontend into internal/webui/dist (requires Node 20+).
# The postbuild npm script restores dist/.gitkeep so plain `go build`
# keeps working on clean checkouts.
web:
	npm --prefix web ci
	npm --prefix web run build

# Full build: frontend + Go binary.
build: web
	go build -o geektrust ./cmd/geektrust
