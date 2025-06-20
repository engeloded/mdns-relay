# Common musl targets
COMMON_TARGETS := \
  x86_64-unknown-linux-musl \
  aarch64-unknown-linux-musl \
  armv7-unknown-linux-musleabihf \
  i686-unknown-linux-musl

TARGET ?= x86_64-unknown-linux-musl
BUILD_MODE ?= release
BIN_NAME := mdns-relay
VERSION := $(shell grep '^version' Cargo.toml | cut -d'"' -f2)
REGISTRY ?=
IMAGE_TAG_BASE := $(if $(REGISTRY),$(REGISTRY)/,)$(BIN_NAME)

# Target → rust-musl-cross image name
define map_target_to_image
$(if $(filter $(1),x86_64-unknown-linux-musl),x86_64-musl,\
$(if $(filter $(1),aarch64-unknown-linux-musl),aarch64-musl,\
$(if $(filter $(1),armv7-unknown-linux-musleabihf),armv7-musleabihf,\
$(if $(filter $(1),i686-unknown-linux-musl),i686-musl,\
$(error ❌ Unknown TARGET: $(1))))))
endef

# Target → Docker platform
define map_target_to_platform
$(if $(filter $(1),x86_64-unknown-linux-musl),linux/amd64,\
$(if $(filter $(1),aarch64-unknown-linux-musl),linux/arm64,\
$(if $(filter $(1),armv7-unknown-linux-musleabihf),linux/arm/v7,\
$(if $(filter $(1),i686-unknown-linux-musl),linux/386,\
$(error ❌ Unsupported target for Docker: $(1))))))
endef

# Extract Docker arch from platform string (e.g. linux/arm/v7 → arm)
define map_platform_to_arch
$(word 2,$(subst /, ,$(1)))
endef

# Extract Docker variant from platform string (e.g. linux/arm/v7 → v7)
define map_platform_to_variant
$(word 3,$(subst /, ,$(1)))
endef

TARGET_PLATFORMS := $(foreach t,$(COMMON_TARGETS),"$(t):$(call map_target_to_platform,$(t))")
IMAGE := messense/rust-musl-cross:$(strip $(call map_target_to_image,$(TARGET)))

CARGO_FLAGS := --locked --target $(TARGET)
ifeq ($(BUILD_MODE),debug)
    BUILD_DIR := debug
else
    CARGO_FLAGS += --release
    BUILD_DIR := release
endif

.PHONY: push push-manifest status install clean dist docker push-all docker-all build-all dist-all release all test lint strip show-targets help

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

show-targets: ## Show supported target architectures
	@echo "Supported Target Architectures:"
	@for target in $(COMMON_TARGETS); do echo "  $$target"; done

build-all: ## Build all supported targets
	@for target in $(COMMON_TARGETS); do \
		echo "Building $(BIN_NAME) for $$target ($(BUILD_MODE) mode)..."; \
		$(MAKE) build TARGET=$$target || exit 1; \
	done

dist-all: ## Build + package for all targets
	@for target in $(COMMON_TARGETS); do \
		echo "Creating dist for $$target..."; \
		$(MAKE) dist TARGET=$$target || exit 1; \
	done

docker-all: ## Build Docker images for all targets
	@for target in $(COMMON_TARGETS); do \
	  echo "Building Docker image for $$target..."; \
	  $(MAKE) docker TARGET=$$target || exit 1; \
	done

push-all: ## Push all built images for all targets
	@for target in $(COMMON_TARGETS); do \
	  echo "Pushing $$target..."; \
	  docker push $(IMAGE_TAG_BASE):$(VERSION)-$$target || exit 1; \
	  docker push $(IMAGE_TAG_BASE):latest-$$target || exit 1; \
	done

push-manifest: ## Create and push multi-arch manifest for :latest
	@echo "Creating multi-arch manifest for :latest..."
	docker manifest create --amend $(IMAGE_TAG_BASE):latest \
	$(foreach t,$(COMMON_TARGETS),$(IMAGE_TAG_BASE):latest-$(t))

	@echo "Annotating platforms..."
	@for pair in $(TARGET_PLATFORMS); do \
	  pair=$$(echo $$pair | tr -d '"'); \
	  t=$$(echo $$pair | cut -d: -f1); \
	  platform=$$(echo $$pair | cut -d: -f2); \
	  arch=$$(echo $$platform | cut -d/ -f2); \
	  variant=$$(echo $$platform | cut -d/ -f3); \
	  echo "Annotating $$t → arch=$$arch variant=$$variant"; \
	  if [ -n "$$arch" ]; then \
	    if [ -n "$$variant" ]; then \
	      docker manifest annotate $(IMAGE_TAG_BASE):latest $(IMAGE_TAG_BASE):latest-$$t --os linux --arch $$arch --variant $$variant; \
	    else \
	      docker manifest annotate $(IMAGE_TAG_BASE):latest $(IMAGE_TAG_BASE):latest-$$t --os linux --arch $$arch; \
	    fi; \
	  else \
	    echo "⚠️  Skipping $$t: failed to parse arch from $$platform"; \
	  fi; \
	done

	docker manifest push $(IMAGE_TAG_BASE):latest

release: test lint dist-all docker-all push-all push-manifest ## Full release process

all: test lint build dist ## Run tests, lint, build, and create dist

build: ## Build the binary for specified target
	@echo "Building $(BIN_NAME) for $(TARGET) ($(BUILD_MODE) mode)..."
	docker run --rm \
		-e RUSTFLAGS=--cfg=build_version=\"$(VERSION)\" \
		-v $$PWD:/app -w /app $(IMAGE) \
		cargo build $(CARGO_FLAGS)

test: ## Run tests
	@echo "Running tests..."
	docker run --rm -v $$PWD:/app -w /app $(IMAGE) \
		cargo test --target $(TARGET)

lint: ## Run clippy linter
	@echo "Running clippy..."
	docker run --rm -v $$PWD:/app -w /app $(IMAGE) \
		cargo clippy --target $(TARGET) -- -D warnings

strip: ## Strip debug symbols (release mode only)
ifeq ($(BUILD_MODE),release)
	@echo "Stripping debug symbols..."
	docker run --rm -v $$PWD:/app -w /app $(IMAGE) \
		musl-strip target/$(TARGET)/$(BUILD_DIR)/$(BIN_NAME)
else
	@echo "Skipping strip (debug mode)"
endif

dist: build strip ## Package build output
	@echo "Creating distribution package..."
	mkdir -p dist
	cp target/$(TARGET)/$(BUILD_DIR)/$(BIN_NAME) dist/$(BIN_NAME)-$(VERSION)-$(TARGET)
	cp etc/mdns-relay.toml dist/
	cp systemd/mdns-relay.service dist/
	cp docker-compose.yml dist/
	@echo "dist/$(BIN_NAME)-$(VERSION)-$(TARGET)"

docker: ## Build and tag Docker image for a specific TARGET
	@echo "Building Docker image for $(TARGET)..."
	docker buildx create --name mdns-builder --use --bootstrap 2>/dev/null || true
	docker buildx build \
		--platform $(call map_target_to_platform,$(TARGET)) \
		--build-arg VERSION=$(VERSION) \
		--build-arg TARGET=$(TARGET) \
		--build-arg BIN_NAME=$(BIN_NAME)-$(VERSION)-$(TARGET) \
		--tag $(IMAGE_TAG_BASE):$(VERSION)-$(TARGET) \
		--tag $(IMAGE_TAG_BASE):latest-$(TARGET) \
		--load .

push: ## Push Docker image for a specific TARGET
	@echo "Pushing $(TARGET)..."
	docker push $(IMAGE_TAG_BASE):$(VERSION)-$(TARGET)
	docker push $(IMAGE_TAG_BASE):latest-$(TARGET)

install: build ## Install binary locally (Linux + systemd)
	@echo "Installing $(BIN_NAME)..."
	sudo cp target/$(TARGET)/$(BUILD_DIR)/$(BIN_NAME) /usr/local/bin/
	sudo chmod +x /usr/local/bin/$(BIN_NAME)
	sudo cp etc/mdns-relay.toml /etc/
	sudo cp systemd/mdns-relay.service /etc/systemd/system/
	sudo systemctl daemon-reload
	@echo "Installed! Run: sudo systemctl enable --now mdns-relay"

clean: ## Clean build artifacts
	@echo "Cleaning..."
	rm -rf target dist

status: ## Show current build status
	@echo "Build Status:"
	@echo "  Target:        $(TARGET)"
	@echo "  Build Mode:    $(BUILD_MODE)"
	@echo "  Version:       $(VERSION)"
	@echo "  Docker Image:  $(BIN_NAME):$(VERSION)"
