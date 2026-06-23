# cert-hub image — build & test entrypoints.
# Run from the repo root: `make <target>`.
IMAGE        ?= cert-hub:test
IMAGE_DIR    := $(CURDIR)
TESTS_DIR    := $(IMAGE_DIR)/tests
VENV         := $(TESTS_DIR)/.venv
PYTEST       ?= $(VENV)/bin/python -m pytest
PYTEST_FLAGS ?= -q

.PHONY: build venv test lint clean

## build: build the image as $(IMAGE)
build:
	docker build -t $(IMAGE) $(IMAGE_DIR)

$(VENV):
	python3 -m venv $(VENV)
	$(VENV)/bin/pip install -q -r $(TESTS_DIR)/requirements.txt

## venv: create the test virtualenv
venv: $(VENV)

## test: all unit tests (no docker)
test: venv
	cd $(TESTS_DIR) && $(PYTEST) $(PYTEST_FLAGS)

## lint: validate python syntax of CLI/app/package
lint: venv
	@echo "==> py_compile"; \
	$(VENV)/bin/python -m py_compile certhub.py wsgi.py gunicorn.conf.py $$(find cert_hub -name '*.py')
	@echo "  OK"

## clean: tear down scratch
clean:
	rm -rf $(VENV) $(TESTS_DIR)/.pytest_cache
