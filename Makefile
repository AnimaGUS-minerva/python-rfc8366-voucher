SHELL := /bin/bash

all: dist

doc:
	pipenv run make html -C docs

ci:
	pipenv install --dev
	make doc
	make test

PYTHON := LD_LIBRARY_PATH=../local/lib:$(LD_LIBRARY_PATH) pipenv run python
test-batch: dist
	cd ./dist && $(PYTHON) < ../tests/batch.py  # batch tests compatible with micropython
test-pytest: dist
	cd ./dist && $(PYTHON) -m pytest --collect-only --quiet ../tests/  # list tests
	cd ./dist && $(PYTHON) -m pytest ../tests/  # run tests

test-pip-install-local: dist
	# Install the wheel just built. Do not `pip install .` (that rebuilds via setup.py).
	pipenv run pip install --force-reinstall ./dist/python_voucher-*.whl
	pipenv run python ./tests/batch.py
	pipenv run pip uninstall -y python-voucher
test-pip-install-remote:
	pip3 install git+https://github.com/AnimaGUS-minerva/python-rfc8366-voucher

test:
	make test-batch
	make test-pytest
	make test-pip-install-local
	make test-pip-install-remote

#

get-voucher:
	[ -e "voucher/.git" ] || \
        (git submodule init voucher && git submodule update)
sync-voucher:
	git submodule update --remote voucher && \
        cd voucher && git checkout master && git pull

#

VOUCHER_IF_CRATE_PATH := ./voucher/if
local: get-voucher
	cd $(VOUCHER_IF_CRATE_PATH) && cargo build --lib --release --features std
	mkdir -p local
	mkdir -p local/lib && cp $(VOUCHER_IF_CRATE_PATH)/target/release/libvoucher_if.a local/lib/
	mkdir -p local/include && cp -r $(VOUCHER_IF_CRATE_PATH)/include/* local/include/

# PEP 517 frontend. --no-isolation uses the pipenv env (Cython is a dev dep).
# `python -m build` still packs an sdist first, so MANIFEST.in must graft local/.
#
# MANIFEST.in grafts local/. `python -m build` packs an sdist, then builds the
# wheel from that sdist, so without this the wheel build will not see libvoucher_if.a.
dist: local
	ls -lrt local/include local/lib
	pipenv run python -m build --wheel --no-isolation --outdir dist
	cd ./dist && \
		rm -rf voucher python_voucher-*info && \
		unzip -o python_voucher-*.whl && \
		ls -lrt
clean:
	rm -rf dist build
purge:
	rm -rf dist build local ./src/*.egg-info
