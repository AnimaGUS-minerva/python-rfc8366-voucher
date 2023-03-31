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
test-pip-install: dist
	pipenv run pip install .
	#pipenv run pip install --force-reinstall ./dist/python_voucher-*.whl  # debug
	#pipenv run pip list  # debug
	pipenv run python ./tests/batch.py
	pipenv run pip uninstall -y python-voucher
test:
	make test-batch
	make test-pytest
	make test-pip-install

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
	make build-std -C $(VOUCHER_IF_CRATE_PATH)
	mkdir -p local
	mkdir -p local/lib && cp $(VOUCHER_IF_CRATE_PATH)/target/release/libvoucher_if.a local/lib/
	mkdir -p local/include && cp -r $(VOUCHER_IF_CRATE_PATH)/include/* local/include/

# exports for 'setup.py'
export C_INCLUDE_PATH := local/include
export LIBRARY_PATH := local/lib
export LD_LIBRARY_PATH := local/lib
export DYLD_LIBRARY_PATH := local/lib
export SETUP_MODULE_NAME := voucher
export SETUP_EXTENSION_LIBS := voucher_if

dist: local
	ls -lrt local/include local/lib
	pipenv run python ./setup.py bdist_wheel
	cd ./dist && \
		rm -rf voucher python_voucher-*info && \
		unzip python_voucher-*.whl && \
		ls -lrt
clean:
	rm -rf dist
purge:
	rm -rf dist build local ./src/*.egg-info
