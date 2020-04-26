.PHONY: init build pre-build

PYTHON=/usr/bin/python3.8

init:
	${PYTHON} -m pip install -r requirements.txt

pre-build:
	${PYTHON} -m pip install setuptools wheel

build: init pre-build
	${PYTHON} setup.py bdist bdist_wheel

clean:
	rm -r ./build ./dist ./uctp.egg-info