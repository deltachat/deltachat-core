#!/bin/bash
set -e -x

## Compile wheels
for PYBIN in /opt/python/*/bin; do
    "${PYBIN}/pip" install cffi requests attrs six pytest
    "${PYBIN}/pip" wheel /io/python -w wheelhouse/
done

## Bundle external shared libraries into the wheels
for whl in wheelhouse/deltachat*.whl; do
    auditwheel repair "$whl" -w /io/python/wheelhouse/
done

## Install packages (and test)
for PYBIN in /opt/python/*/bin/; do
    "${PYBIN}/pip" install deltachat --no-index -f /io/python/wheelhouse
    # (cd "$HOME"; "${PYBIN}/pytest" /io/python/tests)
done
