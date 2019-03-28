
set -x -e

# we use the python3.5 environment as the base environment 
/opt/python/cp35-cp35m/bin/pip install meson tox devpi-client

pushd /usr/bin

ln -s /opt/_internal/cpython-3.5.*/bin/meson 
ln -s /opt/_internal/cpython-3.5.*/bin/tox
ln -s /opt/_internal/cpython-3.5.*/bin/devpi

popd
