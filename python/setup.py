import setuptools

def main():
    with open('README.rst') as fd:
        long_description = fd.read()

    setuptools.setup(
        name='deltachat',
        version='0.1',
        description='Python bindings for deltachat-core using CFFI',
        long_description = long_description,
        author='Delta Chat contributors',
        setup_requires=['cffi>=1.0.0'],
        install_requires=['cffi>=1.0.0', 'requests', 'attr'],
        packages=setuptools.find_packages('src'),
        package_dir={'': 'src'},
        cffi_modules=['src/deltachat/_build.py:ffibuilder'],
        classifiers=[
            'Development Status :: 3 - Alpha',
            'Intended Audience :: Developers',
            'License :: OSI Approved :: GNU General Public License (GPL)',
            'Programming Language :: Python :: 3',
            'Topic :: Communications :: Email',
            'Topic :: Software Development :: Libraries',
        ],
    )

if __name__ == "__main__":
    main()

