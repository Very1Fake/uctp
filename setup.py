from setuptools import setup
import uctp

with open('README.md', 'r') as file:
    long_description = file.read()

setup(
    name='uctp',
    version=uctp.__version__,
    packages=['uctp'],
    url='https://github.com/Very1Fake/uctp',
    license='MIT',
    author='Timur Israpilov',
    author_email='very1fake.coder@gmail.com',
    description='Universal Command Transfer Protocol',
    long_description=long_description,
    long_description_content_type='text/markdown',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'License :: OSI Approved :: MIT License',
        'Intended Audience :: Developers',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python :: 3 :: Only',
        'Programming Language :: Python :: 3.8',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Topic :: System :: Networking'
    ],
    python_requires='>=3.8',
    install_requires=['pycryptodome>=3.9.7'],
    scripts=['bin/uctp'],
    include_package_data=True,
    zip_safe=False
)
