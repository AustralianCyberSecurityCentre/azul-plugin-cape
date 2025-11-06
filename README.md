# Azul Plugin Cape

Submit binaries to CAPE dynamic analysis

## Development Installation

To install azul-plugin-cape for development run the command
(from the root directory of this project):

```bash
pip install -e .
```

## Usage

Usage on local files:

```
$ azul-plugin-cape malware.file
... example output goes here ...
```

Check `azul-plugin-cape --help` for advanced usage.

## Python Package management

This python package is managed using a `setup.py` and `pyproject.toml` file.

Standardisation of installing and testing the python package is handled through tox.
Tox commands include:

```bash
# Run all standard tox actions
tox
# Run linting only
tox -e style
# Run tests only
tox -e test
```

## Dependency management

Dependencies are managed in the requirements.txt, requirements_test.txt and debian.txt file.

The requirements files are the python package dependencies for normal use and specific ones for tests
(e.g pytest, black, flake8 are test only dependencies).

The debian.txt file manages the debian dependencies that need to be installed on development systems and docker images.

Sometimes the debian.txt file is insufficient and in this case the Dockerfile may need to be modified directly to
install complex dependencies.
