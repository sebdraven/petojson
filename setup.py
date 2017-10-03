#!/usr/bin/env python
# -*- coding: utf-8 -*-

# +----------------------------------------------------------------------------
# | Imports
# +----------------------------------------------------------------------------
from setuptools import setup

import release

# +----------------------------------------------------------------------------
# | Definition of the scripts
# +----------------------------------------------------------------------------
scripts = [
    "petojson.py"
]


# +----------------------------------------------------------------------------
# | Definition of the dependencies
# +----------------------------------------------------------------------------
dependencies = []

extra_dependencies = {}

dependency_links = []

# +----------------------------------------------------------------------------
# | Extensions in the build operations (test)
# +----------------------------------------------------------------------------
CMD_CLASS = {

}

# Extract the long description from README.md
README = open('README.md', 'rt').read()

# +----------------------------------------------------------------------------
# | Definition of the setup
# +----------------------------------------------------------------------------
setup(
    name=release.name,
    packages=['peanalysis'],
    scripts=scripts,
    install_requires=dependencies,
    extras_require=extra_dependencies,
    dependency_links=dependency_links,
    version=release.version,
    license=release.licenseName,
    description=release.description,
    platforms=release.platforms,
    author=release.author,
    author_email=release.author_email,
    url=release.url,
    keywords=release.keywords,
    long_description=README,
    cmdclass=CMD_CLASS,
)
