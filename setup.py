from setuptools import find_packages, setup


def readme():
    with open('README.md', 'r') as file:
        return file.read()


NAME = 'tird'
VERSION = '0.6.0'

setup(
    name=NAME,
    version=VERSION,
    license='CC0',
    author='Alexey Avramov',
    author_email='hakavlad@gmail.com',
    description='A tool for encrypting file contents and hiding encrypted data'
                ' among random data',
    long_description=readme(),
    long_description_content_type='text/markdown',
    url='https://github.com/hakavlad/tird',
    packages=find_packages(),
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Environment :: Console',
        'License :: CC0 1.0 Universal (CC0 1.0) Public Domain Dedication',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3 :: Only',
        'Topic :: Security',
        'Topic :: Security :: Cryptography',
        'Topic :: Utilities'
    ],
    keywords='encryption hiding',
    project_urls={
        'Homepage': 'https://github.com/hakavlad/tird',
        'Bug Tracker': 'https://github.com/hakavlad/tird/issues',
        'Documentation': 'https://github.com/hakavlad/tird/blob/main/README.md'
    },
    entry_points={'console_scripts': [
        '{n} = {n}.{n}:main'.format(n=NAME),
    ]},
    python_requires='>=3.6',
    install_requires=[
        'pycryptodomex>=3.6.2',
        'pynacl>=1.2.0',
    ],
)
