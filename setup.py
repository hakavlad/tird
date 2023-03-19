from setuptools import find_packages, setup


def readme():
    with open('README.md', 'r') as f:
        return f.read()


NAME = 'tird'

setup(
    name=NAME,
    version='0.0.0',
    license='CC0',
    author='Alexey Avramov',
    author_email='hakavlad@gmail.com',
    description='File encryption and plausible deniability for multiple '
                'hidden files (user-driven fs in any byte arrays)',
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
    keywords='encryption',
    project_urls={
        'Homepage': 'https://github.com/hakavlad/tird',
        'Bug Tracker': 'https://github.com/hakavlad/tird/issues',
        'Documentation': 'https://github.com/hakavlad/tird/blob/main/README.md'
    },
    entry_points={'console_scripts': [
        '{} = {}.{}:main'.format(NAME, NAME, NAME),
    ]},
    python_requires='>=3.6'
)
