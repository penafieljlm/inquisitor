try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

config = {
    'description': 'Google OSINT Tool',
    'author': 'John Lawrence M. Penafiel',
    'url': 'https://github.com/penafieljlm/inquisitor',
    'download_url': 'https://github.com/penafieljlm/inquisitor',
    'author_email': 'penafieljlm@gmail.com',
    'version': '0.1',
    'install_requires': [
        'cython',
        'google-api-python-client',
        'ipwhois',
        'netaddr',
        'nose',
        'python-whois',
        'shodan',
        'tabulate',
        'tld',
        'unidecode',
        'unqlite',
        'validate_email',
    ],
    'packages': ['inquisitor'],
    'scripts': ['inq'],
    'name': 'inquisitor'
}

setup(**config)