=====
Pyark
=====

|Travis| |PyPi| |License|

.. |Travis| image:: https://img.shields.io/travis/adfinis-sygroup/pyark.svg?style=flat-square
   :target: https://travis-ci.org/adfinis-sygroup/pyark
.. |PyPi| image:: https://img.shields.io/pypi/v/pyark.svg?style=flat-square
   :target: https://pypi.python.org/pypi/pyark
.. |License| image:: https://img.shields.io/github/license/adfinis-sygroup/pyark.svg?style=flat-square
   :target: LICENSE

Pyark is a small python-based CLI tool, which allows you to interact with the
CyberArk Enterprise Password Vault API.

Features
========
Currently the following functionalities are supported:

* Get accounts
* Create accounts
* Delete accounts

Requirements
============
Make sure to have the following Python 3 dependencies installed before using the
tool:

* python-requests

Furthermore it's important to know which version of the CyberArk Password Vault
is used as only the newest versions expose all API endpoints. Make sure to
double check the API documentation, specific for your version, in case the tool
fails to interact with the API.

Installation
============
Simply clone this repository and start using the script. You can also install
it using setup.py or pip.

Examples
========
Get a list of available accounts:

.. code:: shell

   #TODO

Create a new account:

.. code:: shell

   #TODO

Delete an existing account:

.. code:: shell

   #TODO

Contributions
=============
Contributions are more than welcome! Please feel free to open new issues or
pull requests.

License 
=======
GNU GENERAL PUBLIC LICENSE Version 3

See the `LICENSE`_ file.

.. _LICENSE: LICENSE
