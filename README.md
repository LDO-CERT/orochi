# orochi
[![Black code style](https://img.shields.io/badge/code%20style-black-000000.svg)](http://shields.io/)
[![GitHub license](https://img.shields.io/github/license/LDO-CERT/orochi.svg)](https://github.com/LDO-CERT/orochi/blob/master/LICENSE)
[![Built with Cookiecutter Django](https://img.shields.io/badge/built%20with-Cookiecutter%20Django-ff69b4.svg)](https://github.com/pydanny/cookiecutter-django/)

Orochi - the volatility collaborative gui

## Table of Contents
1. [About Orochi](#about-orochi)
2. [Getting started](#getting-started)
3. [Community](#community)
4. [Contributing](#contributing)
5. [Origin of name](#origin)

## About Orochi
Orochi is an open source tool for collaborative forensic memory dump analysis. Using Orochi you and your collaborators can easily organize your memory dumps and analyze them all at the same time. 
Orochi architecture: 
- uses Volatility: the world’s most widely used framework for extracting digital artifacts from volatile memory (RAM) samples. 
- saves Volatility results in ElasticSearch
- distributes loads among nodes using Dask 
- uses Django as frontend
- use node for js/css compression
- uses Postgresql to save users, analysis metadata such status and errors.
- uses MailHog to manage the users registration emails
- use Redis for cache




## Origin of name
"Its eyes are like akakagachi, it has one body with eight heads and eight tails. Moreover on its body grows moss, and also chamaecyparis and cryptomerias. Its length extends over eight valleys and eight hills, and if one look at its belly, it is all constantly bloody and inflamed."
[Full story](https://en.wikipedia.org/wiki/Yamata_no_Orochi)

Let's go cut tails and find your Kusanagi-no-Tsurugi !



Settings
--------

Moved to settings_.

.. _settings: http://cookiecutter-django.readthedocs.io/en/latest/settings.html

Basic Commands
--------------

Setting Up Your Users
^^^^^^^^^^^^^^^^^^^^^

* To create a **normal user account**, just go to Sign Up and fill out the form. Once you submit it, you'll see a "Verify Your E-mail Address" page. Go to your console to see a simulated email verification message. Copy the link into your browser. Now the user's email should be verified and ready to go.

* To create an **superuser account**, use this command::

    $ python manage.py createsuperuser

For convenience, you can keep your normal user logged in on Chrome and your superuser logged in on Firefox (or similar), so that you can see how the site behaves for both kinds of users.

Type checks
^^^^^^^^^^^

Running type checks with mypy:

::

  $ mypy orochi

Test coverage
^^^^^^^^^^^^^

To run the tests, check your test coverage, and generate an HTML coverage report::

    $ coverage run -m pytest
    $ coverage html
    $ open htmlcov/index.html

Running tests with py.test
~~~~~~~~~~~~~~~~~~~~~~~~~~

::

  $ pytest

Live reloading and Sass CSS compilation
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Moved to `Live reloading and SASS compilation`_.

.. _`Live reloading and SASS compilation`: http://cookiecutter-django.readthedocs.io/en/latest/live-reloading-and-sass-compilation.html




Email Server
^^^^^^^^^^^^

In development, it is often nice to be able to see emails that are being sent from your application. For that reason local SMTP server `MailHog`_ with a web interface is available as docker container.

Container mailhog will start automatically when you will run all docker containers.
Please check `cookiecutter-django Docker documentation`_ for more details how to start all containers.

With MailHog running, to view messages that are sent by your application, open your browser and go to ``http://127.0.0.1:8025``

.. _mailhog: https://github.com/mailhog/MailHog



Sentry
^^^^^^

Sentry is an error logging aggregator service. You can sign up for a free account at  https://sentry.io/signup/?code=cookiecutter  or download and host it yourself.
The system is setup with reasonable defaults, including 404 logging and integration with the WSGI application.

You must set the DSN url in production.


Deployment
----------

The following details how to deploy this application.



Docker
^^^^^^

See detailed `cookiecutter-django Docker documentation`_.

.. _`cookiecutter-django Docker documentation`: http://cookiecutter-django.readthedocs.io/en/latest/deployment-with-docker.html



docker-compose -f local.yml run --rm django python manage.py migrate
docker-compose -f local.yml run --rm django python manage.py createsuperuser
