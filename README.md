# Orochi

[![Black code style](https://img.shields.io/badge/code%20style-black-000000.svg)](http://shields.io/)
[![GitHub license](https://img.shields.io/github/license/LDO-CERT/orochi.svg)](https://github.com/LDO-CERT/orochi/blob/master/LICENSE)
[![Built with Cookiecutter Django](https://img.shields.io/badge/built%20with-Cookiecutter%20Django-ff69b4.svg)](https://github.com/pydanny/cookiecutter-django/)
[![HitCount](http://hits.dwyl.com/LDO-CERT/orochi.svg)](http://hits.dwyl.com/LDO-CERT/orochi)
[![Join the chat at https://gitter.im/ldo-cert-orochi/community](https://badges.gitter.im/LDO-CERT/orochi.svg)](https://gitter.im/ldo-cert-orochi?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

Orochi - The Volatility Collaborative GUI

![Orochi](docs/images/orochi.png)

## Table of Contents

- [Orochi](#orochi)
  - [Table of Contents](#table-of-contents)
  - [About Orochi](#about-orochi)
  - [Getting started](#getting-started)
      - [Installation](#installation)
      - [Quick Start Guide](#quick-start-guide)
      - [User Guide](#user-guide)
  - [Community](#community)
  - [Contributing](#contributing)
  - [Origin of name](#origin-of-name)

## About Orochi

Orochi is an open source framework for collaborative forensic memory dump analysis. Using Orochi you and your collaborators can easily organize your memory dumps and analyze them all at the same time.

Orochi architecture:

- uses [Volatility 3](https://github.com/volatilityfoundation/volatility3): the world’s most widely used framework for extracting digital artifacts from volatile memory (RAM) samples.
- saves Volatility results in [ElasticSearch](https://github.com/elastic/elasticsearch)
- distributes loads among nodes using [Dask](https://github.com/dask/dask)
- uses [Django](https://github.com/django/django) as frontend
- uses [Postgresql](https://github.com/postgres/postgres) to save users, analysis metadata such status and errors.
- uses [MailHog](https://github.com/mailhog/MailHog) to manage the users registration emails
- use [Redis](https://github.com/redis/redis) for cache and websocket for notifications
- [Kibana](https://github.com/elastic/kibana) interface is provided for ElasticSearch maintenance (checking indexes, deleting if something hangs)
- all framework is provided as [docker-compose](https://github.com/docker/) images

## Getting started

#### Installation

Using Docker-compose you can start multiple dockers and link them together.


Start cloning the repo:

- `git clone https://github.com/LDO-CERT/orochi.git`

- ElasticSearch container likes [big mmap count ](https://www.elastic.co/guide/en/elasticsearch/reference/current/vm-max-map-count.html) so from shell do `sysctl -w vm.max_map_count=262144` otherwise docker image of Elastic would not start.
  In case you are running docker on Windows you can do `wsl -d docker-desktop sysctl -w vm.max_map_count=262144` from PowerShell.

- You need to set some useful variable that docker-compose will use for [configure the environment](https://cookiecutter-django.readthedocs.io/en/latest/developing-locally-docker.html#configuring-the-environment)

  Here a sample of .env\\.local\\.postgres:

  ```
  POSTGRES_HOST=postgres
  POSTGRES_PORT=5432
  POSTGRES_DB=orochi
  POSTGRES_USER=debug
  POSTGRES_PASSWORD=debug
  ```

  Here a sample of .env\\.local\\.django:

  ```
  USE_DOCKER=yes
  IPYTHONDIR=/app/.ipython
  REDIS_URL=redis://redis:6379/0
  ELASTICSEARCH_URL=http://es01:9200
  DASK_SCHEDULER_URL=tcp://scheduler:8786
  ```

- If needed you can change the ALLOWED_HOSTS for the frontend adding ALLOWED_HOSTS value in in .envs\\.local\\.django

- If needed you can change number of Dask workers will be started. In order to do this you need modify the local.yaml file adding/ removing workerXX code blocks.

- Now it's time to fire up the images!
  \
   `docker-compose up`
  \
   When finished - it takes a while - you can check the status of images:
  \
   `orochi$ docker ps -a`
  ````
   CONTAINER ID        IMAGE                                                 COMMAND                  CREATED             STATUS                      PORTS                              NAMES
   61c220705bbb        orochi_local_node                                     "docker-entrypoint.s…"   7 minutes ago       Up 6 minutes                0.0.0.0:3000-3001->3000-3001/tcp   node
   f4afedd2cca1        orochi_local_django                                   "/entrypoint /start"     7 minutes ago       Up 7 minutes                0.0.0.0:8000->8000/tcp             django
   242df255b753        mailhog/mailhog:v1.0.0                                "MailHog"                7 minutes ago       Up 7 minutes                1025/tcp, 0.0.0.0:8025->8025/tcp   mailhog
   975b65f963dd        orochi_local_postgres                            "docker-entrypoint.s…"   7 minutes ago       Up 7 minutes                5432/tcp                           postgres
   780a899932d1        daskdev/dask                                          "tini -g -- /usr/bin…"   7 minutes ago       Up 7 minutes                0.0.0.0:8786-8787->8786-8787/tcp   orochi_scheduler_1
   35db49ca8108        redis:5.0                                             "docker-entrypoint.s…"   7 minutes ago       Up 7 minutes                6379/tcp                           redis
   5e93fae103c0        daskdev/dask                                          "tini -g -- /usr/bin…"   7 minutes ago       Up 7 minutes                                                   orochi_worker01_1
   82b9fc948fe2        daskdev/dask                                          "tini -g -- /usr/bin…"   7 minutes ago       Up 7 minutes                                                   orochi_worker03_1
   9ae0e06d958d        daskdev/dask                                          "tini -g -- /usr/bin…"   7 minutes ago       Up 7 minutes                                                   orochi_worker02_1
   0b446818998f        docker.elastic.co/elasticsearch/elasticsearch:7.7.0   "/tini -- /usr/local…"   7 minutes ago       Up 7 minutes                0.0.0.0:9200->9200/tcp, 9300/tcp   orochi_es01
   776ddda3b3b8        daskdev/dask                                          "tini -g -- /usr/bin…"   7 minutes ago       Up 7 minutes                                                   orochi_worker04_1
   663e42e9b0b3        docker.elastic.co/kibana/kibana:7.7.0                 "/usr/local/bin/dumb…"   7 minutes ago       Up 7 minutes                0.0.0.0:5601->5601/tcp             orochi_kib01
   ```
  ````
- Now some management command in case you are upgrading:
  ```
   $ docker-compose run --rm django python manage.py makemigrations
   $ docker-compose run --rm django python manage.py migrate
  ```
- Create superuser to access admin page:
  ```
  $ docker-compose run --rm django python manage.py createsuperuser
  ```
- Sync Volatility plugins (\*) in order to make them available to users:
  ```
  $ docker-compose run --rm django python manage.py plugins_sync
  ```
- Volatility Symbol Tables are available [here](https://github.com/volatilityfoundation/volatility3#symbol-tables) and can be sync using this command (\*):
  ```
  $ docker-compose run --rm django python manage.py symbols_sync
  ```
(\*) It is also possible to run plugins_sync and symbols_sync directly from the admin page in case new plugins or new symbols are available.

- To create a **normal user account**, just go to Sign Up (http://127.0.0.1:8000) and fill out the form. Once you submit it, you'll see a "Verify Your E-mail Address" page. Go to your console to see a simulated email verification message. Copy the link into your browser. Now the user's email should be verified and ready to go.
  In development, it is often nice to be able to see emails that are being sent from your application. For that reason local SMTP server [Mailhog](https://github.com/mailhog/MailHog) with a web interface is available as docker container.
  Container mailhog will start automatically when you will run all docker containers.
  Please check `cookiecutter-django Docker documentation` for more details how to start all containers.
  With MailHog running, to view messages that are sent by your application, open your browser and go to `http://127.0.0.1:8025`

- Other details in [cookiecutter-django Docker documentation](http://cookiecutter-django.readthedocs.io/en/latest/deployment-with-docker.html)

### Quick Start Guide

- register your user
- login with your user and password
- upload a memory dump and choose a name, the OS and the color: in order to speed up the upload it accepts also zipped files.
- When upload is done, all Volatility plugins will be executed in parallel thanks to Dask. With Dask it is possible to distribute jobs among different servers.
- You can configure which plugin you want run by default through admin page.
- As the results come, they will be shown.
- Is it possible to view the results of a plugin executed on multiple dumps, for example view simultaneoously processes list output of 2 different machines.

Applications links:

Orochi homepage: http://127.0.0.1:8000

Orochi admin: http://127.0.0.1:8000/admin

Mailhog: http://127.0.0.1:8025

Kibana: http://127.0.0.1:5601

Dask: http://127.0.0.1:8787

### User guide

Please see [Users-Guide](docs/Users-Guide.md)

## Community

We are available on [Gitter](https://gitter.im/ldo-cert-orochi/community) to help you and discuss about improvements.

## Contributing

If you want to contribute to orochi, be sure to review the [contributing guidelines](CONTRIBUTING.md). This project adheres to orochi
[code of conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

## Origin of name

"Its eyes are like akakagachi, it has one body with eight heads and eight tails. Moreover on its body grows moss, and also chamaecyparis and cryptomerias. Its length extends over eight valleys and eight hills, and if one look at its belly, it is all constantly bloody and inflamed."
[Full story from wikipedia](https://en.wikipedia.org/wiki/Yamata_no_Orochi)

Let's go cut tails and find your Kusanagi-no-Tsurugi !
