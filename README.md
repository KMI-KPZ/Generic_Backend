#  Generic Backend

## 📚 Table of Contents

- [Generic Backend](#generic-backend)
  - [📚 Table of Contents](#-table-of-contents)
  - [🔍 Project Overview](#-project-overview)
    - [Short Description](#short-description)
    - [Tech Stack](#tech-stack)
  - [🚀 Getting Started](#-getting-started)
    - [Prerequisites](#prerequisites)
    - [Environment Variables](#environment-variables)
    - [Installation](#installation)
    - [Running the Application](#running-the-application)
      - [Windows](#windows)
      - [Linux/Mac](#linuxmac)
  - [🛠️ Development](#️-development)
    - [Run Backend Locally (Without Docker)](#run-backend-locally-without-docker)
      - [Prerequisites](#prerequisites-1)
      - [Environment Variables](#environment-variables-1)
      - [Installation](#installation-1)
      - [Services](#services)
      - [Database](#database)
    - [Docker files](#docker-files)
    - [🗃️ Folder structure](#️-folder-structure)
    - [Documentation](#documentation)
    - [Branch descriptions:](#branch-descriptions)
  - [🌟 Best Practices](#-best-practices)
    - [Linting and Formatting](#linting-and-formatting)
    - [Recommended VSCode Extensions](#recommended-vscode-extensions)
  - [📜 License](#-license)


## 🔍 Project Overview

### Short Description

The Generic Backend is the generic part of the Semper-KI platform where users can submit their 3D printing requirements and find suitable service providers. 
It can be used as a baseline for other django-based backends since it includes multiple parts that almost every backend needs at some point.


### Tech Stack

- **Language**: Python 3.11
- **Backend**: Django, Django REST Framework, Channels
- **Auth & Security**: Authlib
- **Database**: PostgreSQL
- **Caching**: Redis
- **Task Queue**: Celery (Redis as broker)
- **Storage**: MinIO, S3 compatible
- **API Documentation**: Swagger UI (DRF Spectacular)
- **Testing & Debugging**: pytest, Django Test Framework
- **Deployment**: Gunicorn, Uvicorn, Nginx
- **Containerization**: Docker
- **Code Quality**: Pylint


## 🚀 Getting Started

### Prerequisites

Make sure you have the following installed on your machine:

- `Docker`: Latest version
- (`Python`: 3.11)

### Environment Variables
Make sure you have the following `.env` files
- `.env.local_container`: For local development with Docker 
- `.env.staging`: For a deployed staging environment on a server
- `.env.production`: For a deployed production environment on a server


- If you don't have any .env file:
  - Ask someone who does on your team
  - Create one yourself based on the .env template `exampleEnv.txt`

### Installation

Clone the repository:

```bash
git clone git@github.com:KMI-KPZ/Generic_Backend.git
cd Generic_Backend
```


Optional:
- Install packages to your local machine
```
python -m pip install -r requirements.txt
```


### Running the Application
To run the application, you can use our `docker compose` starting script in the root of the project.
The Script starts both the services and the backend inside Docker containers.

#### Windows
```
start_local_dev.bat -m local_container
```

#### Linux/Mac
1. Make the script executable:
```
chmod +x start_local_dev.sh
```
2. Run the script
```
./start_local_dev.sh -m local_container
```

> **Note:**  
> The backend container supports hot reloading — changes to files are reflected automatically after saving.  
> In debug mode, the current request handler must complete before the worker restarts.  
> There may be a slight delay before the changes take effect, but the logs will indicate when the reload occurs.


## 🛠️ Development


### Run Backend Locally (Without Docker)
#### Prerequisites

Make sure you have the following installed on your machine:

- `Docker`: Latest version
- `Python`: 3.11

#### Environment Variables
Make sure you have the following `.env` files
- `.env.dev`: For local debugging via VS Code
- `.env.local`: For local development of the backend without docker (services always run inside docker)

#### Installation
Follow installation in [Getting Started](#-Getting-Started) (clone project and install submodules)

- Install packages to your local machine
```
python -m pip install -r requirements.txt
```

#### Services
- Run the services in Docker containers:

```bash
# Windows
start_local_dev.bat -m local

# Linux / macOS
chmod +x start_local_dev.sh
./start_local_dev.sh -m local
```

#### Database
1. Create the database:
```
python manage.py create_db --env local
```
2. Migrate the database to the latest state:
```
python manage.py migrate --env local
```
3. Run the backend locally:
```
python manage.py runserver --env local
```


### Docker files
There are a couple of docker and docker-compose files in the root folder. 
Regarding the docker files:
- `Dockerfile`: Used by local docker-compose files, uses caching for faster builds
- `Dockerfile.Server`:  Used for compose files that run on a server (no caching for example)

As for the compose files:
- `docker-local-dev-container-backend.yml`: For the backend container when running in local_container mode
- `docker-local-dev-services.yml`: Every other container like redis, postgres and so on for local use
- `docker-compose.test.yml`: For running the tests, can be called via docker-compose up directly, usable by GitHub Actions
- `docker-compose.staging.yml`: Used on the server for staging
- `docker-compose.production.yml`: Same as above albeit for production


### 🗃️ Folder structure
- `.`: The main folder contains the manage.py file of django and docker files as well as the .env files
  - `.devcontainer`: Contains the json needed for running the service containers together with the debug container
  - `.vscode`: Everything necessary to run the debug-mode of VS Code
  - `Benchy`: A small tool to fire calls to certain paths
  - `code_General`: The main code
    - `configs`: Contains the auth0 configuration
    - `connections`: Connections to internal and external services like ID management (auth0 in our case), redis, ...
      - `postgresql`: Specific code for the models using the postgres database
    - `handlers`: API Paths handling calls
    - `logics`: Logics to these handlers
    - `migrations`: Migrations done by django
    - `modelFiles`: Database models
    - `settings`: Setting files specific to the GB module
    - `static`: Static files (only a testpicture currently)
    - `templates`: HTML templates
    - `utilities`: Helper functions
  - `docker`: Docker scripts for redis and minio
  - `logs`: Log files
  - `main`: Main django app
    - `helper`: Helper functions like checking connections to other containers
    - `management`: Command line tools
      - `commands`: 
    - `settings`: Settings for django
  - `minio`: Folder containing the locally saved files
  - `postgres`: Folder that holds the database
  - `redis`: Folder that holds snapshots of redis
  - `run`: Run scripts

### Documentation
If backend is running: 
- Project Documentation: Available at [`http://127.0.0.1:8000/private/doc`](http://127.0.0.1:8000/private/doc)
- Swagger UI (API reference): Available at [`http://127.0.0.1:8000/public/api/schema/swagger-ui/`](http://127.0.0.1:8000/public/api/schema/swagger-ui/)


### Branch descriptions:
- **dev**: Where all branches derive from and will be pushed to
- **main**: publish/forkable branch, only pull requests from dev go here

## 🌟 Best Practices
Please refer to the [Code style guide](./CodeStyle.md).

### Linting and Formatting

A `.pylintrc` configuration file is located in the main folder and can be used with the **Pylint** extension in VS Code.
This ensures consistent linting across the project.

### Recommended VSCode Extensions

- Pylint
- Pip Manager
- Docker

## 📜 License

This project is licensed under the [MIT License](https://mit-license.org/).

You are free to use, modify, and distribute this software, provided that you comply with the terms of the license.

For more details, see the [LICENSE](./LICENSE) file in this repository.
