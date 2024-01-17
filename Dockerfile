# For more information, please refer to https://aka.ms/vscode-docker-python
FROM python:3.11

# if nothing else is said, the 8000 port is exposed to the host
EXPOSE 8000

# Keeps Python from generating .pyc files in the container
ENV PYTHONDONTWRITEBYTECODE=1

# Turns off buffering for easier container logging when set to 1
ENV PYTHONUNBUFFERED=1

# Install necessary libraries
RUN apt-get update \
    && apt-get -y install libpq-dev gcc bash iputils-ping curl gawk

# Tell docker, that /app is the working directory inside the container
WORKDIR /app

# Install pip requirements
# mount required packages from cache, needs the entry "features": {"buildkit": true} in the docker engine
COPY requirements.txt /app/
RUN --mount=type=cache,target=/root/.cache \
    pip install -r requirements.txt

# copy current directory to /app
COPY . /app

# set every shell script as executable inside the container
RUN find /app/*.sh -type f -exec chmod +x {} \;

# TODO, currently everything is root
# Creates a non-root user with an explicit UID and adds permission to access the /app folder
# For more info, please refer to https://aka.ms/vscode-docker-python-configure-containers
#RUN adduser -u 5678 --disabled-password --gecos "" appuser && chown -R appuser /app
#USER appuser

# During debugging, this entry point will be overridden. For more information, please refer to https://aka.ms/vscode-docker-python-debug
#CMD ["gunicorn", "--bind", "0.0.0.0:8000", "main.asgi", "--reload", "--capture-output", "--log-level", "debug", "--env", "DJANGO_SETTINGS_MODULE=main.settings.debug", "-k", "uvicorn.workers.UvicornWorker", "--workers",  "16", "--threads", "16", "--timeout", "12000"]
ENTRYPOINT ["./run/run.sh"]
CMD [ "-e","production", "-m", "-c"]