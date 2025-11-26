# determine standard shell used to run commands,
# in this case `bash` supports `source` (used in `dbg` target)
set shell := ["bash", "-c"]

# loading environment variables from `.env` file
# (to keep API Key details out of source code control)
set dotenv-load := true

# install, lint, build, and test the application
default: install lint

# build the docker image
build:
    docker build -t ksc/tools .

# remove all artifacts
clean-all:
    # remove all __pycache__ folders
    find . -type d -name "__pycache__" -exec rm -r {} +
    # remove all .pyc and .pyo files
    find . -type f -name "*.pyc" -exec rm -f {} +
    find . -type f -name "*.pyo" -exec rm -f {} +
    # remove specific caches
    rm -rf .pytest_cache/
    rm -rf .ruff_cache/
    # remove the virtual environment
    rm -rf .venv/

# install dependencies
install:
    uv lock --upgrade
    uv sync --all-extras --no-install-project --frozen

# format and check code
lint:
    uv run ruff format .
    uv run ruff check .
    uv run ty check .

# run docker and start interactive shell
sh:
    # pass on the environment variable, as loaded from .env file
    docker run --rm -it -e KSC_API_KEY=$KSC_API_KEY ksc/tools sh
