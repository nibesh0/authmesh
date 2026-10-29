# Test runner image: every service dependency plus pytest, with the repo mounted
# at runtime so a test edit does not require a rebuild.
FROM python:3.12-slim

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /work

COPY libs/common/requirements.txt libs/common/requirements.txt
COPY services/auth/requirements.txt services/auth/requirements.txt
COPY services/user/requirements.txt services/user/requirements.txt
COPY services/gateway/requirements.txt services/gateway/requirements.txt
COPY requirements-dev.txt requirements-dev.txt
RUN pip install -r requirements-dev.txt

# Source is bind-mounted at /work, so the packages are installed in editable
# mode: imports resolve to the mounted tree, not to a copied snapshot.
COPY libs/common libs/common
COPY services services
RUN pip install --no-deps -e ./libs/common -e ./services/auth -e ./services/user -e ./services/gateway

CMD ["python", "-m", "pytest", "tests", "-v"]
