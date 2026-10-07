ARG EDITION=cloud
ARG VARIANT=2.4.0p27
FROM checkmk/check-mk-${EDITION}:${VARIANT}

# Create the site "cmk" at build time instead of on first container start.
RUN /docker-entrypoint.sh /bin/true

# Basic development tools
RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
 && apt-get install -y --no-install-recommends \
    less \
    git \
    man-db \
    unzip \
    gnupg2 \
    gh \
    jq \
    vim \
    curl \
    ca-certificates \
 && apt-get clean && rm -rf /var/lib/apt/lists/*

ENV DEVCONTAINER=true
ENV EDITOR=vim
ENV VISUAL=vim

COPY --chmod=644 requirements-site.txt requirements-tools.txt /tmp/

USER cmk

# Test helpers go into the site's local/lib/python3, so pytest imports them
# next to the Checkmk code. The site's pip3 wrapper always adds --target,
# which ignores installed packages and would pull in its own copies of
# requests, urllib3, pytest, ... that shadow the ones Checkmk ships; hence
# --no-deps (requirements-site.txt lists the dependencies Checkmk lacks).
RUN PATH="/omd/sites/cmk/bin:${PATH}" \
    OMD_ROOT="/omd/sites/cmk" \
    /omd/sites/cmk/bin/pip3 install --no-cache-dir --no-deps -r /tmp/requirements-site.txt

# Formatters and linters get their own venv (site Python, so they parse the
# same Python version), linked into ~/.local/bin, which is on PATH everywhere.
RUN /omd/sites/cmk/bin/python3 -m venv /omd/sites/cmk/.local/share/devtools \
 && /omd/sites/cmk/.local/share/devtools/bin/pip install --no-cache-dir \
    --disable-pip-version-check -r /tmp/requirements-tools.txt \
 && mkdir -p /omd/sites/cmk/.local/bin \
 && for tool in black isort flake8; do \
      ln -s /omd/sites/cmk/.local/share/devtools/bin/$tool /omd/sites/cmk/.local/bin/$tool; \
    done

# Claude Code via the native installer, as cmk: it installs into $HOME
# (~/.local/bin/claude -> ~/.local/share/claude/versions/<version>), so
# `claude update` and auto-updates work without root.
# HOME is set explicitly because Docker does not set it when switching USER.
# CLAUDE_CODE_VERSION=latest is resolved at build time and the layer is cached;
# a stale version is not a problem, Claude Code updates itself afterwards.
ARG CLAUDE_CODE_VERSION=latest
RUN curl -fsSL https://claude.ai/install.sh -o /tmp/claude-install.sh \
 && HOME=/omd/sites/cmk bash /tmp/claude-install.sh "${CLAUDE_CODE_VERSION}" \
 && rm -f /tmp/claude-install.sh \
 && mkdir -p /omd/sites/cmk/.claude

# devcontainer.json builds its PATH from ${containerEnv:PATH}, so this is what
# makes `claude` resolvable in the VS Code remote environment.
ENV PATH=/omd/sites/cmk/.local/bin:${PATH}

ENTRYPOINT ["/bin/bash"]
