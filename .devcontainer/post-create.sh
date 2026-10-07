#!/usr/bin/env bash
# Runs once after the container has been created (postCreateCommand).
set -Eeuo pipefail

OMD_ROOT="${OMD_ROOT:-/omd/sites/cmk}"
WORKSPACE="${WORKSPACE:-$(cd "$(dirname "$0")/.." && pwd)}"

# Nagios-compatible active check executables and a scratch dir from the
# workspace (both created by initializeCommand in devcontainer.json).
rm -rf "$OMD_ROOT/local/lib/nagios/plugins"
ln -sv "$WORKSPACE/nagios_plugins" "$OMD_ROOT/local/lib/nagios/plugins"

rm -rf "$OMD_ROOT/local/tmp"
ln -sv "$WORKSPACE/temp" "$OMD_ROOT/local/tmp"

# The bind-mounted workspace belongs to the host user, not cmk: without this,
# git refuses to work in it ("detected dubious ownership").
git config --global --add safe.directory "$WORKSPACE"

# Fixed GUI login for local development only: cmkadmin / cmkadmin
set +u
source "$OMD_ROOT/.profile"
set -u
echo 'cmkadmin' | cmk-passwd -i cmkadmin
