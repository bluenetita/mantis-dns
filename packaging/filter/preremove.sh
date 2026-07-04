#!/bin/sh
set -e
systemctl disable --now mantis-filter 2>/dev/null || true
