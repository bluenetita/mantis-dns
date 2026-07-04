#!/bin/sh
set -e
systemctl disable --now aegis-filter 2>/dev/null || true
