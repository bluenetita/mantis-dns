#!/bin/sh
set -e
systemctl daemon-reload || true
echo "mantis-filter installed. Edit /etc/mantis-filter/mantis-filter.env, then:"
echo "  systemctl enable --now mantis-filter"
