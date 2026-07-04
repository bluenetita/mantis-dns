#!/bin/sh
set -e
systemctl daemon-reload || true
echo "aegis-filter installed. Edit /etc/aegis-filter/aegis-filter.env, then:"
echo "  systemctl enable --now aegis-filter"
