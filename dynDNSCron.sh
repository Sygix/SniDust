#!/bin/bash
source /lib/log.sh
export LOG_CONTEXT="DynDNSCron"

log_step "Reloading dnsdist ACL config"
if /usr/bin/dog @127.0.0.1:53 --short reload.acl.snidust.local; then
  log_ok "dnsdist ACL config successfully reloaded!"
else
  log_error "Failed to reload dnsdist ACL config!"
fi
