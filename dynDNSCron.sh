#!/bin/bash
source /lib/log.sh
export LOG_CONTEXT="DynDNSCron"

log_step "Regenerating ACL..."
if ! { /bin/bash /generateACL.sh && nginx -t -q && nginx -s reload; }; then
  log_error "ACL refresh failed - keeping active ACL"
  exit 1
fi

log_step "Applying ACL to dnsdist"
if /usr/bin/dog @127.0.0.1:53 --short apply.acl.snidust.local; then
  log_ok "ACL refreshed"
else
  log_error "Failed to apply ACL to dnsdist"
  exit 1
fi
