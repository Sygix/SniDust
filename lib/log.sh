#!/bin/bash
# Shared logging helpers for SniDust scripts.
#
# Provides timestamped, level-tagged log output:
#   2026-07-12T10:30:01Z [INFO ] message
#
# Colors are enabled automatically when the target stream is a terminal and
# disabled otherwise (e.g. when logs are captured by the container runtime),
# so aggregated logs stay parseable.
#
# INFO / OK / STEP go to stdout, WARN / ERROR go to stderr.
#
# Optional: set LOG_CONTEXT before logging to prefix every line, e.g.
#   LOG_CONTEXT="DynDNSCron"  ->  ... [INFO ] [DynDNSCron] message

# Guard against being sourced more than once (entrypoint sources this file and
# then sources generateACL.sh, which sources it again).
if [ -n "${__SNIDUST_LOG_SH_LOADED:-}" ]; then
  return 0 2>/dev/null || true
fi
__SNIDUST_LOG_SH_LOADED=1

if [ -t 1 ]; then
  __LOG_C_RESET=$'\033[0m'
  __LOG_C_INFO=$'\033[0;36m'
  __LOG_C_WARN=$'\033[0;33m'
  __LOG_C_ERROR=$'\033[0;31m'
  __LOG_C_OK=$'\033[0;32m'
  __LOG_C_STEP=$'\033[1;34m'
else
  __LOG_C_RESET=""
  __LOG_C_INFO=""
  __LOG_C_WARN=""
  __LOG_C_ERROR=""
  __LOG_C_OK=""
  __LOG_C_STEP=""
fi

# __log <color> <level-label> <fd> <message...>
__log() {
  local color="$1" level="$2" fd="$3"
  shift 3
  local ts ctx=""
  ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  [ -n "${LOG_CONTEXT:-}" ] && ctx="[${LOG_CONTEXT}] "
  printf '%s %s[%s]%s %s%s\n' "$ts" "$color" "$level" "$__LOG_C_RESET" "$ctx" "$*" >&"$fd"
}

log_info()  { __log "$__LOG_C_INFO"  "INFO " 1 "$@"; }
log_warn()  { __log "$__LOG_C_WARN"  "WARN " 2 "$@"; }
log_error() { __log "$__LOG_C_ERROR" "ERROR" 2 "$@"; }
log_ok()    { __log "$__LOG_C_OK"    " OK  " 1 "$@"; }
log_step()  { __log "$__LOG_C_STEP"  "STEP " 1 "$@"; }
