#!/bin/bash
source /lib/log.sh

generate_acl() {
  local -a client_list=() clients=("127.0.0.1") addresses=()
  local entry address result entry_cache cache='{}' next_cache='{}'
  local cache_file=/etc/snidust/ddns-cache.json max_age="${DDNS_CACHE_MAX_AGE:-86400}" now
  local dns_tmp nginx_tmp cache_tmp
  export DYNDNS_CRON_ENABLED=false

  if [[ ! "$max_age" =~ ^[0-9]+$ ]]; then
    log_error "DDNS_CACHE_MAX_AGE must be a number of seconds - keeping existing ACL"
    return 1
  fi

  if [ -n "${ALLOWED_CLIENTS_FILE}" ]; then
    if [ ! -r "$ALLOWED_CLIENTS_FILE" ]; then
      log_error "Allowed clients file is not readable - keeping existing ACL"
      return 1
    fi
    mapfile -t client_list < "$ALLOWED_CLIENTS_FILE"
  else
    IFS=', ' read -ra client_list <<< "$ALLOWED_CLIENTS"
  fi

  if [ -f "$cache_file" ]; then
    cache=$(jq -ce 'select(type == "object")' "$cache_file") || return 1
  fi
  now=$(date +%s)

  for entry in "${client_list[@]}"; do
    entry="${entry%%#*}"
    entry="${entry//[$'\t\r ']/}"
    [ -n "$entry" ] || continue
    if /bin/ipcalc -cs "$entry"; then
      log_info "Allowing client '$entry'"
      clients+=("$entry")
      continue
    fi

    export DYNDNS_CRON_ENABLED=true
    addresses=()
    if result=$(timeout 10 /usr/bin/dog --json "$entry" A); then
      result=$(jq -r '[.responses[]?.answers[]? | select(.type == "A") | .address] | unique | .[]' <<< "$result") || result=''
    else
      result=''
    fi
    while IFS= read -r address; do
      [ -n "$address" ] || continue
      if /bin/ipcalc -4cs "$address"; then
        addresses+=("$address")
      else
        log_error "Ignoring invalid IPv4 address returned for '$entry'"
      fi
    done <<< "$result"

    if [ "${#addresses[@]}" -gt 0 ]; then
      entry_cache=$(printf '%s\n' "${addresses[@]}" | jq -Rsc --argjson updated "$now" '{addresses: (split("\n") | map(select(length > 0))), updated: $updated}') || return 1
    else
      entry_cache=$(jq -c --arg domain "$entry" --argjson now "$now" --argjson max_age "$max_age" \
        '.[$domain] | select(type == "object" and (.addresses | type) == "array" and (.updated | type) == "number" and $now - .updated <= $max_age)' <<< "$cache") || return 1
      if [ -z "$entry_cache" ]; then
        log_error "Resolution failed for '$entry' without recent cached addresses - client not allowed"
        continue
      fi
      mapfile -t addresses < <(jq -r '.addresses[]' <<< "$entry_cache")
      log_warn "Resolution failed for '$entry' - retaining addresses from the last successful lookup"
    fi
    for address in "${addresses[@]}"; do
      clients+=("$address")
      log_info "Allowing '$entry' => '$address'"
    done
    next_cache=$(jq -c --arg domain "$entry" --argjson value "$entry_cache" '.[$domain] = $value' <<< "$next_cache") || return 1
  done

  dns_tmp=$(mktemp /etc/dnsdist/allowedClients.acl.XXXXXX) || return 1
  nginx_tmp=$(mktemp /etc/nginx/allowedClients.conf.XXXXXX) || { rm -f "$dns_tmp"; return 1; }
  cache_tmp=$(mktemp /etc/snidust/ddns-cache.json.XXXXXX) || { rm -f "$dns_tmp" "$nginx_tmp"; return 1; }
  if ! {
    printf '%s\n' "${clients[@]}" | sort -u > "$dns_tmp" &&
    while IFS= read -r address; do
      printf 'allow %s;\n' "$address"
    done < "$dns_tmp" > "$nginx_tmp" &&
    printf 'deny all;\n' >> "$nginx_tmp" &&
    printf '%s\n' "$next_cache" > "$cache_tmp" &&
    mv "$cache_tmp" "$cache_file" &&
    mv "$nginx_tmp" /etc/nginx/allowedClients.conf &&
    mv "$dns_tmp" /etc/dnsdist/allowedClients.acl;
  }; then
    rm -f "$dns_tmp" "$nginx_tmp" "$cache_tmp"
    return 1
  fi
  log_ok "Generated ACL successfully"
}

generate_acl
