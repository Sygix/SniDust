#!/bin/bash
source /lib/log.sh

generate_acl() {
  local -a client_list=() clients=("127.0.0.1") addresses=()
  local domain address result cache='{}' next_cache='{}' failed=false
  local cache_file=/etc/snidust/ddns-cache.json
  local dns_tmp nginx_tmp cache_tmp
  export DYNDNS_CRON_ENABLED=false

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

  for domain in "${client_list[@]}"; do
    [ -n "$domain" ] || continue
    if /bin/ipcalc -cs "$domain"; then
      log_info "Allowing client '$domain'"
      clients+=("$domain")
      continue
    fi

    export DYNDNS_CRON_ENABLED=true
    addresses=()
    if result=$(timeout 10 /usr/bin/dog --json "$domain" A); then
      result=$(jq -r '[.responses[]?.answers[]? | select(.type == "A") | .address] | unique | .[]' <<< "$result") || result=''
    else
      result=''
    fi
    if [ -z "$result" ]; then
      result=$(jq -r --arg domain "$domain" '.[$domain][]?' <<< "$cache") || return 1
      if [ -n "$result" ]; then
        log_warn "Resolution failed for '$domain' - retaining last known addresses"
      else
        log_error "Resolution failed for '$domain' without cached addresses - keeping existing ACL"
        failed=true
        continue
      fi
    fi
    while IFS= read -r address; do
      if /bin/ipcalc -4cs "$address"; then
        addresses+=("$address")
        clients+=("$address")
        log_info "Allowing '$domain' => '$address'"
      else
        log_error "Invalid IPv4 address returned for '$domain'"
        failed=true
      fi
    done <<< "$result"
    result=$(printf '%s\n' "${addresses[@]}" | jq -Rsc 'split("\n") | map(select(length > 0))') || return 1
    next_cache=$(jq -c --arg domain "$domain" --argjson addresses "$result" '.[$domain] = $addresses' <<< "$next_cache") || return 1
  done

  [ "$failed" = false ] || return 1
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
