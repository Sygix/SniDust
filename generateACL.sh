#!/bin/bash
source /lib/log.sh

CLIENTS=()
export DYNDNS_CRON_ENABLED=false

function read_acl () {
  for i in "${client_list[@]}"
  do
    /bin/ipcalc -cs "$i"
    retVal=$?
    if [ $retVal -eq 0 ]; then
      log_info "Allowing client '${i}'"
      CLIENTS+=( "${i}" )
    else
      log_info "'${i}' is not an IP/CIDR - trying to resolve it via DNS"
      RESOLVE_RESULT=$(/usr/bin/dog --json "${i}" | jq -r '.responses[].answers | map(select(.type == "A")) | first | .address // empty')
      if [ -n "${RESOLVE_RESULT}" ]; then
        log_info "Resolved '${i}' => '${RESOLVE_RESULT}' - enabling DynDNS cron"
        export DYNDNS_CRON_ENABLED=true
        CLIENTS+=( "${RESOLVE_RESULT}" )
      else
        log_error "Could not resolve '${i}' => Skipping"
      fi
    fi
  done
  (echo "${client_list[@]}" | grep -q '127.0.0.1')
  localipCheck=$?
  if [[ "$localipCheck" -eq 1 ]] && [[ "$DYNDNS_CRON_ENABLED" = true ]]; then
    log_info "Adding '127.0.0.1' to allowed clients cause else cron reload will not work"
    CLIENTS+=( "127.0.0.1" )
  fi
}

if [ -n "${ALLOWED_CLIENTS_FILE}" ];
then
  if [ -f "${ALLOWED_CLIENTS_FILE}" ];
  then
    log_info "Reading allowed clients from file '${ALLOWED_CLIENTS_FILE}'"
    mapfile -t client_list < "$ALLOWED_CLIENTS_FILE"
  else
    log_error "ALLOWED_CLIENTS_FILE is set but file does not exists or is not accessible!"
  fi
else
  IFS=', ' read -ra client_list <<< "$ALLOWED_CLIENTS"
fi

if [ "${#client_list[@]}" -eq 0 ]; then
  log_warn "No allowed clients configured - only 'deny all;' will be applied (nginx will reject every client)"
fi

read_acl
printf '%s\n' "${CLIENTS[@]}" > /etc/dnsdist/allowedClients.acl

if [ -f "/etc/dnsdist/allowedClients.acl" ];
then
  : > /etc/nginx/allowedClients.conf
  while read -r line
  do
    echo "allow $line;" >> /etc/nginx/allowedClients.conf
  done < "/etc/dnsdist/allowedClients.acl"
  echo "deny  all;" >> /etc/nginx/allowedClients.conf
  log_ok "Generated ACL with ${#CLIENTS[@]} allowed client(s)"
else
  log_warn "dnsdist ACL file not found - writing empty nginx ACL"
  touch /etc/nginx/allowedClients.conf
fi
