#!/bin/bash -e
source /lib/log.sh

# Validate DoT config
if [ "${DNSDIST_ENABLE_DOT}" == "true" ]; then
  VALID_CERT_TYPE_VALUES=("auto-self" "manual")
  if [[ -z "$DNSDIST_DOT_CERT_TYPE" ]]; then
    log_error "The environment variable DNSDIST_DOT_CERT_TYPE is not set."
    exit 1
  fi

  if [[ " ${VALID_CERT_TYPE_VALUES[*]} " =~ " ${DNSDIST_DOT_CERT_TYPE} " ]]; then
    if [ "${DNSDIST_DOT_CERT_TYPE}" == "auto-self" ]; then
      log_step "Creating self-signed DoT certificate"
      /usr/bin/step certificate create dot.snidust.local /etc/dnsdist/certs/tls.pem /etc/dnsdist/certs/tls.key --profile self-signed --subtle --no-password --insecure
    fi
  else
    log_error "Invalid value for DNSDIST_DOT_CERT_TYPE: $DNSDIST_DOT_CERT_TYPE"
    exit 1
  fi
fi

if [ -z "${EXTERNAL_IP}" ];
then
  log_info "External IP not set - trying to determine it automatically"
  if EXTERNAL_IP=$(curl -fsS --max-time 10 https://icanhazip.com);
  then
    export EXTERNAL_IP
    log_ok "Detected external IP: ${EXTERNAL_IP}"
  else
    log_error "Could not determine external IP automatically. Set the EXTERNAL_IP environment variable explicitly."
    exit 1
  fi
fi

if [ -z "${DNSDIST_WEBSERVER_PASSWORD}" ];
then
  log_info "Dnsdist webserver password not set - generating one"
  DNSDIST_WEBSERVER_PASSWORD=$(< /dev/urandom tr -dc _A-Z-a-z-0-9 | head -c12)
  export DNSDIST_WEBSERVER_PASSWORD
  log_info "Generated WebServer Password: $DNSDIST_WEBSERVER_PASSWORD"
fi

if [ -z "${DNSDIST_WEBSERVER_API_KEY}" ];
then
  log_info "Dnsdist webserver api key not set - generating one"
  DNSDIST_WEBSERVER_API_KEY=$(< /dev/urandom tr -dc _A-Z-a-z-0-9 | head -c32)
  export DNSDIST_WEBSERVER_API_KEY
  log_info "Generated WebServer API Key: $DNSDIST_WEBSERVER_API_KEY"
fi

if [ "$INSTALL_DEFAULT_DOMAINS" = true ];
then
  log_step "Installing default domains..."
  cp -v /var/lib/snidust/domains.d/*.lst /etc/snidust/domains.d/
fi

log_step "Generating ACL..."
set +e
source generateACL.sh
set -e

log_step "Generating DNSDist Config..."
/bin/bash /etc/dnsdist/dnsdist.conf.template > /etc/dnsdist/dnsdist.conf

if [ "$DYNDNS_CRON_ENABLED" = true ];
then
  log_info "DynDNS Address in ALLOWED_CLIENTS detected => Enable cron job"
  echo "$DYNDNS_CRON_SCHEDULE /bin/bash /dynDNSCron.sh" > /etc/snidust/dyndns.cron
  supercronic /etc/snidust/dyndns.cron &
fi

log_step "Starting DNSDist..."
/usr/bin/dnsdist -C /etc/dnsdist/dnsdist.conf --supervised --disable-syslog --uid snidust --gid snidust &

log_step "Starting nginx.."
# Run nginx in the foreground so we can capture its real PID and supervise it.
# (Without 'daemon off;' nginx forks and returns immediately, so $! would point
# at the previously backgrounded process instead of nginx.)
nginx -g 'daemon off;' &
nginx_processId=$!

sleep 5

echo "==================================================================="
log_ok "SniDust started => Using $EXTERNAL_IP - Point your DNS settings to this address"
echo "==================================================================="
wait $nginx_processId
