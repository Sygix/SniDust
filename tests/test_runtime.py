import os
import secrets
import shlex
import socket
import ssl
import struct
import subprocess
import time
import unittest


DOCKER = shlex.split(os.environ.get("DOCKER_COMMAND", "docker"))
IMAGE = os.environ.get("SNIDUST_TEST_IMAGE", "snidust:diagnostic")


def docker(*args):
    return subprocess.check_output(DOCKER + list(args), text=True).strip()


def query(port, name, qtype, tcp=False, tls_context=None, include_authority=False):
    ident = secrets.randbelow(65536)
    wire_name = b"".join(bytes([len(label)]) + label.encode() for label in name.split(".")) + b"\0"
    packet = struct.pack("!6H", ident, 256, 1, 0, 0, 0) + wire_name + struct.pack("!2H", qtype, 1)
    transport = socket.socket(socket.AF_INET, socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM)
    if tls_context:
        transport = tls_context.wrap_socket(transport, server_hostname="dot.snidust.local")
    with transport as sock:
        sock.settimeout(3)
        if tcp:
            sock.connect(("127.0.0.1", port))
            sock.sendall(struct.pack("!H", len(packet)) + packet)
            def receive(length):
                data = b""
                while len(data) < length:
                    part = sock.recv(length - len(data))
                    if not part:
                        raise RuntimeError("DNS connection closed")
                    data += part
                return data
            data = receive(struct.unpack("!H", receive(2))[0])
        else:
            sock.sendto(packet, ("127.0.0.1", port))
            data, _ = sock.recvfrom(65535)
    response_id, flags, questions, answers, authorities, _ = struct.unpack("!6H", data[:12])
    if response_id != ident:
        raise RuntimeError("DNS response ID mismatch")
    def skip_name(pos):
        while data[pos]:
            if data[pos] & 192 == 192:
                return pos + 2
            pos += 1 + data[pos]
        return pos + 1
    pos = 12
    for _ in range(questions):
        pos = skip_name(pos) + 4
    def read_records(count):
        nonlocal pos
        records = []
        for _ in range(count):
            pos = skip_name(pos)
            record_type, _, _, length = struct.unpack("!HHIH", data[pos:pos + 10])
            pos += 10
            records.append((record_type, data[pos:pos + length]))
            pos += length
        return records
    records = read_records(answers)
    authority = read_records(authorities)
    if include_authority:
        return flags & 15, records, authority
    return flags & 15, records


class RuntimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.containers = []
        cls.addClassCleanup(cls.cleanup)
        cls.all_domains = cls.start("true")
        cls.listed_domains = cls.start("false")

    @classmethod
    def cleanup(cls):
        for name in cls.containers:
            docker("rm", "-f", name)

    @classmethod
    def start(cls, spoof_all, from_file=False, enable_dot=False, clients="0.0.0.0/0"):
        name = "snidust-test-" + secrets.token_hex(5)
        args = ["run", "-d", "--name", name,
               "-p", "127.0.0.1::53/udp", "-p", "127.0.0.1::53/tcp",
               "-p", "127.0.0.1::443/tcp", "-p", "127.0.0.1::80/tcp",
               "--cap-add", "NET_BIND_SERVICE",
               "-e", "ALLOWED_CLIENTS=" + clients, "-e", "EXTERNAL_IP=192.0.2.10",
               "-e", "DNSDIST_DEBUG=true", "-e", "SPOOF_ALL_DOMAINS=" + spoof_all]
        if from_file:
            args += ["-e", "ALLOWED_CLIENTS_FILE=/etc/snidust/test-clients"]
        if enable_dot:
            args += ["-e", "DNSDIST_ENABLE_DOT=true", "-p", "127.0.0.1::853/tcp"]
        args.append(IMAGE)
        if from_file:
            args += ["bash", "-c", "if [ ! -f /etc/snidust/test-initialized ]; then printf '0.0.0.0/0\\n' > /etc/snidust/test-clients; touch /etc/snidust/test-initialized; fi; exec bash /entrypoint.sh"]
        docker(*args)
        cls.containers.append(name)
        return cls.wait_ready(name)

    @classmethod
    def wait_ready(cls, name):
        udp_port = int(docker("port", name, "53/udp").rsplit(":", 1)[1])
        tcp_port = int(docker("port", name, "53/tcp").rsplit(":", 1)[1])
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            try:
                if query(udp_port, "netflix.com", 1)[1]:
                    return name, udp_port, tcp_port
            except (OSError, RuntimeError):
                pass
            if docker("inspect", "-f", "{{.State.Running}}", name) != "true":
                break
            time.sleep(0.2)
        raise RuntimeError(docker("logs", name))

    def test_ipv4_udp_and_tcp(self):
        for _, udp, tcp in (self.all_domains, self.listed_domains):
            for port, transport in ((udp, False), (tcp, True)):
                with self.subTest(port=port, tcp=transport):
                    self.assertEqual(query(port, "www.netflix.com", 1, transport),
                                     (0, [(1, socket.inet_aton("192.0.2.10"))]))

    def test_no_ipv6_or_service_hint_escape(self):
        for _, udp, tcp in (self.all_domains, self.listed_domains):
            for port, transport in ((udp, False), (tcp, True)):
                for qtype in (28, 64, 65):
                    with self.subTest(port=port, tcp=transport, qtype=qtype):
                        rcode, answers, authority = query(port, "www.netflix.com", qtype, transport, include_authority=True)
                        self.assertEqual((rcode, answers), (0, []))
                        self.assertEqual(len(authority), 1)
                        self.assertEqual(authority[0][0], 6)
                        self.assertEqual(struct.unpack("!I", authority[0][1][-4:])[0], 60)

    def test_all_domains_rewrites_unlisted_names(self):
        self.assertEqual(query(self.all_domains[1], "probe.invalid", 1),
                         (0, [(1, socket.inet_aton("192.0.2.10"))]))

    def test_nginx_config(self):
        for name, _, _ in (self.all_domains, self.listed_domains):
            docker("exec", name, "nginx", "-t")

    def test_dns_over_tls_on_documented_port(self):
        name, _, _ = self.start("true", enable_dot=True)
        for restarted in (False, True):
            with self.subTest(restarted=restarted):
                if restarted:
                    docker("restart", name)
                    self.wait_ready(name)
                port = int(docker("port", name, "853/tcp").rsplit(":", 1)[1])
                context = ssl.create_default_context(cadata=docker("exec", name, "cat", "/etc/dnsdist/certs/tls.pem"))
                self.assertEqual(query(port, "netflix.com", 1, tcp=True, tls_context=context),
                                 (0, [(1, socket.inet_aton("192.0.2.10"))]))

    def test_listed_mode_forwards_unlisted_domains(self):
        port = self.listed_domains[1]
        for qtype in (1, 28):
            with self.subTest(qtype=qtype):
                rcode, answers = query(port, "example.org", qtype)
                self.assertEqual(rcode, 0)
                self.assertIn(qtype, [record_type for record_type, _ in answers])
                self.assertNotIn((1, socket.inet_aton("192.0.2.10")), answers)

    def test_clients_file_ignores_comments_and_whitespace(self):
        name = self.start("true")[0]
        docker("exec", name, "sh", "-c", "printf '# clients\\r\\n10.0.0.1\\r\\n10.0.0.2 \\n\\n10.0.0.3 # inline\\n' > /tmp/clients")
        docker("exec", name, "env", "ALLOWED_CLIENTS_FILE=/tmp/clients", "bash", "/generateACL.sh")
        self.assertEqual(set(docker("exec", name, "cat", "/etc/dnsdist/allowedClients.acl").splitlines()),
                         {"127.0.0.1", "10.0.0.1", "10.0.0.2", "10.0.0.3"})

    def test_unresolvable_client_does_not_block_startup(self):
        name, port, _ = self.start("true", clients="0.0.0.0/0, unresolvable.invalid")
        self.assertEqual(docker("exec", name, "cat", "/etc/dnsdist/allowedClients.acl").splitlines(),
                         ["0.0.0.0/0", "127.0.0.1"])
        self.assertEqual(query(port, "netflix.com", 1), (0, [(1, socket.inet_aton("192.0.2.10"))]))

    def test_cron_refresh_applies_acl(self):
        name, port, _ = self.start("true")
        docker("exec", name, "env", "ALLOWED_CLIENTS=0.0.0.0/0,10.0.0.9", "bash", "/dynDNSCron.sh")
        self.assertIn("allow 10.0.0.9;", docker("exec", name, "cat", "/etc/nginx/allowedClients.conf"))
        self.assertEqual(query(port, "netflix.com", 1), (0, [(1, socket.inet_aton("192.0.2.10"))]))
        docker("exec", name, "env", "ALLOWED_CLIENTS=127.0.0.1", "bash", "/dynDNSCron.sh")
        with self.assertRaises(socket.timeout):
            query(port, "netflix.com", 1)

    def test_netflix_https_through_proxy_and_logs(self):
        name = self.all_domains[0]
        port = int(docker("port", name, "443/tcp").rsplit(":", 1)[1])
        with socket.create_connection(("127.0.0.1", port), timeout=15) as raw:
            with ssl.create_default_context().wrap_socket(raw, server_hostname="www.netflix.com") as sock:
                sock.sendall(b"GET / HTTP/1.1\r\nHost: www.netflix.com\r\nConnection: close\r\n\r\n")
                response = sock.recv(4096)
                self.assertTrue(response.startswith(b"HTTP/1.1 "), response[:100])
                while sock.recv(65535):
                    pass
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            logs = docker("logs", name)
            if "sni=www.netflix.com status=200 upstream=" in logs:
                break
            time.sleep(0.2)
        self.assertIn("sni=www.netflix.com status=200 upstream=", logs)
        self.assertIn("www.netflix.com", logs)
        self.assertIn("Packet from", logs)

    def test_http_through_proxy(self):
        name = self.all_domains[0]
        port = int(docker("port", name, "80/tcp").rsplit(":", 1)[1])
        with socket.create_connection(("127.0.0.1", port), timeout=15) as sock:
            sock.sendall(b"GET / HTTP/1.1\r\nHost: www.netflix.com\r\nConnection: close\r\n\r\n")
            response = sock.recv(4096)
        self.assertTrue(response.startswith(b"HTTP/1.1 "), response[:100])
        self.assertNotIn(response.split(b"\r\n", 1)[0].split()[1], (b"502", b"504"))

    def test_ddns_cache_and_multiple_addresses(self):
        name, _, _ = self.start("true")
        mock = '#!/bin/sh\n[ ! -f /etc/snidust/ddns-fail ] || exit 1\nprintf \'%s\\n\' \'{"responses":[{"answers":[{"type":"A","address":"192.0.2.20"},{"type":"A","address":"192.0.2.21"}]}]}\'\n'
        docker("exec", "-u", "0", name, "sh", "-c", 'printf "%s" "$1" > /usr/bin/dog', "sh", mock)
        docker("exec", name, "env", "ALLOWED_CLIENTS=client.invalid", "bash", "/generateACL.sh")
        original = docker("exec", name, "cat", "/etc/dnsdist/allowedClients.acl")
        self.assertEqual(set(original.splitlines()), {"127.0.0.1", "192.0.2.20", "192.0.2.21"})
        docker("exec", name, "touch", "/etc/snidust/ddns-fail")
        docker("exec", name, "env", "ALLOWED_CLIENTS=client.invalid,unknown.invalid", "bash", "/generateACL.sh")
        self.assertEqual(docker("exec", name, "cat", "/etc/dnsdist/allowedClients.acl"), original)
        docker("exec", name, "sh", "-c", "jq -c '.[\"client.invalid\"].updated = 0' /etc/snidust/ddns-cache.json > /tmp/cache && cat /tmp/cache > /etc/snidust/ddns-cache.json")
        docker("exec", name, "env", "ALLOWED_CLIENTS=client.invalid", "bash", "/generateACL.sh")
        self.assertEqual(docker("exec", name, "cat", "/etc/dnsdist/allowedClients.acl"), "127.0.0.1")
        docker("exec", name, "rm", "/etc/snidust/ddns-fail")
        docker("exec", name, "env", "ALLOWED_CLIENTS=client.invalid", "bash", "/generateACL.sh")
        self.assertEqual(docker("exec", name, "cat", "/etc/dnsdist/allowedClients.acl"), original)
        docker("exec", name, "env", "ALLOWED_CLIENTS=", "bash", "/generateACL.sh")
        self.assertEqual(docker("exec", name, "cat", "/etc/dnsdist/allowedClients.acl"), "127.0.0.1")
        self.assertEqual(docker("exec", name, "cat", "/etc/snidust/ddns-cache.json"), "{}")
        docker("exec", name, "nginx", "-t")

    def test_acl_reload(self):
        name, port, _ = self.all_domains
        self.assertEqual(query(port, "reload.acl.snidust.local", 1),
                         (0, [(1, socket.inet_aton("127.0.0.7"))]), docker("logs", name))
        docker("exec", name, "nginx", "-t")

    def test_failed_reload_preserves_active_acl(self):
        name, port, _ = self.start("true", from_file=True)
        original = docker("exec", name, "cat", "/etc/nginx/allowedClients.conf")
        docker("exec", name, "rm", "/etc/snidust/test-clients")
        self.assertEqual(query(port, "reload.acl.snidust.local", 1), (2, []))
        self.assertEqual(query(port, "netflix.com", 1), (0, [(1, socket.inet_aton("192.0.2.10"))]))
        self.assertEqual(docker("exec", name, "cat", "/etc/nginx/allowedClients.conf"), original)

    def test_restart_aborts_when_acl_cannot_be_generated(self):
        name, _, _ = self.start("true", from_file=True)
        docker("exec", name, "rm", "/etc/snidust/test-clients")
        docker("restart", name)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if docker("inspect", "-f", "{{.State.Running}}", name) == "false":
                self.assertNotEqual(docker("inspect", "-f", "{{.State.ExitCode}}", name), "0")
                return
            time.sleep(0.2)
        self.fail("Restart reused stale ACL files after ACL generation failed")

    def test_unauthorized_clients_are_rejected(self):
        name, port, _ = self.start("true", from_file=True)
        docker("exec", name, "sh", "-c", "printf '127.0.0.1\\n' > /etc/snidust/test-clients")
        self.assertEqual(query(port, "reload.acl.snidust.local", 1),
                         (0, [(1, socket.inet_aton("127.0.0.7"))]))
        with self.assertRaises(socket.timeout):
            query(port, "netflix.com", 1)
        http_port = int(docker("port", name, "80/tcp").rsplit(":", 1)[1])
        with socket.create_connection(("127.0.0.1", http_port), timeout=5) as sock:
            sock.sendall(b"GET / HTTP/1.1\r\nHost: www.netflix.com\r\nConnection: close\r\n\r\n")
            self.assertTrue(sock.recv(4096).startswith(b"HTTP/1.1 403"))
        tls_port = int(docker("port", name, "443/tcp").rsplit(":", 1)[1])
        with self.assertRaises((ssl.SSLError, ConnectionResetError)):
            with socket.create_connection(("127.0.0.1", tls_port), timeout=5) as raw:
                with ssl.create_default_context().wrap_socket(raw, server_hostname="www.netflix.com"):
                    self.fail("Unauthorized TLS client reached the upstream")

    def test_nginx_exit_stops_container(self):
        name, _, _ = self.start("true")
        docker("exec", name, "nginx", "-s", "quit")
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if docker("inspect", "-f", "{{.State.Running}}", name) == "false":
                return
            time.sleep(0.2)
        self.fail("Container survived Nginx exit")

    def test_dnsdist_exit_stops_container(self):
        name, _, _ = self.start("true")
        docker("exec", name, "pkill", "-TERM", "dnsdist")
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if docker("inspect", "-f", "{{.State.Running}}", name) == "false":
                return
            time.sleep(0.2)
        self.fail("Container survived DNSDist exit")


if __name__ == "__main__":
    unittest.main(verbosity=2)
