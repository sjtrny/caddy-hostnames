import os
import socket
import struct
import unittest


os.environ["PUBLISHED_IP"] = "192.168.20.10"

import monitor  # noqa: E402


def query(*questions, transaction_id=0):
    payload = struct.pack("!6H", transaction_id, 0, len(questions), 0, 0, 0)
    for name, record_type, record_class in questions:
        payload += monitor.encode_name(name)
        payload += struct.pack("!HH", record_type, record_class)
    return payload


class HostnameParsingTests(unittest.TestCase):
    def test_extracts_local_hosts_from_labels_and_urls(self):
        labels = {
            "caddy": "one.local, https://Two.Local:8443/path public.example",
            "caddy_2": "deep.name.local",
            "caddy.reverse_proxy": "ignored.local",
        }
        self.assertEqual(
            monitor.parse_site_addresses(labels),
            [
                "one.local",
                "https://Two.Local:8443/path",
                "public.example",
                "deep.name.local",
            ],
        )
        self.assertEqual(monitor.parse_local_hostname("one.local"), "one.local")
        self.assertEqual(
            monitor.parse_local_hostname("https://Two.Local:8443/path"),
            "two.local",
        )
        self.assertIsNone(monitor.parse_local_hostname("public.example"))

    def test_rejects_empty_and_oversized_labels(self):
        self.assertIsNone(monitor.parse_local_hostname(".local"))
        self.assertIsNone(monitor.parse_local_hostname("bad..local"))
        with self.assertRaises(ValueError):
            monitor.parse_local_hostname(("x" * 64) + ".local")


class DnsPacketTests(unittest.TestCase):
    def test_parses_compressed_question_name(self):
        first = monitor.encode_name("alias.local") + struct.pack(
            "!HH", monitor.TYPE_A, monitor.CLASS_IN
        )
        second = b"\xc0\x0c" + struct.pack(
            "!HH", monitor.TYPE_AAAA, monitor.CLASS_IN
        )
        packet = struct.pack("!6H", 19, 0, 2, 0, 0, 0) + first + second

        transaction_id, flags, questions = monitor.parse_questions(packet)

        self.assertEqual(transaction_id, 19)
        self.assertEqual(flags, 0)
        self.assertEqual(
            questions,
            [
                ("alias.local.", monitor.TYPE_A, monitor.CLASS_IN),
                ("alias.local.", monitor.TYPE_AAAA, monitor.CLASS_IN),
            ],
        )

    def test_a_answer_has_address_and_nsec_additional(self):
        packet = query(("alias.local", monitor.TYPE_A, monitor.CLASS_IN))
        _, _, questions = monitor.parse_questions(packet)

        response = monitor.build_response(
            questions, {"alias.local."}, "192.168.20.10"
        )

        header = struct.unpack_from("!6H", response)
        self.assertEqual(header, (0, monitor.FLAG_RESPONSE_AUTHORITATIVE, 0, 1, 0, 1))
        self.assertIn(socket.inet_aton("192.168.20.10"), response)

    def test_aaaa_answer_is_nsec_without_an_a_record(self):
        packet = query(("alias.local", monitor.TYPE_AAAA, monitor.CLASS_IN))
        _, _, questions = monitor.parse_questions(packet)

        response = monitor.build_response(
            questions, {"alias.local."}, "192.168.20.10"
        )

        header = struct.unpack_from("!6H", response)
        self.assertEqual(header, (0, monitor.FLAG_RESPONSE_AUTHORITATIVE, 0, 1, 0, 0))
        name, position = monitor.read_name(response, 12)
        record_type = struct.unpack_from("!H", response, position)[0]
        self.assertEqual(name, "alias.local.")
        self.assertEqual(record_type, monitor.TYPE_NSEC)
        self.assertNotIn(socket.inet_aton("192.168.20.10"), response)

    def test_ignores_dns_sd_and_unknown_host_questions(self):
        questions = [
            ("_http._tcp.local.", 12, monitor.CLASS_IN),
            ("unknown.local.", monitor.TYPE_A, monitor.CLASS_IN),
        ]
        self.assertIsNone(
            monitor.build_response(questions, {"alias.local."}, "192.168.20.10")
        )

    def test_malformed_compression_loop_is_rejected(self):
        with self.assertRaises(ValueError):
            monitor.read_name(b"\xc0\x00", 0)


class RegistrationTests(unittest.TestCase):
    def test_shared_hostname_uses_reference_counts(self):
        responder = monitor.HostnameResponder("192.168.20.10")
        responder.add_hostname("shared.local")
        responder.add_hostname("shared.local")

        responder.remove_hostname("shared.local")
        self.assertIn("shared.local.", responder.hostnames)

        responder.remove_hostname("shared.local")
        self.assertNotIn("shared.local.", responder.hostnames)


if __name__ == "__main__":
    unittest.main()
