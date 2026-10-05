"""HTTP layer tests: status codes, response shapes and error envelopes."""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.schemas.crypto import MAX_TEXT_BYTES

from .conftest import flip_ciphertext_byte

ENCODE_URL = "/api/encode"
ENCRYPTION_URL = "/api/encryption"
HASH_URL = "/api/hash"
BCRYPT_VERIFY_URL = "/api/hash/bcrypt/verify"


class TestSystem:
    def test_health_returns_ok(self, client: TestClient) -> None:
        response = client.get("/api/health")
        assert response.status_code == 200
        assert response.json() == {"status": "ok", "service": "cipherforge", "version": "1.0.0"}

    def test_openapi_schema_is_available(self, client: TestClient) -> None:
        assert client.get("/openapi.json").status_code == 200

    def test_docs_are_available(self, client: TestClient) -> None:
        assert client.get("/docs").status_code == 200

    def test_unknown_route_returns_structured_error(self, client: TestClient) -> None:
        response = client.get("/api/does-not-exist")
        assert response.status_code == 404
        assert response.json()["error"]["code"] == "HTTP_ERROR"


class TestAlgorithmsEndpoint:
    def test_returns_all_three_categories(self, client: TestClient) -> None:
        body = client.get("/api/algorithms").json()
        assert body["categories"] == ["encode", "encryption", "hash"]
        assert len(body["encode"]) == 2
        assert len(body["encryption"]) == 5
        assert len(body["hash"]) == 4

    def test_des_is_marked_legacy_and_disabled(self, client: TestClient) -> None:
        body = client.get("/api/algorithms").json()
        des = next(entry for entry in body["encryption"] if entry["id"] == "des")
        assert des["security_status"] == "legacy"
        assert des["disabled"] is True
        assert des["operations"] == []
        assert "56-bit" in des["disabled_reason"]

    def test_md5_is_marked_broken(self, client: TestClient) -> None:
        body = client.get("/api/algorithms").json()
        md5_entry = next(entry for entry in body["hash"] if entry["id"] == "md5")
        assert md5_entry["security_status"] == "broken"
        assert "BROKEN" in md5_entry["security_info"]["warning"]

    def test_base64_declares_it_is_not_encryption(self, client: TestClient) -> None:
        body = client.get("/api/algorithms").json()
        base64_entry = next(entry for entry in body["encode"] if entry["id"] == "base64")
        assert base64_entry["security_info"]["encryption"] is False

    def test_aes_advertises_authentication(self, client: TestClient) -> None:
        body = client.get("/api/algorithms").json()
        aes_entry = next(entry for entry in body["encryption"] if entry["id"] == "aes")
        assert aes_entry["security_status"] == "recommended"
        assert "Authentication" in aes_entry["security_info"]["provides"]


class TestEncodeEndpoint:
    def test_base64_encode(self, client: TestClient) -> None:
        response = client.post(
            ENCODE_URL, json={"algorithm": "base64", "operation": "encode", "input": "CipherForge"}
        )
        assert response.status_code == 200
        assert response.json() == {
            "success": True,
            "algorithm": "base64",
            "operation": "encode",
            "output": "Q2lwaGVyRm9yZ2U=",
        }

    def test_base64_decode(self, client: TestClient) -> None:
        response = client.post(
            ENCODE_URL, json={"algorithm": "base64", "operation": "decode", "input": "Q2lwaGVyRm9yZ2U="}
        )
        assert response.json()["output"] == "CipherForge"

    def test_hex_encode_and_decode(self, client: TestClient) -> None:
        encoded = client.post(
            ENCODE_URL, json={"algorithm": "hex", "operation": "encode", "input": "abc"}
        ).json()
        assert encoded["output"] == "616263"
        decoded = client.post(
            ENCODE_URL, json={"algorithm": "hex", "operation": "decode", "input": "616263"}
        ).json()
        assert decoded["output"] == "abc"

    def test_invalid_base64_returns_400_with_error_code(self, client: TestClient) -> None:
        response = client.post(
            ENCODE_URL, json={"algorithm": "base64", "operation": "decode", "input": "!!!not base64!!!"}
        )
        assert response.status_code == 400
        assert response.json()["success"] is False
        assert response.json()["error"]["code"] == "INVALID_ENCODING"
        assert "Base64" in response.json()["error"]["message"]

    def test_invalid_hex_returns_400(self, client: TestClient) -> None:
        response = client.post(
            ENCODE_URL, json={"algorithm": "hex", "operation": "decode", "input": "zz"}
        )
        assert response.status_code == 400
        assert response.json()["error"]["code"] == "INVALID_ENCODING"

    def test_empty_input_returns_400(self, client: TestClient) -> None:
        response = client.post(
            ENCODE_URL, json={"algorithm": "base64", "operation": "encode", "input": ""}
        )
        assert response.status_code == 400
        assert response.json()["error"]["code"] == "INVALID_INPUT"

    def test_unknown_algorithm_returns_400(self, client: TestClient) -> None:
        response = client.post(
            ENCODE_URL, json={"algorithm": "rot13", "operation": "encode", "input": "abc"}
        )
        assert response.status_code == 400

    def test_unknown_field_is_rejected(self, client: TestClient) -> None:
        response = client.post(
            ENCODE_URL,
            json={"algorithm": "base64", "operation": "encode", "input": "abc", "extra": True},
        )
        assert response.status_code == 400
        assert response.json()["error"]["code"] == "INVALID_INPUT"

    def test_oversized_text_is_rejected(self, client: TestClient) -> None:
        response = client.post(
            ENCODE_URL,
            json={
                "algorithm": "base64",
                "operation": "encode",
                "input": "A" * (MAX_TEXT_BYTES + 1),
            },
        )
        assert response.status_code in (400, 413)
        assert response.json()["error"]["code"] in ("INVALID_INPUT", "PAYLOAD_TOO_LARGE")


class TestAesEndpoint:
    def test_encrypt_returns_key_and_nonce(self, client: TestClient) -> None:
        response = client.post(
            ENCRYPTION_URL,
            json={"algorithm": "aes", "operation": "encrypt", "input": "CipherForge"},
        )
        assert response.status_code == 200
        body = response.json()
        assert len(body["key"]) == 64
        assert len(body["nonce"]) == 24
        assert body["ciphertext"]

    def test_encrypt_decrypt_round_trip(self, client: TestClient) -> None:
        encrypted = client.post(
            ENCRYPTION_URL,
            json={"algorithm": "aes", "operation": "encrypt", "input": "Attack at dawn"},
        ).json()
        decrypted = client.post(
            ENCRYPTION_URL,
            json={
                "algorithm": "aes",
                "operation": "decrypt",
                "ciphertext": encrypted["ciphertext"],
                "key": encrypted["key"],
                "nonce": encrypted["nonce"],
            },
        )
        assert decrypted.status_code == 200
        assert decrypted.json()["output"] == "Attack at dawn"

    def test_tampered_ciphertext_is_rejected(self, client: TestClient) -> None:
        encrypted = client.post(
            ENCRYPTION_URL,
            json={"algorithm": "aes", "operation": "encrypt", "input": "Attack at dawn"},
        ).json()
        response = client.post(
            ENCRYPTION_URL,
            json={
                "algorithm": "aes",
                "operation": "decrypt",
                "ciphertext": flip_ciphertext_byte(encrypted["ciphertext"]),
                "key": encrypted["key"],
                "nonce": encrypted["nonce"],
            },
        )
        assert response.status_code == 400
        assert response.json()["error"]["code"] == "DECRYPTION_FAILED"

    def test_missing_key_returns_400(self, client: TestClient) -> None:
        response = client.post(
            ENCRYPTION_URL,
            json={"algorithm": "aes", "operation": "decrypt", "ciphertext": "AAAA"},
        )
        assert response.status_code == 400
        assert "key" in response.json()["error"]["message"]

    def test_malformed_key_returns_400(self, client: TestClient) -> None:
        response = client.post(
            ENCRYPTION_URL,
            json={
                "algorithm": "aes",
                "operation": "decrypt",
                "ciphertext": "AAAAAAAAAAAAAAAAAAAAAA==",
                "key": "nothex",
                "nonce": "00" * 12,
            },
        )
        assert response.status_code == 400
        assert response.json()["error"]["code"] == "INVALID_INPUT"


class TestChaCha20Endpoint:
    def test_encrypt_decrypt_round_trip(self, client: TestClient) -> None:
        encrypted = client.post(
            ENCRYPTION_URL,
            json={"algorithm": "chacha20", "operation": "encrypt", "input": "ChaCha payload"},
        ).json()
        assert len(encrypted["key"]) == 64
        assert len(encrypted["nonce"]) == 24
        decrypted = client.post(
            ENCRYPTION_URL,
            json={
                "algorithm": "chacha20",
                "operation": "decrypt",
                "ciphertext": encrypted["ciphertext"],
                "key": encrypted["key"],
                "nonce": encrypted["nonce"],
            },
        )
        assert decrypted.json()["output"] == "ChaCha payload"

    def test_tampered_ciphertext_is_rejected(self, client: TestClient) -> None:
        encrypted = client.post(
            ENCRYPTION_URL,
            json={"algorithm": "chacha20", "operation": "encrypt", "input": "ChaCha payload"},
        ).json()
        response = client.post(
            ENCRYPTION_URL,
            json={
                "algorithm": "chacha20",
                "operation": "decrypt",
                "ciphertext": "AAAAAAAAAAAAAAAAAAAAAA==",
                "key": encrypted["key"],
                "nonce": encrypted["nonce"],
            },
        )
        assert response.status_code == 400
        assert response.json()["error"]["code"] == "DECRYPTION_FAILED"


class TestRsaEndpoint:
    def test_key_generation_returns_pem_pair(self, client: TestClient) -> None:
        response = client.post(
            ENCRYPTION_URL, json={"algorithm": "rsa", "operation": "generate_key_pair"}
        )
        assert response.status_code == 200
        body = response.json()
        assert "BEGIN PUBLIC KEY" in body["public_key"]
        assert "BEGIN PRIVATE KEY" in body["private_key"]
        assert "190 bytes" in body["work_note"]

    def test_encrypt_decrypt_round_trip(self, client: TestClient) -> None:
        keys = client.post(
            ENCRYPTION_URL, json={"algorithm": "rsa", "operation": "generate_key_pair"}
        ).json()
        encrypted = client.post(
            ENCRYPTION_URL,
            json={
                "algorithm": "rsa",
                "operation": "encrypt",
                "input": "Short secret",
                "public_key": keys["public_key"],
            },
        )
        assert encrypted.status_code == 200
        decrypted = client.post(
            ENCRYPTION_URL,
            json={
                "algorithm": "rsa",
                "operation": "decrypt",
                "ciphertext": encrypted.json()["ciphertext"],
                "private_key": keys["private_key"],
            },
        )
        assert decrypted.json()["output"] == "Short secret"

    def test_oversized_plaintext_returns_400(self, client: TestClient) -> None:
        keys = client.post(
            ENCRYPTION_URL, json={"algorithm": "rsa", "operation": "generate_key_pair"}
        ).json()
        response = client.post(
            ENCRYPTION_URL,
            json={
                "algorithm": "rsa",
                "operation": "encrypt",
                "input": "A" * 500,
                "public_key": keys["public_key"],
            },
        )
        assert response.status_code == 400
        assert response.json()["error"]["code"] == "PLAINTEXT_TOO_LARGE"

    def test_encrypt_without_public_key_returns_400(self, client: TestClient) -> None:
        response = client.post(
            ENCRYPTION_URL,
            json={"algorithm": "rsa", "operation": "encrypt", "input": "secret"},
        )
        assert response.status_code == 400
        assert "public_key" in response.json()["error"]["message"]

    def test_invalid_public_key_returns_400(self, client: TestClient) -> None:
        response = client.post(
            ENCRYPTION_URL,
            json={
                "algorithm": "rsa",
                "operation": "encrypt",
                "input": "secret",
                "public_key": "-----BEGIN PUBLIC KEY-----\nbroken\n-----END PUBLIC KEY-----",
            },
        )
        assert response.status_code == 400
        assert response.json()["error"]["code"] == "INVALID_INPUT"

    def test_key_generation_rejected_for_non_rsa_algorithm(self, client: TestClient) -> None:
        response = client.post(
            ENCRYPTION_URL, json={"algorithm": "aes", "operation": "generate_key_pair"}
        )
        assert response.status_code == 400


class TestCaesarEndpoint:
    def test_encrypt_and_decrypt(self, client: TestClient) -> None:
        encrypted = client.post(
            ENCRYPTION_URL,
            json={"algorithm": "caesar", "operation": "encrypt", "input": "Hello", "shift": 3},
        ).json()
        assert encrypted["output"] == "Khoor"
        assert "Educational" in encrypted["work_note"]
        decrypted = client.post(
            ENCRYPTION_URL,
            json={"algorithm": "caesar", "operation": "decrypt", "input": "Khoor", "shift": 3},
        ).json()
        assert decrypted["output"] == "Hello"

    def test_missing_shift_returns_400(self, client: TestClient) -> None:
        response = client.post(
            ENCRYPTION_URL,
            json={"algorithm": "caesar", "operation": "encrypt", "input": "Hello"},
        )
        assert response.status_code == 400
        assert "shift" in response.json()["error"]["message"]


class TestDesEndpoint:
    def test_des_encryption_is_disabled(self, client: TestClient) -> None:
        response = client.post(
            ENCRYPTION_URL,
            json={"algorithm": "des", "operation": "encrypt", "input": "Hello"},
        )
        assert response.status_code == 400
        message = response.json()["error"]["message"]
        assert "56-bit" in message
        assert "disabled" in message.lower()

    def test_des_decryption_is_disabled(self, client: TestClient) -> None:
        response = client.post(
            ENCRYPTION_URL,
            json={"algorithm": "des", "operation": "decrypt", "ciphertext": "AAAA"},
        )
        assert response.status_code == 400


class TestHashEndpoint:
    def test_md5_known_value(self, client: TestClient) -> None:
        response = client.post(HASH_URL, json={"algorithm": "md5", "input": "abc"})
        assert response.status_code == 200
        assert response.json()["hash"] == "900150983cd24fb0d6963f7d28e17f72"
        assert response.json()["digest_size_bits"] == 128

    def test_sha256_known_value(self, client: TestClient) -> None:
        response = client.post(HASH_URL, json={"algorithm": "sha256", "input": "abc"})
        assert response.json()["hash"] == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        assert response.json()["digest_size_bits"] == 256

    def test_sha512_known_value(self, client: TestClient) -> None:
        response = client.post(HASH_URL, json={"algorithm": "sha512", "input": "abc"})
        assert response.json()["hash"].startswith("ddaf35a193617abacc417349ae20413112")
        assert response.json()["digest_size_bits"] == 512

    def test_bcrypt_hash_uses_default_work_factor(self, client: TestClient) -> None:
        response = client.post(HASH_URL, json={"algorithm": "bcrypt", "input": "s3cret-pass"})
        assert response.status_code == 200
        body = response.json()
        assert body["hash"].startswith("$2b$12$")
        assert body["work_factor"] == 12

    def test_bcrypt_hash_respects_work_factor(self, client: TestClient) -> None:
        response = client.post(
            HASH_URL, json={"algorithm": "bcrypt", "input": "s3cret-pass", "work_factor": 5}
        )
        assert response.json()["hash"].startswith("$2b$05$")
        assert response.json()["work_factor"] == 5

    def test_plaintext_password_is_never_returned(self, client: TestClient) -> None:
        response = client.post(HASH_URL, json={"algorithm": "bcrypt", "input": "do-not-leak-me"})
        assert "do-not-leak-me" not in response.text

    def test_work_factor_on_sha256_is_rejected(self, client: TestClient) -> None:
        response = client.post(
            HASH_URL, json={"algorithm": "sha256", "input": "abc", "work_factor": 10}
        )
        assert response.status_code == 400
        assert "bcrypt" in response.json()["error"]["message"]

    def test_verify_operation_on_hash_endpoint_is_rejected(self, client: TestClient) -> None:
        response = client.post(HASH_URL, json={"algorithm": "sha256", "input": "abc", "operation": "verify"})
        assert response.status_code == 400

    def test_empty_input_is_rejected(self, client: TestClient) -> None:
        response = client.post(HASH_URL, json={"algorithm": "sha256", "input": ""})
        assert response.status_code == 400


class TestBcryptVerifyEndpoint:
    def test_correct_password_verifies(self, client: TestClient) -> None:
        generated = client.post(
            HASH_URL, json={"algorithm": "bcrypt", "input": "s3cret-pass", "work_factor": 5}
        ).json()
        response = client.post(
            BCRYPT_VERIFY_URL, json={"password": "s3cret-pass", "hash": generated["hash"]}
        )
        assert response.status_code == 200
        assert response.json() == {
            "success": True,
            "algorithm": "bcrypt",
            "operation": "verify",
            "verified": True,
        }

    def test_wrong_password_reports_false_without_error(self, client: TestClient) -> None:
        generated = client.post(
            HASH_URL, json={"algorithm": "bcrypt", "input": "s3cret-pass", "work_factor": 5}
        ).json()
        response = client.post(
            BCRYPT_VERIFY_URL, json={"password": "wrong-pass", "hash": generated["hash"]}
        )
        assert response.status_code == 200
        assert response.json()["verified"] is False

    def test_malformed_hash_returns_400(self, client: TestClient) -> None:
        response = client.post(
            BCRYPT_VERIFY_URL, json={"password": "s3cret-pass", "hash": "not-a-bcrypt-hash"}
        )
        assert response.status_code == 400
        assert response.json()["error"]["code"] == "INVALID_INPUT"

    def test_over_long_password_returns_400(self, client: TestClient) -> None:
        generated = client.post(
            HASH_URL, json={"algorithm": "bcrypt", "input": "s3cret-pass", "work_factor": 5}
        ).json()
        response = client.post(
            BCRYPT_VERIFY_URL, json={"password": "A" * 200, "hash": generated["hash"]}
        )
        assert response.status_code == 400
        assert response.json()["error"]["code"] == "PASSWORD_TOO_LONG"

    def test_response_never_contains_the_password(self, client: TestClient) -> None:
        generated = client.post(
            HASH_URL, json={"algorithm": "bcrypt", "input": "s3cret-pass", "work_factor": 5}
        ).json()
        response = client.post(
            BCRYPT_VERIFY_URL, json={"password": "s3cret-pass", "hash": generated["hash"]}
        )
        assert "s3cret-pass" not in response.text