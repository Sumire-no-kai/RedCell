from redcell.failures import safe_error_message


def test_persisted_error_message_redacts_common_credentials() -> None:
    error = RuntimeError(
        "Authorization: Bearer secret-token api_key=super-secret "
        "provider=sk-proj-abcdefghijklmnopqrstuvwxyz"
    )

    message = safe_error_message(error)

    assert "secret-token" not in message
    assert "super-secret" not in message
    assert "sk-proj-" not in message
    assert message.count("[REDACTED]") == 3
