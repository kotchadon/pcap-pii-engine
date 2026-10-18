"""Disconnected browsers must not turn completed analyses into server error loops."""
import pytest

from packet_pii.dashboard import DashboardHandler


@pytest.mark.parametrize("where", ["headers", "body"])
@pytest.mark.parametrize("failure", [BrokenPipeError, ConnectionResetError, ConnectionAbortedError])
def test_disconnected_client_is_not_sent_a_second_error(where, failure):
    handler = object.__new__(DashboardHandler)
    class DisconnectedWriter:
        def write(self, data):
            raise failure("test: client left")
    handler.wfile = DisconnectedWriter()
    handler.close_connection = False
    if where == "headers":
        def failing_headers(*args):
            raise failure("test: client left before headers")
        handler._headers = failing_headers
    else:
        def successful_headers(*args):
            return None
        handler._headers = successful_headers
    handler._reply({"error": "safe dummy"}, 200)
    assert handler.close_connection is True
