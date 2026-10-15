from nmap_gui import askpass


def test_cancel_authentication_emits_no_password(qt_app, monkeypatch, capsys):
    monkeypatch.setattr(askpass.QInputDialog, "getText", lambda *args: ("", False))
    assert askpass.main() == 1
    assert capsys.readouterr().out == ""


def test_helper_response_goes_only_to_stdout(qt_app, monkeypatch, capsys):
    # A synthetic sentinel, never a real password or sudo invocation.
    monkeypatch.setattr(askpass.QInputDialog, "getText", lambda *args: ("test-sentinel", True))
    assert askpass.main() == 0
    captured = capsys.readouterr()
    assert captured.out == "test-sentinel\n"
    assert captured.err == ""
