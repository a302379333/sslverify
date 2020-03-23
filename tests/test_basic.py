import os
from io import StringIO

import pytest

from ..sslverify import CSVReport, SSLVerificator

BASE_DIR = os.path.abspath(os.path.dirname(__file__))


def test_CSVReport():
    with StringIO() as str_buf:
        report = CSVReport([("example.com", "Verified", "Jun 18 10:10:40 2020 GMT")], str_buf)
        result_report = (
            "Host,SSL validity,Expires\r\n" "example.com,Verified,Jun 18 10:10:40 2020 GMT\r\n"
        )

        report.save()

        assert str_buf.getvalue() == result_report


def test_setup_param_input_file(monkeypatch, capsys):
    output_file_path = os.path.join(BASE_DIR, "test_data", "report.csv")
    monkeypatch.delattr(SSLVerificator, "__init__")
    ssl_verificator = SSLVerificator()

    parser = ssl_verificator._setup_params()

    with pytest.raises(SystemExit):
        params = parser.parse_args(["-of", output_file_path])
    err_msg = capsys.readouterr().err
    assert "arguments are required: -if/--input_file" in err_msg


def test_setup_param_output_file(monkeypatch, capsys):
    input_file_path = os.path.join(BASE_DIR, "test_data", "domains.txt")
    monkeypatch.delattr(SSLVerificator, "__init__")
    ssl_verificator = SSLVerificator()

    parser = ssl_verificator._setup_params()

    with pytest.raises(SystemExit):
        params = parser.parse_args(["-if", input_file_path])
    err_msg = capsys.readouterr().err
    assert "arguments are required: -of/--output_file" in err_msg


def test_domain_cleaner():
    cleared_domain = SSLVerificator._get_domain("example.com")

    assert cleared_domain == "example.com"


def test_domain_cleaner_path():
    cleared_domain = SSLVerificator._get_domain("example.com/test")

    assert cleared_domain == "example.com"


def test_domain_cleaner_https():
    cleared_domain = SSLVerificator._get_domain("https://example.com/test/abc/")

    assert cleared_domain == "example.com"


def test_domain_cleaner_http():
    cleared_domain = SSLVerificator._get_domain("http://example.com/test")

    assert cleared_domain == "example.com"


def test_get_domain_list_from_file(monkeypatch):
    class Mp:
        pass

    str_buf = StringIO("https://example.com/test\nhttp://example.com")
    monkeypatch.delattr(SSLVerificator, "__init__")
    ssl_verificator = SSLVerificator()
    ssl_verificator.args = Mp()
    ssl_verificator.args.input_file = str_buf

    domain_list = ssl_verificator._get_domain_list()
    assert domain_list == ["example.com", "example.com"]


def test_get_cert():
    """Use localhost:443 (has no local server)."""
    host_cert = SSLVerificator._get_cert(SSLVerificator, "localhost")

    assert host_cert == ("localhost", None)


def test_full(monkeypatch):
    class MpArgs:
        input_file = StringIO("localhost")
        output_file = StringIO()
        verbosity = SSLVerificator.LEVEL_ERROR
        threads = SSLVerificator.THREADS
        print = False

    output_file_close = MpArgs.output_file.close
    monkeypatch.delattr(SSLVerificator, "__init__")
    monkeypatch.setattr(SSLVerificator, "args", MpArgs, raising=False)
    monkeypatch.setattr(MpArgs.output_file, "close", lambda: None)

    verificator = SSLVerificator()
    verificator.process()

    report = MpArgs.output_file.getvalue()
    output_file_close()
    assert report == "Host,SSL validity,Expires\r\nlocalhost,NOT valid,\r\n"
