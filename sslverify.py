"""SSL verification utility."""

import argparse
import csv
import logging
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Optional, Tuple, Type, Union

logging.basicConfig()
logger = logging.getLogger("ssl_verify")


class CSVReport:
    """Report  writer."""

    def __init__(
        self,
        data: List[Tuple[str, str, str]],
        file_descriptor,
        dialect: Union[str, csv.Dialect, Type[csv.Dialect]] = "excel",
    ) -> None:
        self.header = ("Host", "SSL validity", "Expires")
        self.writer = csv.writer(file_descriptor, dialect=dialect)
        self.data = data

    def save(self) -> None:
        """Save report."""
        self.writer.writerow(self.header)
        for row in self.data:
            self.writer.writerow(row)


class SSLVerificator:
    """SSL verificator class."""

    THREADS = 5
    TIMEOUT = 10

    LEVEL_ERROR = 1
    LEVEL_INFO = 2
    LEVEL_DEBUG = 3

    VERBOSITY_LEVELS = {
        LEVEL_ERROR: logging.ERROR,
        LEVEL_INFO: logging.INFO,
        LEVEL_DEBUG: logging.DEBUG,
    }

    def __init__(self) -> None:
        parser = self._setup_params()
        self.args = self._get_args(parser)
        self._set_verbosity()

    def _set_verbosity(self) -> None:
        logger.setLevel(self.VERBOSITY_LEVELS[self.args.verbosity])

    def _setup_params(self) -> argparse.ArgumentParser:
        """Setup all utility parameters."""
        parser = argparse.ArgumentParser(
            description="This utility will help you to check domains SSL validity."
        )
        parser.add_argument(
            "-if",
            "--input_file",
            required=True,
            type=argparse.FileType("r"),
            help="Input file with list of domains names.",
        )
        parser.add_argument(
            "-of",
            "--output_file",
            type=argparse.FileType("w"),
            required=True,
            help="Output csv file with results of checking.",
        )
        parser.add_argument(
            "-v",
            "--verbosity",
            type=int,
            choices=tuple(self.VERBOSITY_LEVELS.keys()),
            default=self.LEVEL_ERROR,
            help="Verbosity level.",
        )
        parser.add_argument(
            "-t", "--threads", type=int, default=self.THREADS, help="Number of threads."
        )
        parser.add_argument(
            "-p", "--print", action="store_true", help="Print domains names to console."
        )
        return parser

    @staticmethod
    def _get_args(parser: argparse.ArgumentParser) -> argparse.Namespace:
        """Return list of parameters."""
        return parser.parse_args()

    def _get_cert(self, domain: str, port: Optional[int] = 443) -> Tuple[str, Union[None, Dict]]:
        context = ssl.SSLContext()
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = True
        context.load_default_certs()

        with context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=domain) as conn:
            try:
                conn.settimeout(self.TIMEOUT)
                conn.connect((domain, port))
                cert = conn.getpeercert()
            except (socket.timeout, ssl.CertificateError, OSError) as ex:
                logger.debug("Error for check %s: %s", domain, ex)
                return (domain, None)
        return (domain, cert)

    def _print_msg(self, msg: Tuple[str, str, str]) -> None:
        if self.args.print:
            print("{:<30} {:<20} {:<20}".format(*msg))

    @staticmethod
    def _get_expire_date(cert: Dict) -> str:
        return cert.get("notAfter", "")

    @staticmethod
    def _get_domain(line: str) -> str:
        """Return domain name from string."""
        line = line.strip().replace("https://", "").replace("http://", "").split("/")[0]
        return line

    def _get_report_writer(self) -> Type[CSVReport]:
        return CSVReport

    def _report(self, result: List[Tuple[str, str, str]]) -> None:
        """Save report."""
        report_class = self._get_report_writer()
        with self.args.output_file as out_fl:
            report = report_class(result, out_fl)
            report.save()

    def _get_domain_list(self) -> List[str]:
        """Return list of domains from file."""
        result = []
        with self.args.input_file as input_file:
            for idx, line in enumerate(input_file.readlines()):
                domain = self._get_domain(line)
                if not domain:
                    logger.warning("Wrong domain name at line %s.", idx + 1)
                    continue
                result.append(domain)
        return result

    def _validate_domains(self, domain_list: List[str]) -> List[Tuple[str, str, str]]:
        """Validate domain list."""
        result = []
        with ThreadPoolExecutor(max_workers=self.args.threads) as th_pool:
            for domain, cert_data in th_pool.map(self._get_cert, domain_list):
                domain_ssl_info = (
                    domain,
                    "valid" if cert_data else "NOT valid",
                    self._get_expire_date(cert_data) if cert_data else "",
                )
                self._print_msg(domain_ssl_info)
                result.append(domain_ssl_info)
        return result

    def process(self) -> None:
        """Entry point."""
        domain_list = self._get_domain_list()
        result_list = self._validate_domains(domain_list)
        self._report(result_list)


if __name__ == "__main__":
    verificator = SSLVerificator()
    verificator.process()
