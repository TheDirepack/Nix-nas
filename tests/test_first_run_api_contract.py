from __future__ import annotations

import unittest

import nas_first_run_api as first_run_api


class FirstRunApiContractTests(unittest.TestCase):
    def test_private_string_boundary_rejects_multiline_values(self) -> None:
        with self.assertRaises(first_run_api.RequestError):
            first_run_api._single_line("one\ntwo", "test")

    def test_job_identifier_is_strictly_bounded(self) -> None:
        with self.assertRaises(first_run_api.RequestError):
            first_run_api.job_status("../escape")


if __name__ == "__main__":
    unittest.main()
