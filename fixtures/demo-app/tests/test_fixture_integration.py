import unittest

from fastapi.testclient import TestClient

import main


class SyntheticBookingFixtureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.old_fixed = main.FIXED
        self.client = TestClient(main.app)

    def tearDown(self) -> None:
        self.client.close()
        main.FIXED = self.old_fixed

    def test_cross_agency_record_is_deliberately_exposed_before_fix(self) -> None:
        main.FIXED = False
        response = self.client.get("/api/v1/bookings/2002", headers={"X-Demo-Agency": "agency-a"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["agency_id"], "agency-b")

    def test_cross_agency_record_is_hidden_after_fix(self) -> None:
        main.FIXED = True
        response = self.client.get("/api/v1/bookings/2002", headers={"X-Demo-Agency": "agency-a"})
        self.assertEqual(response.status_code, 404)

    def test_missing_synthetic_identity_is_rejected(self) -> None:
        main.FIXED = False
        response = self.client.get("/api/v1/bookings/2002")
        self.assertEqual(response.status_code, 401)


if __name__ == "__main__":
    unittest.main()
