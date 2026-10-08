import csv
import os
import tempfile
import unittest

from modules import risk


class RiskEngineTests(unittest.TestCase):
    def test_risk_fusion_uses_requested_weights_and_level_boundaries(self):
        result = risk.calculate_fusion(
            weather_risk=20,
            cyber_risk=60,
            system_risk=80,
        )
        self.assertAlmostEqual(result["overall_risk"], 56.0)
        self.assertEqual(result["severity"], "HIGH")
        self.assertEqual(result["dominant_source"], "SYSTEM")

        low = risk.calculate_fusion(10, 10, 10)
        self.assertEqual(low["severity"], "LOW")
        critical = risk.calculate_fusion(90, 80, 80)
        self.assertEqual(critical["severity"], "CRITICAL")

    def test_cyber_analysis_uses_all_rows_and_isolation_forest(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "cyber.csv")
            with open(path, "w", newline="", encoding="utf-8") as handle:
                writer = csv.writer(handle)
                writer.writerow(["timestamp", "source_ip", "request_count", "bytes_received", "latency_ms", "status_code"])
                for index in range(2500):
                    writer.writerow([
                        f"2026-10-08T00:00:{index % 60:02d}Z",
                        f"10.0.0.{index % 255 + 1}",
                        100 + (index % 19),
                        1000 + (index % 31) * 10,
                        20 + (index % 7),
                        200,
                    ])

            result = risk.analyze_cyber_csv(path)

        self.assertEqual(result["records_analyzed"], 2500)
        self.assertEqual(result["records_uploaded"], 2500)
        self.assertEqual(result["model"], "Isolation Forest")
        self.assertGreaterEqual(result["anomaly_percentage"], 0)
        self.assertLessEqual(result["anomaly_percentage"], 100)
        self.assertIsInstance(result["suspicious_records"], list)

    def test_system_metrics_are_collected_from_psutil(self):
        metrics = risk.collect_system_metrics()
        self.assertIn("cpu", metrics)
        self.assertIn("ram", metrics)
        self.assertIn("disk", metrics)
        self.assertIn("network_activity", metrics)
        self.assertGreaterEqual(metrics["system_risk_score"], 0)
        self.assertLessEqual(metrics["system_risk_score"], 100)

    def test_weatherapi_payload_is_normalized_for_risk_metrics(self):
        payload = {
            "location": {"name": "Local Location", "country": "Local Country"},
            "current": {
                "temp_c": 22.4,
                "precip_mm": 1.5,
                "wind_kph": 18.2,
                "humidity": 63,
                "pressure_mb": 1018.4,
                "condition": {"code": 2, "text": "Partly cloudy"},
            },
        }
        normalized = risk.normalize_weatherapi_payload(payload)
        self.assertEqual(normalized["temperature"], 22.4)
        self.assertEqual(normalized["precipitation"], 1.5)
        self.assertEqual(normalized["wind_speed"], 18.2)
        self.assertEqual(normalized["humidity"], 63)
        self.assertEqual(normalized["pressure"], 1018.4)
        self.assertEqual(normalized["weather_condition"], "Partly cloudy")
        self.assertEqual(normalized["weather_code"], 2)


if __name__ == "__main__":
    unittest.main()
