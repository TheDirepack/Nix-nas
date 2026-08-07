from __future__ import annotations

import json
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "services"))
import nas_syncthing_devices as devices

DEVICE_A = "AAAAAAA-BBBBBBB-CCCCCCC-DDDDDDD-EEEEEEE-FFFFFFF-GGGGGGG-HHHHHHH"


class SyncthingDeviceTests(unittest.TestCase):
    def test_legacy_id_is_normalized_to_narrow_owned_shape(self):
        value = devices.normalize_device(
            {"id": DEVICE_A.lower(), "name": "Laptop", "addresses": ["dynamic", "dynamic"]}
        )
        self.assertEqual(value["deviceID"], DEVICE_A)
        self.assertEqual(value["addresses"], ["dynamic"])
        self.assertFalse(value["autoAcceptFolders"])

    def test_duplicate_ids_and_invalid_usernames_are_rejected(self):
        with self.assertRaises(devices.DeviceError):
            devices.normalize_devices([{"id": DEVICE_A}, {"deviceID": DEVICE_A}])
        with self.assertRaises(devices.DeviceError):
            devices.validate_username("../admin")

    def test_json_array_and_newline_attributes_are_supported(self):
        raw = '{"id":"%s","name":"Laptop","addresses":["dynamic"]}' % DEVICE_A
        self.assertEqual(len(devices.normalize_devices(["[" + raw + "]"])), 1)
        self.assertEqual(len(devices.normalize_devices([raw + "\n"])), 1)

    def test_empty_attribute_removes_all_devices(self):
        self.assertEqual(devices.normalize_devices([]), [])

    def test_invalid_primitive_attributes_fail_loudly(self):
        for value in (1, True, None, 3.14):
            with self.subTest(value=value):
                with self.assertRaises(devices.DeviceError):
                    devices.normalize_devices([value])

    def test_invalid_items_inside_arrays_fail_loudly(self):
        with self.assertRaisesRegex(devices.DeviceError, "list item"):
            devices.normalize_devices([[{"id": DEVICE_A}, 1]])
        with self.assertRaisesRegex(devices.DeviceError, "JSON array item"):
            devices.normalize_devices(['[{"id":"%s"}, false]' % DEVICE_A])

    def test_double_encoded_json_string_has_specific_error(self):
        value = json.dumps(json.dumps({"id": DEVICE_A}))
        with self.assertRaisesRegex(devices.DeviceError, "extra quoting"):
            devices.normalize_devices([value])

    def test_mixed_mapping_and_json_array_inputs_normalize_deterministically(self):
        device_b = "2222222-3333333-4444444-5555555-6666666-7777777-AAAAAAA-BBBBBBB"
        values = [
            {"deviceID": DEVICE_A, "name": "zeta"},
            json.dumps([{"deviceID": device_b, "name": "Alpha"}]),
        ]
        normalized = devices.normalize_devices(values)
        self.assertEqual([item["name"] for item in normalized], ["Alpha", "zeta"])

    def test_control_characters_are_rejected_in_names_and_addresses(self):
        for value in (
            {"deviceID": DEVICE_A, "name": "Laptop\nInjected"},
            {"deviceID": DEVICE_A, "addresses": ["tcp://host:22000\rmalformed"]},
        ):
            with self.subTest(value=value):
                with self.assertRaisesRegex(devices.DeviceError, "control characters"):
                    devices.normalize_device(value)

    def test_device_limit_boundary_is_enforced(self):
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
        values = [
            {"deviceID": "-".join([character * 7] * 8), "name": f"device-{index:02d}"}
            for index, character in enumerate(alphabet[: devices.MAX_DEVICES_PER_USER])
        ]
        self.assertEqual(len(devices.normalize_devices(values)), devices.MAX_DEVICES_PER_USER)
        if devices.MAX_DEVICES_PER_USER < len(alphabet):
            values.append(
                {
                    "deviceID": "-".join([alphabet[devices.MAX_DEVICES_PER_USER] * 7] * 8),
                    "name": "too-many",
                }
            )
            with self.assertRaisesRegex(devices.DeviceError, "At most"):
                devices.normalize_devices(values)

    def test_address_count_and_length_limits_are_enforced(self):
        with self.assertRaisesRegex(devices.DeviceError, "at most"):
            devices.normalize_device(
                {
                    "deviceID": DEVICE_A,
                    "addresses": [f"tcp://host-{index}:22000" for index in range(devices.MAX_ADDRESSES + 1)],
                }
            )
        with self.assertRaisesRegex(devices.DeviceError, "between 1 and"):
            devices.normalize_device(
                {
                    "deviceID": DEVICE_A,
                    "addresses": ["x" * (devices.MAX_ADDRESS_LENGTH + 1)],
                }
            )

    def test_malformed_json_and_primitive_json_are_rejected(self):
        with self.assertRaisesRegex(devices.DeviceError, "must contain JSON"):
            devices.normalize_device("{not-json")
        for encoded in ("null", "false", "17"):
            with self.subTest(encoded=encoded):
                with self.assertRaisesRegex(devices.DeviceError, "JSON object"):
                    devices.normalize_device(encoded)

    def test_explicit_empty_device_id_does_not_fall_back_to_legacy_id(self):
        with self.assertRaisesRegex(devices.DeviceError, "Device ID"):
            devices.normalize_device({"deviceID": "", "id": DEVICE_A})


if __name__ == "__main__":
    unittest.main()
