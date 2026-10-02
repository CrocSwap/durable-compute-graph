"""graph-plan-v2 §5 value digest vector (shared with the Rust program test)."""

import struct
import unittest

from dcg import descent


class ValueDigestVector(unittest.TestCase):
    def test_i32_42(self):
        self.assertEqual(descent.value_digest(struct.pack("<i", 42)).hex(),
                         "1747c7d807a1bde7bbdbf92a721cfbe688e61715ce4391980fe7ee09e2ff95e1")


if __name__ == "__main__":
    unittest.main()
