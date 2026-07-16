import unittest

from broken import should_return_true


class IntentionalFailure(unittest.TestCase):
    def test_detected(self):
        self.assertTrue(should_return_true(), "intentional synthetic failure")
