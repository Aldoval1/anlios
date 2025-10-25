import unittest
from website.web_dashboard import app

class TestApp(unittest.TestCase):
    def test_app_creation(self):
        """Test that the Flask app can be created without crashing."""
        self.assertIsNotNone(app)

if __name__ == '__main__':
    unittest.main()
