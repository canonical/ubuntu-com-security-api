import os
import unittest
from unittest.mock import patch
from cryptography.fernet import Fernet
from webapp.auth import (
    create_time_based_token,
    TOKEN_DELIMITER,
    get_auth_params,
)
from webapp.auth import save_access_token
from webapp.auth import get_access_token


class TestAuth(unittest.TestCase):
    @patch("webapp.auth.get_flask_env")
    def test_create_time_based_token_contains_timestamp(self, mock_get_flask_env):
        """Test that created token contains encrypted timestamp."""
        salt = Fernet.generate_key()
        mock_get_flask_env.return_value = salt

        raw_token = "test_token"
        token = create_time_based_token(raw_token)

        # Decrypt and verify structure
        fernet = Fernet(salt)
        decrypted = fernet.decrypt(token.encode()).decode()

        self.assertIn(TOKEN_DELIMITER, decrypted)
        parts = decrypted.split(TOKEN_DELIMITER)
        self.assertEqual(parts[0], raw_token)
        self.assertTrue(parts[1].isdigit())

    @patch("webapp.auth.get_flask_env")
    def test_create_time_based_token_different_tokens_different_output(
        self, mock_get_flask_env
    ):
        """Test that different raw tokens produce different encrypted outputs."""
        salt = Fernet.generate_key()
        mock_get_flask_env.return_value = salt

        token1 = create_time_based_token("token1")
        token2 = create_time_based_token("token2")

        self.assertNotEqual(token1, token2)

    @patch("webapp.auth.get_flask_env")
    def test_get_auth_params_valid_input(self, mock_get_flask_env):
        """Test that get_auth_params returns correct dictionary for valid input."""
        mock_get_flask_env.return_value = "dummy_env"
        text = "oauth_token=abc123&oauth_token_secret=xyz456"
        expected_output = {"oauth_token": "abc123", "oauth_token_secret": "xyz456"}

        result = get_auth_params(text)
        self.assertEqual(result, expected_output)

    @patch("builtins.open", create=True)
    @patch("os.path.exists")
    def test_save_access_token_new_file(self, mock_exists, mock_open):
        """Test save_access_token creates file if it doesn't exist."""

        mock_exists.return_value = False
        mock_file = mock_open()

        with patch("builtins.open", mock_file):
            save_access_token("request_token_1", "oauth_token&secret")

        self.assertTrue(mock_file.called)

    def test_file_operations_on_access_token(self):
        """Test save_access_token appends to existing file."""

        # Remove any existing file
        location = "/tmp/test_access_tokens.json"
        if os.path.exists(location):
            os.remove(location)

        # First save
        save_access_token("new_token", "access_oauth&secret", location=location)
        self.assertTrue(os.path.exists(location))

        #  Check content
        token = get_access_token("new_token", location=location)
        self.assertEqual(token, "access_oauth&secret")


if __name__ == "__main__":
    unittest.main()
