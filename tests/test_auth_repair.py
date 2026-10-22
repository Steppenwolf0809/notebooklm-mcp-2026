import unittest
from unittest.mock import patch, MagicMock
from notebooklm_mcp_2026 import auth, config


class AuthRepairTests(unittest.TestCase):
    def test_waits_for_notebook_instead_of_redirecting_password_page(self):
        required = [dict(name=n, domain='.google.com', value='synthetic')
                    for n in config.REQUIRED_COOKIES]
        process = MagicMock()
        with patch.object(auth, '_launch_chrome', return_value=process), \
             patch.object(auth, '_find_notebooklm_page', return_value={'webSocketDebuggerUrl': 'mock'}), \
             patch.object(auth, '_get_page_cookies', return_value=required), \
             patch.object(auth, '_get_current_url', side_effect=[
                 'https://accounts.google.com/v3/signin/challenge/pwd',
                 'https://notebook.google.com/']), \
             patch.object(auth, '_get_page_html', return_value='"SNlM0e":"test-csrf","FdrFJe":"-123"'), \
             patch.object(auth, '_navigate_to_url') as navigate, \
             patch.object(auth.time, 'sleep') as sleep:
            tokens = auth.extract_cookies_via_cdp(port=9222)
        self.assertEqual(navigate.call_count, 0, 'Must not interrupt Google password entry')
        self.assertGreaterEqual(sleep.call_count, 1, 'Must wait for the user to finish')
        self.assertEqual(tokens.csrf_token, 'test-csrf')
        self.assertEqual(tokens.session_id, '-123')

    def test_host_cookie_wins_and_accounts_cookie_is_excluded(self):
        raw = [dict(name='OSID', domain='notebook.google.com', value='correct'),
               dict(name='OSID', domain='accounts.google.com', value='wrong'),
               dict(name='OSID', domain='notebooklm.google.com', value='old'),
               dict(name='SID', domain='.google.com', value='shared'),
               dict(name='SID', domain='evilgoogle.com', value='unrelated')]
        selected = auth.select_essential_cookies(raw)
        self.assertEqual(selected, {'OSID': 'correct', 'SID': 'shared'})

    def test_negative_session_id(self):
        self.assertEqual(auth.extract_session_id_from_html('"FdrFJe":"-9223372036854775807"'),
                         '-9223372036854775807')

    def test_incomplete_login_times_out_without_saving_or_navigating(self):
        process = MagicMock()
        with patch.object(auth, '_launch_chrome', return_value=process), \
             patch.object(auth, '_find_notebooklm_page', return_value={'webSocketDebuggerUrl': 'mock'}), \
             patch.object(auth, '_get_current_url', return_value='https://accounts.google.com/signin'), \
             patch.object(auth, '_navigate_to_url') as navigate, \
             patch.object(auth, 'save_tokens') as save, \
             patch.object(auth.time, 'sleep'), \
             patch.object(auth.time, 'time', side_effect=[0, 0, 2]):
            with self.assertRaisesRegex(RuntimeError, 'Login timed out'):
                auth.extract_cookies_via_cdp(port=9222, login_timeout=1)
        navigate.assert_not_called()
        save.assert_not_called()
        process.terminate.assert_called_once()

    def test_api_and_login_use_same_host(self):
        self.assertEqual(config.BASE_URL, 'https://notebook.google.com')
        self.assertEqual(auth.NOTEBOOKLM_URL, config.BASE_URL + '/')


if __name__ == '__main__':
    unittest.main()
