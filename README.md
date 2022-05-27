# Roundcube plugin "nonce_login"

Plugin to allow login via an nonce, created by an api call, to avoid the sharing of credentials when multiple people use the same account.

When the plugin is installed, the roundcube instance will handle an additional endpoint at `https://mail.example.com/?nonce_login`. A HTTP GET request with a `Basic` `Authorization` header containing the login credntials (e.g. `Authorization: Basic aW5mb0BleGFtcGxlLmNvbTpzZWNyZXQ=`) will respond with a `201` status code and a `Location` header. The URL returned via the `Location` header can be used exactly once to login and does not contain any login credentials.
