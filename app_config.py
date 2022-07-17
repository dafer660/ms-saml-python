import os

CLIENT_ID = "fee6744d-99e2-4c46-bc2a-e9888620e61a" # Application (client) ID of app registration
TENANT_ID = '5b1ffd9e-af62-4db2-8b6e-846b12783d79'
OBJECT_ID = "8261d51a-e674-464d-b8ae-a4027bf0902c"

USERNAME = 'test1@danielferr18hotmail.onmicrosoft.com'
PASSWORD = 'Bazinga2@'

CLIENT_SECRET = "xIZ8Q~opA~i-bEE7KGbW3i6JVjleVPtG1dpxhaj0" # Placeholder - for use ONLY during testing.
# In a production app, we recommend you use a more secure method of storing your secret,
# like Azure Key Vault. Or, use an environment variable as described in Flask's documentation:
# https://flask.palletsprojects.com/en/1.1.x/config/#configuring-from-environment-variables
# CLIENT_SECRET = os.getenv("CLIENT_SECRET")
# if not CLIENT_SECRET:
#     raise ValueError("Need to define CLIENT_SECRET environment variable")

# AUTHORITY = "https://login.microsoftonline.com/5b1ffd9e-af62-4db2-8b6e-846b12783d79"  # For multi-tenant app
AUTHORITY = "https://login.microsoftonline.com/danielferr18hotmail.onmicrosoft.com"

REDIRECT_PATH = "/getAToken"  # Used for forming an absolute URL to your redirect URI.
                              # The absolute URL must match the redirect URI you set
                              # in the app's registration in the Azure portal.

# You can find more Microsoft Graph API endpoints from Graph Explorer
# https://developer.microsoft.com/en-us/graph/graph-explorer
ENDPOINT = 'https://graph.microsoft.com/v1.0'  # This resource requires no admin consent
ENDPOINT_ME = 'https://graph.microsoft.com/v1.0/me'

# You can find the proper permission names from this document
# https://docs.microsoft.com/en-us/graph/permissions-reference
SCOPE = ["User.ReadBasic.All"]

SESSION_TYPE = "filesystem"  # Specifies the token cache should be stored in server-side session
