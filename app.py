import uuid
from pprint import pprint

import requests
from flask import Flask, render_template, session, request, redirect, url_for, jsonify
from flask_session import Session  # https://pythonhosted.org/Flask-Session
from flask_cors import CORS, cross_origin
import msal
import app_config

app = Flask(__name__)
app.config.from_object(app_config)
Session(app)
CORS(app)

# This section is needed for url_for("foo", _external=True) to automatically
# generate http scheme when this sample is running on localhost,
# and to generate https scheme when it is deployed behind reversed proxy.
# See also https://flask.palletsprojects.com/en/1.0.x/deploying/wsgi-standalone/#proxy-setups
from werkzeug.middleware.proxy_fix import ProxyFix

app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)


@app.route("/")
def index():
    if not session.get("user"):
        return redirect(url_for("login"))
    return render_template('index.html', user=session["user"], version=msal.__version__)


@cross_origin
@app.route("/login")
def login():
    # Technically we could use empty list [] as scopes to do just sign in,
    # here we choose to also collect end user consent upfront
    # session["flow"] = _build_auth_code_flow(scopes=app_config.SCOPE)
    # try:
    #     cache = _load_cache()
    #     result = _build_msal_app(cache=cache).acquire_token_by_auth_code_flow(
    #         session.get("flow", {}), request.args)
    #     if "error" in result:
    #         return render_template("auth_error.html", result=result)
    #     session["user"] = result.get("id_token_claims")
    #     _save_cache(cache)
    # except ValueError as e:  # Usually caused by CSRF
    #     print(e)  # Simply ignore them
    # print(session)
    # # return jsonify({
    #     # 'token': session['user'],
    #     # 'session': session
    # # })
    #
    # return jsonify({
    #     'flow': session['flow']
    # })
    # return render_template("login.html", auth_url=session["flow"]["auth_uri"], version=msal.__version__)
    from msal import PublicClientApplication
    import sys

    # You can hard-code the registered app's client ID and tenant ID here,
    # or you can provide them as command-line arguments to this script.
    client_id = app_config.CLIENT_ID
    tenant_id = app_config.TENANT_ID

    # Do not modify this variable. It represents the programmatic ID for
    # Azure Databricks along with the default scope of '/.default'.
    # scopes = ['2ff814a6-3304-4ab8-85cb-cd0e6f879c1d/.default']
    scopes = app_config.SCOPE

    # Check for too few or too many command-line arguments.
    if (len(sys.argv) > 1) and (len(sys.argv) != 3):
        print("Usage: get-tokens.py <client ID> <tenant ID>")
        exit(1)

    # If the registered app's client ID and tenant ID are provided as
    # command-line variables, set them here.
    if len(sys.argv) > 1:
        client_id = sys.argv[1]
        tenant_id = sys.argv[2]

    app = PublicClientApplication(
        client_id=client_id,
        authority="https://login.microsoftonline.com/" + tenant_id
    )

    acquire_tokens_result = app.acquire_token_by_username_password(
        username=app_config.USERNAME,
        password=app_config.PASSWORD,
        scopes=scopes
    )

    print(acquire_tokens_result)

    if 'error' in acquire_tokens_result:
        print("Error: " + acquire_tokens_result['error'])
        print("Description: " + acquire_tokens_result['error_description'])
    else:
        print("Access token:\n")
        print(acquire_tokens_result['access_token'])
        print("\nRefresh token:\n")
        print(acquire_tokens_result['refresh_token'])

    return jsonify({
        'token': acquire_tokens_result
    })


@app.route(app_config.REDIRECT_PATH)  # Its absolute URL must match your app's redirect_uri set in AAD
def authorized():
    try:
        cache = _load_cache()
        result = _build_msal_app(cache=cache).acquire_token_by_auth_code_flow(
            session.get("flow", {}), request.args)
        if "error" in result:
            return render_template("auth_error.html", result=result)
        session["user"] = result.get("id_token_claims")
        _save_cache(cache)
    except ValueError:  # Usually caused by CSRF
        pass  # Simply ignore them
    return jsonify({
        'token': session['user'],
        'session': session
    })
    return redirect('http://localhost:3000/')
    return redirect(url_for("index"))


@app.route("/logout")
def logout():
    # session.clear()  # Wipe out user and its token cache from session
    return redirect(  # Also logout from your tenant's web session
        app_config.AUTHORITY + "/oauth2/v2.0/logout" +
        "?post_logout_redirect_uri=" + url_for("index", _external=True))


@app.route("/graphcall")
def graphcall():
    token = _get_token_from_cache(app_config.SCOPE)
    if not token:
        return redirect(url_for("login"))
    graph_data = requests.get(  # Use token to call downstream service
        app_config.ENDPOINT_ME,
        headers={'Authorization': 'Bearer ' + token['access_token']},
    ).json()

    # pprint(graph_data)

    try:
        user_id = graph_data['id']
    except Exception as e:
        return jsonify(
            {'msg': e}
        )

    app_roles = requests.get(
        app_config.ENDPOINT + '/users/{id}/appRoleAssignments'.format(
            id=user_id),
        headers={'Authorization': 'Bearer ' + token['access_token']},
    ).json()

    app_role_names = requests.get(
        app_config.ENDPOINT + '/applications/{obj_id}'.format(
            obj_id=app_config.OBJECT_ID),
        headers={'Authorization': 'Bearer ' + token['access_token']},
    ).json()

    pprint(app_roles)
    pprint([role_names['displayName'] for role_names in app_role_names['appRoles']])

    return render_template('display.html', result=graph_data)


def _load_cache():
    cache = msal.SerializableTokenCache()
    if session.get("token_cache"):
        cache.deserialize(session["token_cache"])
    return cache


def _save_cache(cache):
    if cache.has_state_changed:
        session["token_cache"] = cache.serialize()


def _build_msal_app(cache=None, authority=None):
    return msal.ConfidentialClientApplication(
        app_config.CLIENT_ID, authority=authority or app_config.AUTHORITY,
        client_credential=app_config.CLIENT_SECRET, token_cache=cache)


def _build_auth_code_flow(authority=None, scopes=None):
    return _build_msal_app(authority=authority).initiate_auth_code_flow(
        scopes or [],
        redirect_uri=url_for("authorized", _external=True))


def _get_token_from_cache(scope=None):
    cache = _load_cache()  # This web app maintains one cache per session
    cca = _build_msal_app(cache=cache)
    accounts = cca.get_accounts()
    if accounts:  # So all account(s) belong to the current signed-in user
        result = cca.acquire_token_silent(scope, account=accounts[0])
        _save_cache(cache)
        return result


app.jinja_env.globals.update(_build_auth_code_flow=_build_auth_code_flow)  # Used in template

if __name__ == "__main__":
    app.run()
