import flask
from flask import current_app
from .cas_urls import create_cas_login_url
from .cas_urls import create_cas_logout_url
from .cas_urls import create_cas_validate_url

import json

try:
    from urllib import urlopen
except ImportError:
    from urllib.request import urlopen

blueprint = flask.Blueprint('cas', __name__)


@blueprint.route('/login/')
def login():
    """
    This route has two purposes. First, it is used by the user
    to login. Second, it is used by the CAS to respond with the
    `ticket` after the user logs in successfully.

    When the user accesses this url, they are redirected to the CAS
    to login. If the login was successful, the CAS will respond to this
    route with the ticket in the url. The ticket is then validated.
    If validation was successful the logged in username is saved in
    the user's session under the key `CAS_USERNAME_SESSION_KEY`.
    """

    cas_token_session_key = current_app.config['CAS_TOKEN_SESSION_KEY']

    redirect_url = create_cas_login_url(
        current_app.config['CAS_SERVER2'] if current_app.config['CAS_NEW_LOGIN'] else current_app.config['CAS_SERVER'],
        current_app.config['CAS_ROUTE_PREFIX'],
        flask.url_for('.login', _external=True))

    if 'ticket' in flask.request.args:
        flask.session[cas_token_session_key] = flask.request.args['ticket']

    isjson = False
    if 'fmt' in flask.request.args:
        isjson = flask.request.args['fmt'] == 'json'

    service = None
    if 'service' in flask.request.args:
        service = flask.request.args['service']

    store_func = current_app.config['CAS_SAVE_INFO_CALLBACK']

    if cas_token_session_key in flask.session:

        r = {'status': 'ok'}
        if validate(flask.session[cas_token_session_key], service):
            redirect_url = flask.url_for(
                current_app.config['CAS_AFTER_LOGIN'])
            #cas_username_session_key = current_app.config['CAS_USERNAME_SESSION_KEY']
            #cas_attributes_session_key = current_app.config['CAS_ATTRIBUTES_SESSION_KEY']
            if store_func:
                store_func(flask.request, flask.session)
        else:
            r['status'] = 'error'
            del flask.session[cas_token_session_key]

        if isjson:
            if store_func:
                store_func(flask.request, flask.session)
            return json.dumps(r)

    current_app.logger.debug('Redirecting to: {}, {}'.format(redirect_url, flask.session))

    if current_app.config['CAS_NEW_LOGIN']:
        return flask.render_template(
            'cas_result.html',
            redirect_url=redirect_url,
        )
    else:
        return flask.redirect(redirect_url)


@blueprint.route('/logout/')
def logout():
    """
    When the user accesses this route they are logged out.
    """

    cas_username_session_key = current_app.config['CAS_USERNAME_SESSION_KEY']
    cas_userid_session_key = current_app.config['CAS_USERID_SESSION_KEY']

    if cas_username_session_key in flask.session:
        del flask.session[cas_username_session_key]
    if cas_userid_session_key in flask.session:
        del flask.session[cas_userid_session_key]

    redirect_url = create_cas_logout_url(
        current_app.config['CAS_SERVER'],
        current_app.config['CAS_ROUTE_PREFIX'],
        current_app.config['CAS_LOGOUT_RETURN_URL'],
        current_app.config['CAS_VERSION'],
    )

    current_app.logger.debug('Redirecting to: {}, {}'.format(redirect_url, flask.session))
    return flask.redirect(redirect_url)


def validate(ticket, service=None):
    """
    Will attempt to validate the ticket. If validation fails, then False
    is returned. If validation is successful, then True is returned
    and the validated username is saved in the session under the
    key `CAS_USERNAME_SESSION_KEY`.
    """

    cas_username_session_key = current_app.config['CAS_USERNAME_SESSION_KEY']

    current_app.logger.debug("validating token {0}".format(ticket))

    _PROTOCOLS = {'1': _validate_cas1, '2': _validate_cas2, '3': _validate_cas3}
    if current_app.config['CAS_VERSION'] not in _PROTOCOLS:
        raise ValueError('Unsupported CAS_VERSION %r' % current_app.config['CAS_VERSION'])

    cas_validate_url = create_cas_validate_url(
        current_app.config['CAS_SERVER'],
        current_app.config['CAS_ROUTE_PREFIX'],
        flask.url_for('.login', _external=True) if service == None else service,
        ticket,
        version=current_app.config['CAS_VERSION'])

    current_app.logger.debug("Making GET request to {0}".format(
        cas_validate_url))

    response = urlopen(cas_validate_url)

    _validate = _PROTOCOLS[current_app.config['CAS_VERSION']]
    is_valid = _validate(response)

    if is_valid:
        current_app.logger.debug("valid")
    else:
        current_app.logger.debug("invalid")

    return is_valid


def _validate_cas1(response):
    try:
        (is_valid, username) = response.readlines()
        is_valid = True if is_valid.strip() == b'yes' else False
        if is_valid:
            cas_username_session_key = current_app.config['CAS_USERNAME_SESSION_KEY']
            cas_userid_session_key = current_app.config['CAS_USERID_SESSION_KEY']
            username = username.strip().decode('utf8', 'ignore')
            flask.session[cas_userid_session_key] = flask.session[cas_username_session_key] = username
    except ValueError:
        current_app.logger.error("CAS returned unexpected result")
        is_valid = False

    response.close()

    return is_valid


def _validate_cas2(response):
    from xml.etree import ElementTree

    try:
        data = response.read()
        tree = ElementTree.fromstring(data)
        user = tree.find('*/cas:user', namespaces=dict(cas='http://www.yale.edu/tp/cas'))
        is_valid = user != None
        if is_valid:
            cas_username_session_key = current_app.config['CAS_USERNAME_SESSION_KEY']
            cas_userid_session_key = current_app.config['CAS_USERID_SESSION_KEY']
            username = user.text
            flask.session[cas_userid_session_key] = flask.session[cas_username_session_key] = username
            return True
        else:
            error = tree.find('cas:authenticationFailure', namespaces=dict(cas='http://www.yale.edu/tp/cas'))
            if error is None:
                current_app.logger.error('Error: Unknown response, ' + data)
            else:
                current_app.logger.error('Error: ' + error.get('code') + ', ' + error.text)
            return False
    finally:
        response.close()


def _validate_cas3(response):
    from xml.etree import ElementTree

    try:
        data = response.read()
        current_app.logger.info('Response data, ' + data)
        tree = ElementTree.fromstring(data)
        user = tree.find('*/cas:user', namespaces=dict(cas='http://www.yale.edu/tp/cas'))
        is_valid = user != None
        if is_valid:
            cas_username_session_key = current_app.config['CAS_USERNAME_SESSION_KEY']
            cas_userid_session_key = current_app.config['CAS_USERID_SESSION_KEY']
            cas_attributes_session_key = current_app.config['CAS_ATTRIBUTES_SESSION_KEY']
            attributes = {}
            username = user.text
            current_app.logger.info('Response username, ' + username)
            attrs = tree.find('*/cas:attributes', namespaces=dict(cas='http://www.yale.edu/tp/cas'))
            if attrs != None:
                for attr in attrs:
                    tag = attr.tag.split("}").pop()
                    if tag in attributes:
                        # found multiple value attribute
                        if isinstance(attributes[tag], list):
                            attributes[tag].append(attr.text)
                        else:
                            attributes[tag] = [attributes[tag], attr.text]
                    else:
                        attributes[tag] = attr.text
            flask.session[cas_userid_session_key] = flask.session[cas_username_session_key] = username
            flask.session[cas_attributes_session_key] = attributes
            return True
        else:
            error = tree.find('cas:authenticationFailure', namespaces=dict(cas='http://www.yale.edu/tp/cas'))
            if error is None:
                current_app.logger.error('Error: Unknown response, ' + data)
            else:
                current_app.logger.error('Error: ' + error.get('code') + ', ' + error.text)
            return False
    finally:
        current_app.logger.info("flask.session, {}".format(flask.session))
        response.close()
