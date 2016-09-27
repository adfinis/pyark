#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CyberArk Password Vault API CLI tool."""

import argparse
import json
import logging
import sys

import requests

logger = logging.getLogger('pyark')


class VaultConnector:
    """Handles the authentication against the API and calls the appropriate API
    endpoints.
    """

    def __init__(self, base_url):
        logger.debug('Initialize VaultConnector')
        self.base_url = base_url
        self.user = None
        self.password = None
        self.session_token = None

    def __del__(self):
        logger.debug('Destroy VaultConnector')
        self.logout()

    def call(self, http_method, api_endpoint, params={}):
        """Sends the data to the API endpoint using the appropriate HTTP
        method.

        :param  http_method: HTTP method to use, e.g. POST
        :type   http_method: str
        :param api_endpoint: Target API endpoint
        :type  api_endpoint: str
        :param       params: Payload to send with the request
        :type        params: dict"""
        headers = {}
        ret = None

        if self.session_token is not None:
            headers = {"Authorization": self.session_token}

        logger.debug('Call params: %s, %s' % (api_endpoint, params))
        try:
            url = "%s/PasswordVault/WebServices/%s" % (self.base_url,
                                                       api_endpoint)
            logger.debug('Request %s URL: %s' % (http_method, url))
            if http_method == "GET":
                ret = requests.get(
                    url     = url,
                    params  = params,
                    timeout = 10,
                    verify  = False,
                    headers = headers
                )
            elif http_method == "POST":
                ret = requests.post(
                    url     = url,
                    json    = params,
                    timeout = 10,
                    verify  = False,
                    headers = headers
                )
            elif http_method == "DELETE":
                ret = requests.delete(
                    url     = url,
                    json    = params,
                    timeout = 10,
                    verify  = False,
                    headers = headers
                )
            else:
                logger.error('HTTP method is missing')
                raise

            if ret.status_code is not None:
                logger.debug('Returned HTTP status: %s' % (ret.status_code))
            if ret.text is not None:
                logger.debug('Returned HTTP body: %s' % (ret.text))
            if ret.headers is not None:
                logger.debug('Returned HTTP headers: %s' % (ret.headers))
        except Exception as e:
            logger.warning('Error communicating: %s' % (e))
            raise

        return ret

    def login(self, user, password):
        """Login into CyberArk and get the session token.

        :param     user: Username used for the authentication
        :type      user: str
        :param password: Password used for the authentication
        :type  password: str"""
        logger.debug('Login called, will try to login as %s' % (user))
        params = {
            "username": user,
            "password": password
        }

        ret = self.call(
            "POST",
            "auth/Cyberark/CyberArkAuthenticationService.svc/Logon",
            params
        )

        if ret is None:
            logger.info('Login failed, API call returned %s' % (ret))
            return False

        if ret.status_code == requests.codes.ok:
            logger.info('Login successful')
            payload = json.loads(ret.text)
            logger.debug('Setting session token to %s' % (
                payload['CyberArkLogonResult']))
            self.session_token = payload['CyberArkLogonResult']
            self.user = user
            self.password = password
            return True
        else:
            logger.info('Login failed, please validate your credentials '
                        '(HTTP %s)' % (ret.status_code))
            return False

    def logout(self):
        """Logout and destroy the session."""
        logger.debug('Logout called, will try to logout as %s' % (self.user))
        if self.session_token is None:
            logger.info('Logout skipped, no session token available')
        else:
            params = {
                "username": self.user,
                "password": self.password
            }

            ret = self.call(
                "POST",
                "auth/Cyberark/CyberArkAuthenticationService.svc/Logoff",
                params
            )

            if ret is None:
                logger.info('Login failed, API call returned %s' % (ret))

            if ret.status_code == requests.codes.ok:
                logger.info('Logout successful')
            else:
                logger.info('Logout failed (HTTP %s)' % (ret.status_code))
                logger.debug('API call returned %s' % (ret))


def get_account(vault, params):
    """Get accounts based on keywords.

    :param:  vault: Authenticated Vault session
    :type:   vault: VaultConnector
    :param  params: Payload to send with the request
    :type:  params: dict"""
    ret = vault.call("GET", "PIMServices.svc/Accounts", params)

    if ret is None:
        logger.error('Get account failed, API call returned %s' % (ret))

    if ret.status_code == requests.codes.ok:
        logger.info('Get account successful: %s' % (ret.text))
        return ret.text
    else:
        logger.info('Get account failed (HTTP %s)' % (ret.status_code))
        logger.error('API call returned %s' % (ret))

    return False


def create_account(vault, params):
    """Create a new account.

    :param:  vault: Authenticated Vault session
    :type:   vault: VaultConnector
    :param  params: Payload to send with the request
    :type:  params: dict"""
    ret = vault.call("POST", "PIMServices.svc/Account", params)

    if ret is None:
        logger.error('Create account failed, API call returned %s' % (ret))

    if ret.status_code == requests.codes.created:
        logger.info('Create account successful')
        return True
    else:
        logger.info('Create account failed (HTTP %s)' % (ret.status_code))
        logger.error('API call returned %s' % (ret))

    return False


def delete_account(vault, params):
    """Delete an existing account.

    :param:  vault: Authenticated Vault session
    :type:   vault: VaultConnector
    :param  params: Payload to send with the request
    :type:  params: dict"""
    ret = vault.call("DELETE", "PIMServices.svc/Accounts/" + params)

    if ret is None:
        logger.error('Delete account failed, API call returned %s' % (ret))

    if ret.status_code == requests.codes.ok:
        logger.info('Delete account successful: %s' % (ret.text))
        return True
    else:
        logger.info('Delete account failed (HTTP %s)' % (ret.status_code))
        logger.error('API call returned %s' % (ret))

    return False


def account(vault, args):
    """Manage Password Vault Accounts.

    :param: vault: Authenticated Vault session
    :type:  vault: VaultConnector
    :param   args: The command-line arguments read with :py:mod:`argparse`
    :type    args: namespace"""
    logger.debug('Passed arguments: %s' % (args))

    if args.task == "create":
        params = {
            "account": {
                "safe":        args.safe,
                "platformID":  args.platformid,
                "accountName": args.accountname,
                "address":     args.address,
                "password":    args.password,
                "username":    args.username
            }
        }
        if create_account(vault, params):
            logger.info('Successfully created account: %s' % (params))
            return True
        else:
            logger.error('Unable to create account: %s' % (params))
            return False
    elif args.task == "get":
        params = {
            "Keywords": args.keywords,
            "Safe":     args.safe
        }
        if get_account(vault, params):
            logger.info('Successfully get account: %s' % (params))
            return True
        else:
            logger.error('Unable to get account: %s' % (params))
            return False
    elif args.task == "delete":
        params = {
            "Keywords": args.keywords,
            "Safe":     args.safe
        }
        accounts = get_account(vault, params)
        if accounts:
            data = json.loads(accounts)
            logger.info('Number of accounts found: %s' % (data["Count"]))
            if data["Count"] == 1:
                params = data["accounts"][0]["AccountID"]
                if delete_account(vault, params):
                    logger.info('Successfully deleted account: %s' % (params))
                    return True
                else:
                    logger.info('Unable to delete account: %s' % (params))
                    return False
            else:
                logger.info('Too many accounts found: %s. Please specify a '
                            'more restrictive search string' % (data["Count"]))
                return False
        else:
            logger.info("No accounts found: %s" % (accounts))
            return False


def main(argv=None):
    """Called by command-line, defines parsers and executes commands.

    :param argv: Arguments usually taken from sys.argv
    :type  argv: list"""
    if not argv:
        argv = sys.argv[1:]

    # global parser
    parser = argparse.ArgumentParser(description='Manage CyberArk Password '
                                                 'Vault')
    parser.add_argument(
        '--debug',
        '-d',
        help='Enable debug mode',
        action='store_true'
    )
    parser.add_argument(
        '--base',
        '-b',
        help='Password Vault base URL',
        type=str,
        required=True
    )
    parser.add_argument(
        '--apiuser',
        '-au',
        help='CyberArk account used to login',
        type=str,
        required=True
    )
    parser.add_argument(
        '--apipassword',
        '-ap',
        help='CyberArk password used to login',
        type=str,
        required=True
    )
    subparsers = parser.add_subparsers()

    # account parser
    account_parser = subparsers.add_parser(
        'account',
        help='Manage accounts'
    )
    account_parser.set_defaults(func=account)
    account_subparser = account_parser.add_subparsers()

    # account get parser
    account_get_subparser = account_subparser.add_parser(
        'get',
        help='Get accounts'
    )
    account_get_subparser.set_defaults(task='get')
    account_get_subparser.add_argument(
        '--keywords',
        '-kw',
        help='Keywords to search for',
        type=str,
        required=False
    )
    account_get_subparser.add_argument(
        '--safe',
        '-s',
        help='Safe to search for',
        type=str,
        required=True
    )

    # account create parser
    account_create_subparser = account_subparser.add_parser(
        'create',
        help='Create accounts'
    )
    account_create_subparser.set_defaults(task='create')
    account_create_subparser.add_argument(
        '--safe',
        '-s',
        help='Safe to store account to',
        type=str,
        required=True
    )
    account_create_subparser.add_argument(
        '--platformid',
        '-pid',
        help='PlatformID to assign',
        type=str,
        required=True
    )
    account_create_subparser.add_argument(
        '--accountname',
        '-n',
        help='Account name to save',
        type=str,
        required=True
    )
    account_create_subparser.add_argument(
        '--address',
        '-a',
        help='Address to save',
        type=str,
        required=True
    )
    account_create_subparser.add_argument(
        '--username',
        '-un',
        help='Username to save',
        type=str,
        required=True
    )
    account_create_subparser.add_argument(
        '--password',
        '-pw',
        help='Password to save',
        type=str,
        required=True
    )

    # account delete parser
    account_delete_subparser = account_subparser.add_parser(
        'delete',
        help='Delete accounts'
    )
    account_delete_subparser.set_defaults(task='delete')
    account_delete_subparser.add_argument(
        '--accountname',
        '-n',
        help='Account name to delete',
        type=str,
        required=True
    )
    account_delete_subparser.add_argument(
        '--keywords',
        '-kw',
        help='Keywords to search for',
        type=str,
        required=True
    )
    account_delete_subparser.add_argument(
        '--safe',
        '-s',
        help='Safe to search for',
        type=str,
        required=True
    )

    args = parser.parse_args(argv)

    log_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    ch = logging.StreamHandler()

    if args.debug:
        ch.setLevel(logging.DEBUG)
        logger.setLevel(logging.DEBUG)
    else:
        ch.setLevel(logging.INFO)
        logger.setLevel(logging.INFO)

    ch.setFormatter(log_formatter)
    logger.addHandler(ch)

    vault = VaultConnector(args.base)
    if (vault.login(args.apiuser, args.apipassword)):
        # run function for selected subparser
        if not args.func(vault, args):
            logger.error('Unable to complete CyberArk request')
            exit(1)
    else:
        logger.error('Unable to login to CyberArk')
        exit(1)


if __name__ == "__main__":
    main()
