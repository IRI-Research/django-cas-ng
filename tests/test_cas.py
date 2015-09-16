"""Tests for the cas protocol-related code"""
from __future__ import absolute_import
from django_cas_ng import cas
import pytest
from pytest import fixture
import sys

#general tests, apply to all protocols
#
# get_login_url tests
#
def test_login_url_helper():
    client = cas.CASClientBase(
                        renew=False,
                        extra_login_params=False,
                        server_url='http://www.example.com/cas/',
                        service_url='http://testserver/'
                    )
    actual = client.get_login_url()
    expected = 'http://www.example.com/cas/login?service=http%3A%2F%2Ftestserver%2F'

    assert actual == expected


def test_login_url_helper_with_extra_params():
    client = cas.CASClientBase(
                        renew=False,
                        extra_login_params={'test': '1234'},
                        server_url='http://www.example.com/cas/',
                        service_url='http://testserver/'
                    )
    actual = client.get_login_url()
    # since the dictionary of parameters is unordered, we dont know which
    # parameter will be first, so just check that both are in the url.

    assert 'service=http%3A%2F%2Ftestserver%2F' in actual
    assert 'test=1234' in actual


def test_login_url_helper_with_renew():
    client = cas.CASClientBase(
                        renew=True,
                        extra_login_params=None,
                        server_url='http://www.example.com/cas/',
                        service_url='http://testserver/'
                    )
    actual = client.get_login_url()
    # since the dictionary of parameters is unordered, we dont know which
    # parameter will be first, so just check that both are in the url.

    assert 'service=http%3A%2F%2Ftestserver%2F' in actual
    assert 'renew=true' in actual

#
# get_logout_url tests
#
@fixture
def logout_client():
    return cas.CASClientBase(
        server_url='http://www.example.com/cas/'
    )

def test_logout_url(logout_client):
    actual = logout_client.get_logout_url()
    expected = 'http://www.example.com/cas/logout'

    assert actual == expected


def test_logout_url_with_redirect(logout_client):
    actual = logout_client.get_logout_url(
                redirect_url='http://testserver/landing-page/'
            )
    expected = 'http://www.example.com/cas/logout?service=http%3A%2F%2Ftestserver%2Flanding-page%2F'

    assert actual == expected


#cas3 responses
@fixture
def client_v3():
    return cas.CASClientV3()

SUCCESS_RESPONSE = """<?xml version=\'1.0\' encoding=\'UTF-8\'?>
<cas:serviceResponse xmlns:cas="http://www.yale.edu/tp/cas"><cas:authenticationSuccess><cas:user>user@example.com</cas:user></cas:authenticationSuccess></cas:serviceResponse>
"""
def test_cas3_basic_successful_response_verification(client_v3):
    user, attributes, pgtiou = client_v3.verify_response(SUCCESS_RESPONSE)

    assert user == 'user@example.com'
    assert not attributes
    assert not pgtiou


SUCCESS_RESPONSE_WITH_ATTRIBUTES = """<?xml version='1.0' encoding='UTF-8'?>
<cas:serviceResponse xmlns:cas="http://www.yale.edu/tp/cas"><cas:authenticationSuccess><cas:user>user@example.com</cas:user><cas:attributes><cas:foo>bar</cas:foo><cas:baz>1234</cas:baz></cas:attributes></cas:authenticationSuccess></cas:serviceResponse>
"""
def test_cas3_successful_response_verification_with_attributes(client_v3):
    user, attributes, pgtiou = client_v3.verify_response(SUCCESS_RESPONSE_WITH_ATTRIBUTES)

    assert user == 'user@example.com'
    assert not pgtiou
    assert attributes['foo'] == 'bar'
    assert attributes['baz'] == '1234'


SUCCESS_RESPONSE_WITH_PGTIOU = """<?xml version=\'1.0\' encoding=\'UTF-8\'?>
<cas:serviceResponse xmlns:cas="http://www.yale.edu/tp/cas"><cas:authenticationSuccess><cas:user>user@example.com</cas:user><cas:proxyGrantingTicket>PGTIOU-84678-8a9d</cas:proxyGrantingTicket></cas:authenticationSuccess></cas:serviceResponse>
"""
def test_successful_response_verification_with_pgtiou(client_v3):
    user, attributes, pgtiou = client_v3.verify_response(SUCCESS_RESPONSE_WITH_PGTIOU)

    assert user == 'user@example.com'
    assert pgtiou == 'PGTIOU-84678-8a9d'


FAILURE_RESPONSE = """<?xml version='1.0' encoding='UTF-8'?>
<cas:serviceResponse xmlns:cas="http://www.yale.edu/tp/cas"><cas:authenticationFailure code="INVALID_TICKET">service ticket ST-1415306486-qs5TfUWlwge23u013h8fivR21RklkeWI has already been used</cas:authenticationFailure></cas:serviceResponse>
"""
def test_unsuccessful_response(client_v3):
    user, attributes, pgtiou = client_v3.verify_response(FAILURE_RESPONSE)
    assert user is None
    assert not pgtiou
    assert not attributes


#test CAS+SAML protocol
def test_can_saml_assertion_is_encoded():
    ticket = 'test-ticket'

    client = cas.CASClientWithSAMLV1()
    saml = client.get_saml_assertion(ticket)

    if sys.version_info > (3, 0):
        assert type(saml) is bytes
        assert ticket.encode('utf-8') in saml
    else:
        assert ticket in saml

class CasClientCustom(cas.CASClientBase):
    def verify_ticket(self, ticket):
        return 'test_custom@example.com', {'ticket': ticket,}, None



#test CASClient custom class
def test_casclient_custom_class():
    version = CasClientCustom

    cas_client = cas.CASClient(
        service_url="https://testserver/login/?next=%2F",
        version=version,
        server_url="https://cas.domain.com",
        extra_login_params={},
        renew=False,
        username_attribute="user",
        proxy_callback=False
    )

    assert isinstance(cas_client, CasClientCustom)

#test CASClient custom class with classname
def test_casclient_custom_class_classname():
    version = 'tests.test_cas.CasClientCustom'

    cas_client = cas.CASClient(
        service_url="https://testserver/login/?next=%2F",
        version=version,
        server_url="https://cas.domain.com",
        extra_login_params={},
        renew=False,
        username_attribute="user",
        proxy_callback=False
    )

    assert isinstance(cas_client, CasClientCustom)


#test CASClient custom class fail
def test_casclient_custom_class_fail():
    version = 'foo.bar'

    with pytest.raises(Exception) as excinfo:
        cas_client = cas.CASClient(
            service_url="https://testserver/login/?next=%2F",
            version=version,
            server_url="https://cas.domain.com",
            extra_login_params={},
            renew=False,
            username_attribute="user",
            proxy_callback=False
        )
    assert str(excinfo.value) == "Unsupported CAS_VERSION 'foo.bar'"
