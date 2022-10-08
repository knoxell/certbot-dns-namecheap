"""DNS Authenticator for Namecheap DNS."""
import logging

import zope.interface
from lexicon.providers import namecheap

from certbot import errors
from certbot import interfaces
from certbot.plugins import dns_common
from certbot.plugins import dns_common_lexicon

from acme import challenges

logger = logging.getLogger(__name__)

TOKEN_URL = 'https://api.namecheap.com/xml.response or https://api.sandbox.namecheap.com/xml.response'

@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for Namecheap

    This Authenticator uses the Namecheap API to fulfill a dns-01 challenge.
    """

    description = 'Obtain certificates using a DNS TXT record (if you are using Namecheap for DNS).'
    ttl = 60

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self.credentials = None

    @classmethod
    def add_parser_arguments(cls, add):  # pylint: disable=arguments-differ
        super(Authenticator, cls).add_parser_arguments(add, default_propagation_seconds=60)
        add('credentials', help='Namecheap credentials INI file.')

    def more_info(self):  # pylint: disable=missing-docstring,no-self-use
        return 'This plugin configures a DNS TXT record to respond to a dns-01 challenge using ' + \
               'the Namecheap API.'

    def get_chall_pref(self, domain):
        """Return `collections.Iterable` of challenge preferences.
        :param str domain: Domain for which challenge preferences are sought.
        :returns: `collections.Iterable` of challenge types (subclasses of
            :class:`acme.challenges.Challenge`) with the most
            preferred challenges first. If a type is not specified, it means the
            Authenticator cannot perform the challenge.
        :rtype: `collections.Iterable`
        """
        return [challenges.DNS01]

    def _setup_credentials(self):
        self.credentials = self._configure_credentials(
            'credentials',
            'Namecheap credentials INI file',
            {
                'username': 'Namecheap username',
                'api_key': 'Namecheap api key'
            }
        )

    def _perform(self, domain, validation_name, validation):
        self._get_namecheap_client().add_txt_record(domain, validation_name, validation)

    def _cleanup(self, domain, validation_name, validation):
        self._get_namecheap_client().del_txt_record(domain, validation_name, validation)

    def _get_namecheap_client(self):
        return _NamecheapLexiconClient(
            self.credentials.conf('username'),
            self.credentials.conf('api_key'),
            self.ttl
        )


class _NamecheapLexiconClient(dns_common_lexicon.LexiconClient):
    """
    Encapsulates all communication with the Namecheap API via Lexicon.
    """

    def __init__(self, username, api_key, ttl):
        super(_NamecheapLexiconClient, self).__init__()

        lexicon_options = {
            'ttl': ttl,
        }
        namecheap_options = {
            'auth_username': username,
            'auth_token': api_key,
            'auth_client_ip': '0.0.0.0'
        }
        config = dns_common_lexicon.build_lexicon_config(
            'namecheap',
            lexicon_options,
            namecheap_options
        )

        self.provider = namecheap.Provider(config)

    def _handle_http_error(self, e, domain_name):
        hint = None
        if str(e).startswith('400 Client Error:'):
            hint = 'Is your Application Secret value correct?'
        if str(e).startswith('403 Client Error:'):
            hint = 'Are your Application Key and Consumer Key values correct?'
        return errors.PluginError('Error determining zone identifier for {0}: {1}.{2}'
                                  .format(domain_name, e, ' ({0})'.format(hint) if hint else ''))

    def _handle_general_error(self, e, domain_name):
        if domain_name in str(e) and str(e).endswith('not found'):
            return

        super(_NamecheapLexiconClient, self)._handle_general_error(e, domain_name)
