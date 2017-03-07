import inquisitor.assets.block
import inquisitor.assets.email
import inquisitor.assets.registrant
import ipwhois
import socket
import tld
import whois

class HostValidateException(Exception):
    pass

def canonicalize(host):
    if not host:
        raise HostValidateException('Hosts cannot be None')
    if not isinstance(host, str) and not isinstance(host, unicode):
        raise HostValidateException('Hosts must be strings')
    host = host.strip().lower()
    try:
        tld.get_tld('http://{}'.format(host))
    except tld.exceptions.TldDomainNotFound:
        raise HostValidateException('Invalid tld for host {}'.format(tld))
    return host

def main_classify_args(parser):
    parser.add_argument(
        '-ah', '--accept-host',
        metavar='HOST',
        type=canonicalize,
        nargs='+',
        help='Specifies a host to classify as accepted.',
        dest='hosts_accepted',
        default=list(),
    )
    parser.add_argument(
        '-uh', '--unmark-host',
        metavar='HOST',
        type=canonicalize,
        nargs='+',
        help='Specifies a host to classify as unmarked.',
        dest='hosts_unmarked',
        default=list(),
    )
    parser.add_argument(
        '-rh', '--reject-host',
        metavar='HOST',
        type=canonicalize,
        nargs='+',
        help='Specifies a host to classify as rejected.',
        dest='hosts_rejected',
        default=list(),
    )

def main_classify_canonicalize(args):
    accepted = set(args.hosts_accepted)
    unmarked = set(args.hosts_unmarked)
    rejected = set(args.hosts_rejected)
    redundant = set.intersection(accepted, unmarked, rejected)
    if redundant:
        raise ValueError(
            ('The following hosts were classified '
            'more than once: {}').format(list(redundant))
        )
    accepted = set([canonicalize(a) for a in accepted])
    unmarked = set([canonicalize(a) for a in unmarked])
    rejected = set([canonicalize(a) for a in rejected])
    return (accepted, unmarked, rejected)

class Host(object):
    
    def __init__(self, host, owned=None):
        self.host = canonicalize(host)
        self.owned = owned
        # Acquire parent domain
        self.parent = None
        zones = self.host.split('.')
        if len(zones) > 1:
            self.parent = canonicalize('.'.join(zones[1:]))
        # Acquire whois information
        info = whois.whois(self.host)
        self.registrant = (
            inquisitor.assets.registrant.canonicalize(info['org'])
            if info['org'] is not None else None
        )
        self.emails = set()
        if info['emails']:
            for email in info['emails']:
                self.emails.add(inquisitor.assets.email.canonicalize(email))
        self.emails = list(self.emails)
        self.nameservers = set()
        if info['name_servers'] is not None:
            for nameserver in info['name_servers']:
                self.nameservers.add(canonicalize(nameserver))
        self.nameservers = list(self.nameservers)
        # Acquire ip information
        self.ip = None
        try: self.ip = socket.gethostbyname(self.host)
        except: pass
        self.block = None
        if self.ip is not None:
            info = ipwhois.ipwhois.IPWhois(self.ip).lookup_rdap()
            self.block = inquisitor.assets.block.canonicalize(info['network']['cidr'])

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return False
        return self.host == other.host

    def related(self, repo):
        # Prepare results
        results = set()
        # Related: Block
        if self.block is not None:
            asset = repo.get_asset_string(inquisitor.assets.block.Block, self.block)
            results.add(asset[1] if asset else inquisitor.assets.block.Block(self.block))
        # Related: Parent
        if self.parent is not None and len(self.parent.split('.')) > 1:
            asset = repo.get_asset_string(Host, self.parent)
            results.add(asset[1] if asset else Host(self.parent))
        # Related: Registrant
        if self.registrant is not None:
            asset = repo.get_asset_string(
                inquisitor.assets.registrant.Registrant,
                self.registrant
            )
            results.add(
                asset[1] if asset else
                inquisitor.assets.registrant.Registrant(self.registrant)
            )
        # Related: Emails
        for email in self.emails:
            asset = repo.get_asset_string(inquisitor.assets.email.Email, email)
            results.add(asset[1] if asset else inquisitor.assets.email.Email(email))
        # Related: Nameservers
        for nameserver in self.nameservers:
            asset = repo.get_asset_string(Host, nameserver)
            results.add(asset[1] if asset else Host(nameserver))
        # Return the results
        return results

    def transform(self, sources):
        # Prepare the results
        assets = set()
        # Google Transforms
        if 'google' in sources:
            # Acquire API
            google = sources['google']
            # Query: Site
            assets.update(google.transform('site:{}'.format(self.host)))
            # Query: Email
            assets.update(google.transform('"@{}"'.format(self.host)))
        # Shodan Transforms
        if 'shodan' in sources:
            # Acquire API
            shodan = sources['shodan']
            # Query: Plain
            assets.update(shodan.transform(self.host))
            # Query: Hostname
            assets.update(shodan.transform('hostname:"{}"'.format(self.host)))
        # Return the results
        return assets

    def is_owned(self, repo):
        # If manually classified, return the classification
        if self.owned is not None:
            return self.owned
        # Automatically determine ownership
        if self.parent is not None:
            parent = repo.get_asset_string(Host, self.parent)
            if parent and parent[1].is_owned(repo):
                return True
        if self.registrant is not None:
            registrant = repo.get_asset_string(
                inquisitor.assets.registrant.Registrant,
                self.registrant
            )
            if registrant and registrant[1].is_owned(repo):
                return True
        return False

REPOSITORY = 'hosts'
ASSET_CLASS = Host
OBJECT_ID = 'host'