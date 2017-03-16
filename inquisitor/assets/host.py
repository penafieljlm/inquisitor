import inquisitor.assets
import inquisitor.assets.block
import inquisitor.assets.email
import inquisitor.assets.registrant
import ipwhois
import logging
import netaddr
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
        raise HostValidateException('Invalid tld for host {}'.format(host))
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
            ('Conflicting classifications for hosts '
            ': {}').format(list(redundant))
        )
    accepted = set([canonicalize(a) for a in accepted])
    unmarked = set([canonicalize(a) for a in unmarked])
    rejected = set([canonicalize(a) for a in rejected])
    return (accepted, unmarked, rejected)

class Host(inquisitor.assets.Asset):
    
    def __init__(self, host, owned=None):
        super(self.__class__, self).__init__(owned=owned)
        self.host = canonicalize(host)
        # Acquire parent domain
        self.parent = None
        zones = self.host.split('.')
        if len(zones) > 1:
            self.parent = canonicalize('.'.join(zones[1:]))
        # Acquire IP address
        self.ip = None
        try: self.ip = socket.gethostbyname(self.host)
        except: pass
        # Acquire whois information
        self.registrant = None
        self.emails = set()
        self.nameservers = set()
        if self.ip:
            info = whois.whois(self.host)
            if info.get('org'):
                self.registrant = inquisitor.assets.registrant.canonicalize(
                    info['org']
                )
            if info.get('emails'):
                if type(info['emails']) is list:
                    for email in info['emails']:
                        self.emails.add(inquisitor.assets.email.canonicalize(email))
                elif type(info['emails']) in [str, unicode]:
                    email = info['emails']
                    self.emails.add(inquisitor.assets.email.canonicalize(email))
            if info.get('name_servers'):
                if type(info['name_servers']) is list:
                    for nameserver in info['name_servers']:
                        self.nameservers.add(canonicalize(nameserver))
                elif type(info['name_servers']) in [str, unicode]:
                    nameserver = info['name_servers']
                    self.nameservers.add(canonicalize(nameserver))
        self.emails = list(self.emails)
        self.nameservers = list(self.nameservers)
        # Acquire IP whois information
        self.blocks = set()
        if self.ip:
            tries = 0
            while tries < 3:
                try:
                    info = ipwhois.ipwhois.IPWhois(self.ip).lookup_rdap()
                    for block in info['network']['cidr'].split(','):
                        block = inquisitor.assets.block.canonicalize(block.strip())
                        self.blocks.add(block)
                    tries += 1
                except ipwhois.exceptions.HTTPLookupError:
                    continue
                except ipwhois.exceptions.HTTPRateLimitError:
                    continue
                except ipwhois.exceptions.IPDefinedError:
                    continue
        self.blocks = list(self.blocks)

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return False
        return self.host == other.host

    def related(self, repo):
        # Prepare results
        results = set()
        # Related: Parent
        if self.parent and len(self.parent.split('.')) > 1:
            try:
                results.add(repo.get_asset_string(
                    Host,
                    self.parent,
                    create=True,
                )[1])
            except HostValidateException as e:
                logging.error(e.message)
        # Related: Registrant
        if self.registrant:
            try:
                results.add(repo.get_asset_string(
                    inquisitor.assets.registrant.Registrant,
                    self.registrant,
                    create=True,
                )[1])
            except inquisitor.assets.registrant.RegistrantValidateException as e:
                logging.error(e.message)
        # Related: Emails
        for email in self.emails:
            try:
                results.add(repo.get_asset_string(
                    inquisitor.assets.email.Email,
                    email,
                    create=True,
                )[1])
            except inquisitor.assets.email.EmailValidateException as e:
                logging.error(e.message)
        # Related: Nameservers
        for nameserver in self.nameservers:
            try:
                results.add(repo.get_asset_string(
                    Host,
                    nameserver,
                    create=True,
                )[1])
            except HostValidateException as e:
                logging.error(e.message)
        # Related: Blocks
        for block in self.blocks:
            try:
                results.add(repo.get_asset_string(
                    inquisitor.assets.block.Block,
                    block,
                    create=True,
                )[1])
            except inquisitor.assets.block.BlockValidateException as e:
                logging.error(e.message)
        # Return the results
        return results

    def transform(self, repo, sources):
        # Prepare the results
        assets = set()
        # Google Transforms
        if sources.get('google'):
            subassets = self.cache_transform_get('google', repo)
            if not subassets:
                # Acquire API
                google = sources['google']
                # Query: Site
                subassets.update(google.transform(
                    repo, 'site:{}'.format(self.host))
                )
                # Query: Email
                subassets.update(google.transform(
                    repo, '"@{}"'.format(self.host))
                )
                # Cache The Transform
                self.cache_transform_store('google', subassets)
            assets.update(subassets)
        # Shodan Transforms
        if sources.get('shodan'):
            subassets = self.cache_transform_get('shodan', repo)
            if not subassets:
                # Acquire API
                shodan = sources['shodan']
                # Query: Plain
                subassets.update(shodan.transform(repo, self.host))
                # Query: Hostname
                subassets.update(shodan.transform(
                    repo, 'hostname:"{}"'.format(self.host))
                )
                # Cache The Transform
                self.cache_transform_store('shodan', subassets)
            assets.update(subassets)
        # Return the results
        return assets

    def is_owned(self, repo):
        # If manually classified, return the classification
        if self.owned is not None:
            return self.owned
        # Automatically determine ownership
        if self.parent:
            try:
                parent = repo.get_asset_string(Host, self.parent)
                if parent and parent[1].is_owned(repo):
                    return True
            except HostValidateException as e:
                logging.error(e.message)
        if self.registrant:
            try:
                registrant = repo.get_asset_string(
                    inquisitor.assets.registrant.Registrant,
                    self.registrant
                )
                if registrant and registrant[1].is_owned(repo):
                    return True
            except inquisitor.assets.registrant.RegistrantValidateException as e:
                logging.error(e.message)
        return False

    def parent_asset(self, repo):
        # Prepare result variable
        parent = None
        # Check if this host is the child of another domain
        if parent is None:
            if self.parent:
                try:
                    domain = repo.get_asset_string(Host, self.parent)
                    if domain and domain[1].is_owned(repo):
                        parent = domain[1]
                        return parent
                except HostValidateException as e:
                    logging.error(e.message)
        # Check if this host is the child of a network
        if parent is None:
            if self.ip:
                # Acquire owned netblocks where self is contained
                address = netaddr.IPAddress(self.ip)
                blocks = repo.get_assets(
                    include=lambda o,d: (
                        isinstance(o, inquisitor.assets.block.Block) and
                        o.is_owned(repo) and
                        address in netaddr.IPNetwork(o.block)
                    )
                )
                # Collate blocks and their corresponding network object
                parents = [
                    [block, netaddr.IPNetwork(block.block)]
                    for block in blocks
                ]
                # Return the smallest parent
                if parents:
                    parent = min(parents, key=lambda e: e[1])[0]
                    return parent
        # Check if registrant is a valid parent
        if parent is None:
            if self.registrant:
                try:
                    registrant = repo.get_asset_string(
                        inquisitor.assets.registrant.Registrant,
                        self.registrant,
                    )
                    if registrant and registrant[1].is_owned(repo):
                        parent = registrant[1]
                        return parent
                except inquisitor.assets.registrant.RegistrantValidateException as e:
                    logging.error(e.message)
        # If no parental candidate is found, return None
        return None

REPOSITORY = 'hosts'
ASSET_CLASS = Host
OBJECT_ID = 'host'