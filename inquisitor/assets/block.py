import inquisitor.assets
import inquisitor.assets.registrant
import ipwhois
import logging
import netaddr

class BlockValidateException(Exception):
    pass

def canonicalize(block):
    if not block:
        raise BlockValidateException('Blocks cannot be None')
    if not isinstance(block, str) and not isinstance(block, unicode):
        raise BlockValidateException('Blocks must be strings')
    network = None
    try:
        network = netaddr.IPNetwork(block)
    except netaddr.core.AddrFormatError:
        raise BlockValidateException('Unable to parse block {}'.format(block))
    return str(network)

def main_classify_args(parser):
    parser.add_argument(
        '-ab', '--accept-block',
        metavar='BLOCK',
        type=canonicalize,
        nargs='+',
        help='Specifies a block to classify as accepted.',
        dest='blocks_accepted',
        default=list(),
    )
    parser.add_argument(
        '-ub', '--unmark-block',
        metavar='BLOCK',
        type=canonicalize,
        nargs='+',
        help='Specifies a block to classify as unmarked.',
        dest='blocks_unmarked',
        default=list(),
    )
    parser.add_argument(
        '-rb', '--reject-block',
        metavar='BLOCK',
        type=canonicalize,
        nargs='+',
        help='Specifies a block to classify as rejected.',
        dest='blocks_rejected',
        default=list(),
    )

def main_classify_canonicalize(args):
    accepted = set(args.blocks_accepted)
    unmarked = set(args.blocks_unmarked)
    rejected = set(args.blocks_rejected)
    redundant = set.intersection(accepted, unmarked, rejected)
    if redundant:
        raise ValueError(
            ('Conflicting classifications for blocks '
            ': {}').format(list(redundant))
        )
    accepted = set([canonicalize(a) for a in accepted])
    unmarked = set([canonicalize(a) for a in unmarked])
    rejected = set([canonicalize(a) for a in rejected])
    return (accepted, unmarked, rejected)

class Block(inquisitor.assets.Asset):

    def __init__(self, block, owned=None):
        super(self.__class__, self).__init__(owned=owned)
        self.block = canonicalize(block)
        # Acquire IP whois for block
        ip = str(netaddr.IPNetwork(self.block).ip)
        info = ipwhois.ipwhois.IPWhois(ip).lookup_rdap()
        self.registrant = None
        if (info.get('network') and info.get('network').get('cidr')
            and info.get('network').get('cidr') == self.block):
            for key, obj in info['objects'].iteritems():
                if obj.get('roles') and 'registrant' in obj.get('roles'):
                    if obj.get('contact') and obj.get('contact').get('kind') == 'org':
                        name = obj['contact']['name']
                        registrant = inquisitor.assets.registrant.canonicalize(
                            name
                        )
                        self.registrant = registrant
                        break

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return False
        return self.block == other.block

    def related(self, repo):
        # Prepare the results
        results = set()
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
        # Return the results
        return results

    def transform(self, repo, sources):
        # Prepare the results
        assets = set()
        # Shodan Transforms
        if sources.get('shodan'):
            subassets = self.cache_transform_get('shodan', repo)
            if not subassets:
                # Acquire API
                shodan = sources['shodan']
                # Query: Network
                subassets.update(shodan.transform(
                    repo, 'net:"{}"'.format(self.block))
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
        if self.registrant:
            try:
                registrant = repo.get_asset_string(
                    inquisitor.assets.registrant.Registrant,
                    self.registrant,
                )
                if registrant and registrant[1].is_owned(repo):
                    return True
            except inquisitor.assets.registrant.RegistrantValidateException as e:
                logging.error(e.message)
        return False

    def parent_asset(self, repo):
        # Prepare result variable
        parent = None
        # Check if this is a child of another netblock
        if parent is None:
            # Acquire start and end IPs of this netblock
            network = netaddr.IPNetwork(self.block)
            network_start = network.ip & network.netmask
            network_end = network_start + (network.size - 1)
            # Acquire other owned netblocks
            blocks = repo.get_assets(
                include=lambda o,d: (
                    self != o and
                    isinstance(o, self.__class__) and
                    o.is_owned(repo)
                )
            )
            # Check if this netblock is a child of another netblock
            parents = list()
            for block in blocks:
                # Acquire start and end IPs of the other netblock
                other = netaddr.IPNetwork(block.block)
                other_start = other.ip & other.netmask
                other_end = other_start + (other.size - 1)
                # Check if self is contained by the other netblock
                contained = (
                    other_start <= network_start and
                    network_end <= other_end and
                    network.size < other.size
                )
                # If contained, add as potential parent
                candidate = [block, other]
                if contained and candidate not in parents:
                    parents.append(candidate)
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

REPOSITORY = 'blocks'
ASSET_CLASS = Block
OBJECT_ID = 'block'