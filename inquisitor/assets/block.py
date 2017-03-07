import inquisitor.assets.registrant
import ipwhois
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
            ('The following blocks were classified '
            'more than once: {}').format(list(redundant))
        )
    accepted = set([canonicalize(a) for a in accepted])
    unmarked = set([canonicalize(a) for a in unmarked])
    rejected = set([canonicalize(a) for a in rejected])
    return (accepted, unmarked, rejected)

class Block(object):

    def __init__(self, block, owned=None):
        self.block = canonicalize(block)
        self.owned = owned
        # Acquire IP whois for block
        ip = str(netaddr.IPNetwork(self.block).ip)
        info = ipwhois.ipwhois.IPWhois(ip).lookup_rdap()
        registrant = None
        if info['network']['cidr'] == self.block:
            for key, obj in info['objects'].iteritems():
                if 'roles' in obj and 'registrant' in obj['roles']:
                    if 'contact' in obj and obj['contact']['kind'] == 'org':
                        registrant = obj['contact']['name']
                        break
        self.registrant = inquisitor.assets.registrant.canonicalize(registrant)

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return False
        return self.block == other.block

    def related(self, repo):
        # Prepare the results
        results = set()
        # Related: Registrant
        asset = repo.get_asset_string(
            inquisitor.assets.registrant.Registrant,
            self.registrant
        )
        results.add(
            asset[1] if asset else
            inquisitor.assets.registrant.Registrant(self.registrant)
        )
        # Return the results
        return results

    def transform(self, sources):
        # Prepare the results
        assets = set()
        # Shodan Transforms
        if 'shodan' in sources:
            # Acquire API
            shodan = sources['shodan']
            # Query: Network
            assets.update(shodan.transform('net:"{}"'.format(self.block)))
        # Return the results
        return assets

    def is_owned(self, repo):
        # If manually classified, return the classification
        if self.owned is not None:
            return self.owned
        # Automatically determine ownership
        registrant = repo.get_asset_string(
            inquisitor.assets.registrant.Registrant,
            self.registrant
        )
        if registrant and registrant[1].is_owned(repo):
            return True
        return False

REPOSITORY = 'blocks'
ASSET_CLASS = Block
OBJECT_ID = 'block'