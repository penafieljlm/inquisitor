import unidecode
import urlparse

class RegistrantValidateException(Exception):
    pass

def canonicalize(registrant):
    if not registrant:
        raise RegistrantValidateException('Registrants cannot be None')
    if not isinstance(registrant, str) and not isinstance(registrant, unicode):
        raise RegistrantValidateException('Registrants must be strings')
    registrant = unidecode.unidecode(unicode(registrant.strip())).upper()
    return registrant

def main_classify_args(parser):
    parser.add_argument(
        '-ar', '--accept-registrant',
        metavar='REGISTRANT',
        type=canonicalize,
        nargs='+',
        help='Specifies a registrant to classify as accepted.',
        dest='registrants_accepted',
        default=list(),
    )
    parser.add_argument(
        '-ur', '--unmark-registrant',
        metavar='REGISTRANT',
        type=canonicalize,
        nargs='+',
        help='Specifies a registrant to classify as unmarked.',
        dest='registrants_unmarked',
        default=list(),
    )
    parser.add_argument(
        '-rr', '--reject-registrant',
        metavar='REGISTRANT',
        type=canonicalize,
        nargs='+',
        help='Specifies a registrant to classify as rejected.',
        dest='registrants_rejected',
        default=list(),
    )

def main_classify_canonicalize(args):
    accepted = set(args.registrants_accepted)
    unmarked = set(args.registrants_unmarked)
    rejected = set(args.registrants_rejected)
    redundant = set.intersection(accepted, unmarked, rejected)
    if redundant:
        raise ValueError(
            ('The following registrants were classified '
            'more than once: {}').format(list(redundant))
        )
    accepted = set([canonicalize(a) for a in accepted])
    unmarked = set([canonicalize(a) for a in unmarked])
    rejected = set([canonicalize(a) for a in rejected])
    return (accepted, unmarked, rejected)

class Registrant(object):

    def __init__(self, registrant, owned=None):
        self.registrant = canonicalize(registrant)
        self.owned = owned

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return False
        return self.registrant == other.registrant

    def related(self, repo):
        # Prepare the results
        results = set()
        # Return the results
        return results

    def transform(self, sources):
        # Prepare the results
        assets = set()
        # Google Transforms
        if 'google' in sources:
            # Acquire API
            google = sources['google']
            # Query: Plain
            assets.update(google.transform(self.registrant))
        # Shodan Transforms
        if 'shodan' in sources:
            # Acquire API
            shodan = sources['shodan']
            # Query: Plain
            assets.update(shodan.transform(self.registrant))
            # Query: Organization
            assets.update(shodan.transform('org:"{}"'.format(self.registrant)))
        # Return the results
        return assets

    def is_owned(self, repo):
        if self.owned:
            return True
        return False

REPOSITORY = 'registrants'
ASSET_CLASS = Registrant
OBJECT_ID = 'registrant'