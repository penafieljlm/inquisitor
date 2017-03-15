import inquisitor.assets
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
            ('Conflicting classifications for registrants '
            ': {}').format(list(redundant))
        )
    accepted = set([canonicalize(a) for a in accepted])
    unmarked = set([canonicalize(a) for a in unmarked])
    rejected = set([canonicalize(a) for a in rejected])
    return (accepted, unmarked, rejected)

class Registrant(inquisitor.assets.Asset):

    def __init__(self, registrant, owned=None):
        super(self.__class__, self).__init__(owned=owned)
        self.registrant = canonicalize(registrant)

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return False
        return self.registrant == other.registrant

    def related(self, repo):
        # Prepare the results
        results = set()
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
                # Query: Plain
                subassets.update(google.transform(repo, self.registrant))
                # Query: LinkedIn
                subassets.update(google.transform(
                    repo, 'site:linkedin.com {}'.format(self.registrant)
                ))
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
                subassets.update(shodan.transform(repo, self.registrant))
                # Query: Organization
                subassets.update(shodan.transform(
                    repo, 'org:"{}"'.format(self.registrant))
                )
                # Cache The Transform
                self.cache_transform_store('shodan', subassets)
            assets.update(subassets)
        # Return the results
        return assets

    def is_owned(self, repo):
        if self.owned:
            return True
        return False

    def parent_asset(self, repo):
        # Registrants don't have parents
        return None

REPOSITORY = 'registrants'
ASSET_CLASS = Registrant
OBJECT_ID = 'registrant'