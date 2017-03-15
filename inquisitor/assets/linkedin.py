import inquisitor.assets
import inquisitor.assets.registrant
import logging
import urlparse

class LinkedInValidateException(Exception):
	pass

def canonicalize(linkedin):
    if not linkedin:
        raise LinkedInValidateException('LinkedIn accounts cannot be None')
    if not isinstance(linkedin, str) and not isinstance(linkedin, unicode):
        raise LinkedInValidateException('LinkedIn accounts must be strings')
    # Validate URL
    parsed = urlparse.urlparse(linkedin)
    # Validate Network Location
    if not parsed.netloc.endswith('linkedin.com'):
    	raise LinkedInValidateException(
    		'Failed to validate LinkedIn account: {}'.format(linkedin)
		)
	# Validate Path
	if not parser.path.startswith('/in/'):
		raise LinkedInValidateException(
			'Failed to validate LinkedIn account: {}'.format(linkedin)
		)
	# Return the URL
    return linkedin

def main_classify_args(parser):
    parser.add_argument(
        '-al', '--accept-linkedin',
        metavar='LINKEDIN',
        type=canonicalize,
        nargs='+',
        help='Specifies a LinkedIn Account to classify as accepted.',
        dest='linkedin_accepted',
        default=list(),
    )
    parser.add_argument(
        '-ul', '--unmark-linkedin',
        metavar='LINKEDIN',
        type=canonicalize,
        nargs='+',
        help='Specifies a LinkedIn Account to classify as unmarked.',
        dest='linkedin_unmarked',
        default=list(),
    )
    parser.add_argument(
        '-rl', '--reject-linkedin',
        metavar='LINKEDIN',
        type=canonicalize,
        nargs='+',
        help='Specifies a LinkedIn Account to classify as rejected.',
        dest='linkedin_rejected',
        default=list(),
    )

def main_classify_canonicalize(args):
    accepted = set(args.linkedin_accepted)
    unmarked = set(args.linkedin_unmarked)
    rejected = set(args.linkedin_rejected)
    redundant = set.intersection(accepted, unmarked, rejected)
    if redundant:
        raise ValueError(
            ('Conflicting classifications for LinkedIn Accounts '
            ': {}').format(list(redundant))
        )
    accepted = set([canonicalize(a) for a in accepted])
    unmarked = set([canonicalize(a) for a in unmarked])
    rejected = set([canonicalize(a) for a in rejected])
    return (accepted, unmarked, rejected)

class LinkedIn(inquisitor.assets.Asset):

	def __init__(self, linkedin):
		super(self.__class__, self).__init__(owned=owned)
		self.linkedin = canonicalize(linkedin)
        self.username = urlparse.urlparse(self.linkedin).path.split('/')[3]
		# TODO: This should be retrieved using linkedin api but we don't have
		# TODO: time for that, so fill it up using Google Search results
		# TODO: instead
		self.corporation = None

	def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return False
        return self.linkedin == other.linkedin

    def related(self, repo):
        # Prepare the results
        results = set()
        # Related: Corporation
        if self.corporation:
            try:
                results.add(repo.get_asset_string(
                    inquisitor.assets.registrant.Registrant,
                    self.corporation,
                    create=True,
                )[1])
            except inquisitor.assets.registrant.RegistrantValidateException as e:
                logging.error(e.message)
        # Return the results
        return results

    def transform(self, repo, sources):
    	# Prepare the results
        assets = set()
        # Return the results
        return assets

    def is_owned(self, repo):
		# If manually classified, return the classification
        if self.owned is not None:
            return self.owned
        # Automatically determine ownership
        if self.corporation:
            try:
                registrant = repo.get_asset_string(
                    inquisitor.assets.registrant.Registrant,
                    self.corporation
                )
                if registrant and registrant[1].is_owned(repo):
                    return True
            except inquisitor.assets.registrant.RegistrantValidateException as e:
                logging.error(e.message)
        return False

    def parent_asset(self, repo):
        # Prepare result variable
        parent = None
        # Check if registrant is a valid parent
        if parent is None:
            if self.corporation:
                try:
                    registrant = repo.get_asset_string(
                        inquisitor.assets.registrant.Registrant,
                        self.corporation,
                    )
                    if registrant and registrant[1].is_owned(repo):
                        parent = registrant[1]
                        return parent
                except inquisitor.assets.registrant.RegistrantValidateException as e:
                    logging.error(e.message)
        # If no parental candidate is found, return None
        return None

REPOSITORY = 'linkedins'
ASSET_CLASS = LinkedIn
OBJECT_ID = 'linkedin'