import inquisitor.assets.host
import validate_email

class EmailValidateException(Exception):
    pass

def canonicalize(email):
    if not email:
        raise EmailValidateException('Emails cannot be None')
    if not isinstance(email, str) and not isinstance(email, unicode):
        raise EmailValidateException('Emails must be strings')
    email = email.strip()
    if not validate_email.validate_email(email):
        raise EmailValidateException(
            'Unable to validate email {}'.format(email)
        )
    recipient, domain = email.split('@')
    try:
        domain = inquisitor.assets.host.canonicalize(domain)
    except inquisitor.assets.host.HostValidateException:
        raise EmailValidateException(
            'Unable to validate domain for email {}'.format(email)
        )
    return '@'.join([recipient, domain])

def main_classify_args(parser):
    parser.add_argument(
        '-ae', '--accept-email',
        metavar='EMAIL',
        type=canonicalize,
        nargs='+',
        help='Specifies a email to classify as accepted.',
        dest='emails_accepted',
        default=list(),
    )
    parser.add_argument(
        '-ue', '--unmark-email',
        metavar='EMAIL',
        type=canonicalize,
        nargs='+',
        help='Specifies a email to classify as unmarked.',
        dest='emails_unmarked',
        default=list(),
    )
    parser.add_argument(
        '-re', '--reject-email',
        metavar='EMAIL',
        type=canonicalize,
        nargs='+',
        help='Specifies a email to classify as rejected.',
        dest='emails_rejected',
        default=list(),
    )

def main_classify_canonicalize(args):
    accepted = set(args.emails_accepted)
    unmarked = set(args.emails_unmarked)
    rejected = set(args.emails_rejected)
    redundant = set.intersection(accepted, unmarked, rejected)
    if redundant:
        raise ValueError(
            ('The following emails were classified '
            'more than once: {}').format(list(redundant))
        )
    accepted = set([canonicalize(a) for a in accepted])
    unmarked = set([canonicalize(a) for a in unmarked])
    rejected = set([canonicalize(a) for a in rejected])
    return (accepted, unmarked, rejected)

class Email(object):

    def __init__(self, email, owned=None):
        self.email = canonicalize(email)
        self.owned = owned
        recipient, domain = self.email.split('@')
        self.recipient = recipient
        self.domain = domain

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return False
        return self.email == other.email

    def related(self, repo):
        # Prepare results
        results = set()
        # Related: Domain
        asset = repo.get_asset_string(inquisitor.assets.host.Host, self.domain)
        results.add(asset[1] if asset else inquisitor.assets.host.Host(self.domain))
        # Return the results
        return results

    def transform(self, sources):
        # Prepare the results
        assets = set()
        # Google Transforms
        if 'google' in sources:
            # Acquire API
            google = sources['google']
            # Query: Email
            assets.update(google.transform('"{}"'.format(self.email)))
        # Return the results
        return assets

    def is_owned(self, repo):
        # If manually classified, return the classification
        if self.owned is not None:
            return self.owned
        # Automatically determine ownership
        host = repo.get_asset_string(inquisitor.assets.host.Host, self.domain)
        if host and host[1].is_owned(repo):
            return True
        return False

REPOSITORY = 'emails'
ASSET_CLASS = Email
OBJECT_ID = 'email'