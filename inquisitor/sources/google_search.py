import googleapiclient.discovery
import inquisitor.assets.email
import inquisitor.assets.host
import inquisitor.assets.linkedin
import inquisitor.assets.registrant
import inquisitor.extractors.emails
import logging
import urlparse

class GoogleAPI:

    def __init__(self, dev_key, cse_id, limit=None):
        self.dev_key = dev_key
        self.cse_id = cse_id
        self.limit = limit
        self.service = googleapiclient.discovery.build(
            "customsearch", "v1",
            developerKey=self.dev_key,
        )

    def search(self, query):
        items = list()
        page = 1
        start = 1
        while True:
            if self.limit and page > self.limit:
                break
            try:
                results = self.service.cse().list(
                    q=query,
                    cx=self.cse_id,
                    start=start,
                ).execute()
                items.extend(results['items'])
                start += 10
                page += 1
            except googleapiclient.errors.HttpError:
                break
        return items

    def transform(self, repository, query):
        assets = set()
        items = self.search(query)
        for item in items:
            parsed_link = urlparse.urlparse(item['link'])
            # Extract Host
            try:
                assets.add(repository.get_asset_string(
                    inquisitor.assets.host.Host,
                    parsed_link.netloc,
                    create=True,
                )[1])
            except inquisitor.assets.host.HostValidateException as e:
                logging.error(e.message)
            # Extract Emails
            for email in inquisitor.extractors.emails.extract(item['snippet']):
                try:
                    assets.add(repository.get_asset_string(
                        inquisitor.assets.email.Email,
                        email,
                        create=True,
                    )[1])
                except inquisitor.assets.email.EmailValidateException as e:
                    logging.error(e.message)
            # Extract LinkedIn Accounts
            if parsed_link.netloc.endswith('linkedin.com'):
                try:
                    # Create the asset
                    asset = repository.get_asset_string(
                        inquisitor.assets.linkedin.LinkedIn,
                        parsed_link.netloc,
                        create=True,
                    )[1]
                    # Apply work around for acquiring the corporation
                    if (item.get('pagemap') and
                        item.get('pagemap').get('person') and 
                        item.get('pagemap').get('person').get('org')):
                        asset.corporation = inquisitor.assets.registrant.canonicalize(
                            item.get('pagemap').get('person').get('org')
                        )
                    # Add the asset
                    assets.add(asset)
                except inquisitor.assets.linkedin.LinkedInValidateException as e:
                    logging.error(e.message)
            # TODO: extract accounts for other social media networks
        return assets