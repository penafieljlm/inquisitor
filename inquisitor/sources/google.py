import googleapiclient.discovery
import inquisitor.assets.email
import inquisitor.assets.host
import inquisitor.extractors.emails

class GoogleCustomSearchAPI:

	def __init__(self, dev_key, cse_id, limit=None):
		self.dev_key = dev_key
		self.cse_id = cse_id
		self.limit = limit
		self.service = googleapiclient.discovery.build(
			"customsearch", "v1",
			developerKey=self.dev_key,
		)

	def search(self, query):
		# TODO: Try to implement caching
		items = list()
		start = 1
		while True:
			if self.limit is not None and start > self.limit:
				break
			try:
				results = self.service.cse().list(
					q=query,
					cx=self.cse_id,
					start=start,
				).execute()
				items.extend(results['items'])
				start += 10
			except googleapiclient.errors.HttpError:
				break
		return items

	def transform(self, query):
		assets = set()
		items = self.search(query)
		for item in items:
            # Extract Hosts
            host = urlparse.urlparse(item['link']).netloc
            assets.add(inquisitor.assets.host.Host(host))
            # Extract Emails
            assets.update([
                inquisitor.assets.email.Email(email)
                for email in inquisitor.extractors.emails(item['snippet'])
            ])
            # TODO: extract potential social media accounts via the 
            # TODO: "pagemap/person" attribute
        return assets