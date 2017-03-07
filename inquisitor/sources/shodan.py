import inquisitor.assets.host
import inquisitor.assets.registrant
import shodan

class ShodanAPI:

	def __init__(self, api_key):
		self.api_key = api_key
		self.service = shodan.Shodan(self.api_key)

	def search(self, query):
        # TODO: Try to implement caching
		page = 1
		items = list()
		while True:
			results = self.service.search(query, page=page)
			items.extend(results['matches'])
			if len(items) >= results['total']:
				break
			page += 1
		return items
				
	def transform(self, query):
		assets = set()
		items = self.search(query)
		for item in items:
            # Extract Registrants
            assets.add(inquisitor.assets.registrant.Registrant(item['isp']))
            assets.add(inquisitor.assets.registrant.Registrant(item['org']))
            # Extract Hosts
            if 'hostname' in item['_shodan']['options']:
                assets.add(inquisitor.assets.host.Host(
                    item['_shodan']['options']['hostname']
                ))
            if 'http' in item and 'host' in item['http']:
                assets.add(inquisitor.assets.host.Host(
                    item['http']['host']
                ))
            assets.update([
                inquisitor.assets.host.Host(host)
                for host in item['hostnames']
            ])
            assets.update([
                inquisitor.assets.host.Host(host)
                for host in item['domains']
            ])
        return assets