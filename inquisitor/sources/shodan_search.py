import inquisitor.assets.host
import inquisitor.assets.registrant
import logging
import shodan

class ShodanAPI:

    def __init__(self, api_key, limit=None):
        self.api_key = api_key
        self.service = shodan.Shodan(self.api_key)
        self.limit = limit

    def search(self, query):
        page = 1
        items = list()
        while True:
            results = self.service.search(query, page=page)
            items.extend(results['matches'])
            if len(items) >= results['total']:
                break
            page += 1
        return items
                
    def transform(self, repository, query):
        assets = set()
        items = self.search(query)
        for item in items:
            # Extract ISP Registrant
            try:
                assets.add(repository.get_asset_string(
                    inquisitor.assets.registrant.Registrant,
                    item['isp'],
                    create=True,
                )[1])
            except inquisitor.assets.registrant.RegistrantValidateException as e:
                logging.error(e.message)
            # Extract Organization Registrant
            try:
                assets.add(repository.get_asset_string(
                    inquisitor.assets.registrant.Registrant,
                    item['org'],
                    create=True,
                )[1])
            except inquisitor.assets.registrant.RegistrantValidateException as e:
                logging.error(e.message)
            # Extract Host From Options
            if (item.get('_shodan') and item.get('_shodan').get('options') and 
                item.get('_shodan').get('options').get('hostname')):
                try:
                    assets.add(repository.get_asset_string(
                        inquisitor.assets.host.Host,
                        item['_shodan']['options']['hostname'],
                        create=True,
                    )[1])
                except inquisitor.assets.host.HostValidateException as e:
                    logging.error(e.message)
            # Extract Host From HTTP
            if item.get('http') and item.get('http').get('host'):
                try:
                    assets.add(repository.get_asset_string(
                        inquisitor.assets.host.Host,
                        item['http']['host'],
                        create=True,
                    )[1])
                except inquisitor.assets.host.HostValidateException as e:
                    logging.error(e.message)
            # Extract Hosts From Hostnames
            for host in item['hostnames']:
                try:
                    assets.add(repository.get_asset_string(
                        inquisitor.assets.host.Host,
                        host,
                        create=True,
                    )[1])
                except inquisitor.assets.host.HostValidateException as e:
                    logging.error(e.message)
            # Extract Hosts From Domains
            for host in item['domains']:
                try:
                    assets.add(repository.get_asset_string(
                        inquisitor.assets.host.Host,
                        host,
                        create=True,
                    )[1])
                except inquisitor.assets.host.HostValidateException as e:
                    logging.error(e.message)
        return assets