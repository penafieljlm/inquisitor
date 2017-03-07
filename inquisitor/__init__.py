import inquisitor.assets.block
import inquisitor.assets.email
import inquisitor.assets.host
import inquisitor.assets.registrant
import sys
import unqlite

ASSET_MODULES = [
    inquisitor.assets.registrant,
    inquisitor.assets.block,
    inquisitor.assets.host,
    inquisitor.assets.email,
]

class IntelligenceRepository:

    def __init__(self, path):
        self.database = unqlite.UnQLite(path)
        self.repositories = dict()
        for asset_module in ASSET_MODULES:
            identifier = asset_module.REPOSITORY
            repository = self.database.collection(identifier)
            repository.create()
            self.repositories[identifier] = repository

    def get_asset_data(self, asset):
        module = sys.modules[asset.__class__.__module__]
        repository = self.repositories[module.REPOSITORY]
        identifier = module.OBJECT_ID
        query = getattr(asset, identifier)
        results = repository.filter(lambda a: a['data'][identifier] == query)
        return results[0] if results else None

    def get_asset_object(self, asset):
        result = self.get_asset_data(asset)
        if result:
            __id = result['__id']
            data = result['data']
            obj = asset.__class__.__new__(asset.__class__)
            for name, value in data.iteritems():
                setattr(obj, name, value)
            return (__id, obj)
        return None

    def get_asset_string(self, asset_type, identifier):
        query = asset_type.__new__(asset_type)
        module = sys.modules[asset_type.__module__]
        setattr(query, module.OBJECT_ID, identifier)
        return self.get_asset_object(query)

    def get_assets(self, include, limit=None):
        results = set()
        for asset_module in ASSET_MODULES:
            asset_class = asset_module.ASSET_CLASS
            repository = self.repositories[asset_module.REPOSITORY]
            index = 0
            for data in repository.all():
                data = data['data']
                obj = asset_class.__new__(asset_class)
                for name, value in data.iteritems():
                    setattr(obj, name, value)
                if include(obj, data):
                    results.add(obj)
                index += 1
                if limit is not None and index >= limit:
                    break
        return results

    def put_asset_object(self, asset, overwrite=False):
        module = sys.modules[asset.__class__.__module__]
        repository = self.repositories[module.REPOSITORY]
        exists = self.get_asset_data(asset)
        if not exists:
            repository.store({'data': asset.__dict__})
        elif overwrite:
            repository.update(exists['__id'], {'data': asset.__dict__})
        if not exists or overwrite:
            for related in asset.related(self):
                self.put_asset_object(related, overwrite=False)

    def put_asset_string(
            self,
            asset_type, 
            identifier, 
            owned=None, 
            overwrite=False
        ):
        asset = asset_type(identifier, owned=owned)
        self.put_asset_object(asset, overwrite=overwrite)
