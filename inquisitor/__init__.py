import inquisitor.assets.block
import inquisitor.assets.email
import inquisitor.assets.host
import inquisitor.assets.linkedin
import inquisitor.assets.registrant
import sys
import unqlite

ASSET_MODULES = [
    inquisitor.assets.registrant,
    inquisitor.assets.block,
    inquisitor.assets.host,
    inquisitor.assets.email,
    inquisitor.assets.linkedin,
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

    def get_asset_object(self, asset, create=False, store=False):
        result = self.get_asset_data(asset)
        asset_type = asset.__class__
        if result:
            __id = result['__id']
            data = result['data']
            obj = asset_type.__new__(asset_type)
            for name, value in data.iteritems():
                setattr(obj, name, value)
            obj.transforms = dict(obj.transforms)
            return (__id, obj)
        elif create:
            asset_module = sys.modules[asset_type.__module__]
            asset = asset_type(getattr(asset, asset_module.OBJECT_ID))
            result = (None, asset)
            if store:
                result[0] = self.put_asset_object(asset)
            return result
        return None

    def get_asset_string(
        self,
        asset_type,
        identifier,
        create=False,
        store=False
    ):
        query = asset_type.__new__(asset_type)
        module = sys.modules[asset_type.__module__]
        setattr(query, module.OBJECT_ID, identifier)
        return self.get_asset_object(query, create=create, store=store)

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
                obj.transforms = dict(obj.transforms)
                if include(obj, data):
                    results.add(obj)
                index += 1
                if limit and index >= limit:
                    break
        return results

    def put_asset_object(self, asset, overwrite=False):
        result = None
        module = sys.modules[asset.__class__.__module__]
        repository = self.repositories[module.REPOSITORY]
        exists = self.get_asset_data(asset)
        if not exists:
            result = repository.store({'data': asset.__dict__})
        elif overwrite:
            repository.update(exists['__id'], {'data': asset.__dict__})
            result = exists['__id']
        if not exists or overwrite:
            for related in asset.related(self):
                self.put_asset_object(related, overwrite=False)
        return result

    def put_asset_string(
            self,
            asset_type, 
            identifier, 
            owned=None, 
            overwrite=False
        ):
        asset = asset_type(identifier, owned=owned)
        self.put_asset_object(asset, overwrite=overwrite)
