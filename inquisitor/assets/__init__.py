import sys

class Asset(object):

    def __init__(self, owned=None):
        self.owned = owned
        self.transforms = dict()

    def cache_transform_store(self, source, assets):
        cached = list()
        for asset in assets:
            module_name = asset.__class__.__module__
            module = sys.modules[module_name]
            entry = [module_name, getattr(asset, module.OBJECT_ID)]
            if entry not in cached:
                cached.append(entry)
        self.transforms[source] = cached

    def cache_transform_get(self, source, repo):
        results = set()
        if source not in self.transforms:
            return results
        cached = self.transforms[source]
        for module_name, object_id in cached:
            module = sys.modules[module_name]
            asset_type = module.ASSET_CLASS
            results.add(repo.get_asset_string(
                asset_type,
                object_id,
                create=True,
            )[1])
        return results
