# Inquisitor

> **Note: The development of this tool was originally part of my application to a company I was applying with. I was given four days to build it from the ground up so I'm probably going to do some cleanup first before I move forward with adding new features. Please bear with me here.**

Inquisitor is a simple for gathering information on companies and organizations through the use of Open Source Intelligence (OSINT) sources.

The key features of Inquisitor include:

1. The ability to cascade the ownership label of an asset (e.g. if a Registrant Name is known to belong to the target organization, then the hosts and networks registered with that name shall be marked as belonging to the target organization)
2. The ability transform assets into other potentially related assets through querying open sources such as Google and Shodan
3. The ability to visualize the relationships of those assets through a zoomable pack layout

It is heavily inspired from how Maltego operates, except in this tool, all transforms are performed automatically.

## Concept

The whole concept of Inquisitor revolves around the idea of extracting information from open sources based on what is already known about a target organization. In the context of Inquisitor these are called "transforms". Related information may also be immidiately retrieved from an known asset based on metadata also retrievable from open sources such as whois and internet registries.

## Installation

To install Inquisitor, simply clone the repository, enter it, and execute the installation script.
```
pip install Cython click
git clone git@github.com:penafieljlm/inquisitor.git
cd inquisitor
python setup.py install
```

## Usage

Inquisitor has five basic commands which include `scan`, `status`, `classify`, `dump`, and `visualize`.
```
usage: inq [-h] {scan,status,classify,dump,visualize} ...

optional arguments:
  -h, --help            show this help message and exit

command:
  {scan,status,classify,dump,visualize}
                        The action to perform.
    scan                Search OSINT sources for intelligence based on known
                        assets belonging to the target.
    status              Prints out the current status of the specified
                        intelligence database.
    classify            Classifies an existing asset as either belonging or
                        not belonging to the target. Adds a new asset with the
                        specified classification if none is present.
    dump                Dumps the contents of the database into a JSON file
    visualize           Create a D3.js visualization based on the contents of
                        the specified intelligence database.
```

### Scan

In scan mode, the tool runs all available transforms for all the assets you have in your Intelligence Database. Make sure to create API Keys for the various OSINT sources indicated below and provide it to the script lest the transforms using those sources be skipped. Also, make sure you seed your Intelligence Database with some known owned target assets using the `classify` command first because if the database does not contain any owned assets, there will be nothing to transform.
```
usage: inq scan [-h] [--google-dev-key GOOGLE_DEV_KEY]
                          [--google-cse-id GOOGLE_CSE_ID]
                          [--google-limit GOOGLE_LIMIT]
                          [--shodan-api-key SHODAN_API_KEY]
                          [--shodan-limit SHODAN_LIMIT]
                          DATABASE

positional arguments:
  DATABASE              The path to the intelligence database to use. If
                        specified file does not exist, a new one will be
                        created.

optional arguments:
  -h, --help            show this help message and exit
  --google-dev-key GOOGLE_DEV_KEY
                        Specifies the developer key to use to query Google
                        Custom Search. Visit the Google APIs Console
                        (http://code.google.com/apis/console) to get an API
                        key. If notspecified, the script will simply skip
                        asset transforms that involve Google Search.
  --google-cse-id GOOGLE_CSE_ID
                        Specifies the custom search engine to query. Visit the
                        Google Custom Search Console
                        (https://cse.google.com/cse/all) to create your own
                        Google Custom Search Engine. If not specified, the
                        script will simply skip asset transforms that involve
                        Google Search.
  --google-limit GOOGLE_LIMIT
                        The number of pages to limit Google Search to. This is
                        to avoid exhausting your daily quota.
  --shodan-api-key SHODAN_API_KEY
                        Specifies the API key to use to query Shodan. Log into
                        your Shodan account (https://www.shodan.io/) and look
                        at the top right corner of the page in order to view
                        your API key. If not specified, the script will simply
                        skip asset transforms that involve Shodan.
  --shodan-limit SHODAN_LIMIT
                        The number of pages to limit Shodan Search to. This is
                        to avoid exhausting your daily quota.
```

### Status

In status mode, the tool simply prints out a quick summary of the status of your scan database.
```
usage: inq status [-h] [-s] DATABASE

positional arguments:
  DATABASE      The path to the intelligence database to use. If specified
                file does not exist, a new one will be created.

optional arguments:
  -h, --help    show this help message and exit
  -s, --strong  Indicates if the status will be based on the strong ownership
                classification.
```

### Classify

In classify mode, you will be able to manually add assets and re-classify already existing assets in the Intelligence Database. You should use this command to seed your Intelligence Database with known owned target assets.
```
usage: inq classify [-h] [-ar REGISTRANT [REGISTRANT ...]]
                              [-ur REGISTRANT [REGISTRANT ...]]
                              [-rr REGISTRANT [REGISTRANT ...]]
                              [-ab BLOCK [BLOCK ...]] [-ub BLOCK [BLOCK ...]]
                              [-rb BLOCK [BLOCK ...]] [-ah HOST [HOST ...]]
                              [-uh HOST [HOST ...]] [-rh HOST [HOST ...]]
                              [-ae EMAIL [EMAIL ...]] [-ue EMAIL [EMAIL ...]]
                              [-re EMAIL [EMAIL ...]]
                              [-al LINKEDIN [LINKEDIN ...]]
                              [-ul LINKEDIN [LINKEDIN ...]]
                              [-rl LINKEDIN [LINKEDIN ...]]
                              DATABASE

positional arguments:
  DATABASE              The path to the intelligence database to use. If
                        specified file does not exist, a new one will be
                        created.

optional arguments:
  -h, --help            show this help message and exit
  -ar REGISTRANT [REGISTRANT ...], --accept-registrant REGISTRANT [REGISTRANT ...]
                        Specifies a registrant to classify as accepted.
  -ur REGISTRANT [REGISTRANT ...], --unmark-registrant REGISTRANT [REGISTRANT ...]
                        Specifies a registrant to classify as unmarked.
  -rr REGISTRANT [REGISTRANT ...], --reject-registrant REGISTRANT [REGISTRANT ...]
                        Specifies a registrant to classify as rejected.
  -ab BLOCK [BLOCK ...], --accept-block BLOCK [BLOCK ...]
                        Specifies a block to classify as accepted.
  -ub BLOCK [BLOCK ...], --unmark-block BLOCK [BLOCK ...]
                        Specifies a block to classify as unmarked.
  -rb BLOCK [BLOCK ...], --reject-block BLOCK [BLOCK ...]
                        Specifies a block to classify as rejected.
  -ah HOST [HOST ...], --accept-host HOST [HOST ...]
                        Specifies a host to classify as accepted.
  -uh HOST [HOST ...], --unmark-host HOST [HOST ...]
                        Specifies a host to classify as unmarked.
  -rh HOST [HOST ...], --reject-host HOST [HOST ...]
                        Specifies a host to classify as rejected.
  -ae EMAIL [EMAIL ...], --accept-email EMAIL [EMAIL ...]
                        Specifies a email to classify as accepted.
  -ue EMAIL [EMAIL ...], --unmark-email EMAIL [EMAIL ...]
                        Specifies a email to classify as unmarked.
  -re EMAIL [EMAIL ...], --reject-email EMAIL [EMAIL ...]
                        Specifies a email to classify as rejected.
  -al LINKEDIN [LINKEDIN ...], --accept-linkedin LINKEDIN [LINKEDIN ...]
                        Specifies a LinkedIn Account to classify as accepted.
  -ul LINKEDIN [LINKEDIN ...], --unmark-linkedin LINKEDIN [LINKEDIN ...]
                        Specifies a LinkedIn Account to classify as unmarked.
  -rl LINKEDIN [LINKEDIN ...], --reject-linkedin LINKEDIN [LINKEDIN ...]
                        Specifies a LinkedIn Account to classify as rejected.
```

### Dump

In dump mode, you will be able to dump the contents of the Intelligence Database into a human-readable JSON file.
```
usage: inq dump [-h] [-j FILE] [-a] DATABASE

positional arguments:
  DATABASE              The path to the intelligence database to use. If
                        specified file does not exist, a new one will be
                        created.

optional arguments:
  -h, --help            show this help message and exit
  -j FILE, --json FILE  The path to dump the JSON file to. Overwrites existing
                        files.
  -a, --all             Include rejected assets in dump.
```

### Visualize

In visualize mode, you will be able to acquire a hierarchical visualization of the Intelligence Repository.
```
usage: inq visualize [-h] [-l] DATABASE

positional arguments:
  DATABASE    The path to the intelligence database to use. If specified file
              does not exist, a new one will be created.

optional arguments:
  -h, --help  show this help message and exit
  -l, --last  Simply open the last visualization generated instead of creating
              a new one.
```

## Development

The the Inquisitor project is laid out in the following format:
```
.
|-- README.md
|-- inquisitor
|   |-- __init__.py
|   |-- assets
|   |   |-- __init__.py
|   |   |-- block.py
|   |   |-- email.py
|   |   |-- host.py
|   |   |-- linkedin.py
|   |   `-- registrant.py
|   |-- extractors
|   |   |-- __init__.py
|   |   `-- emails.py
|   `-- sources
|       |-- __init__.py
|       |-- google_search.py
|       `-- shodan_search.py
|-- inq
|-- report
|   `-- index.html
|-- setup.py
`-- tests
    |-- __init__.py
    `-- test_inq.py
```

It has three main modules named `assets`, `extractors`, and `sources`. The main script is called `inq`.

As a developer you would mostly be interested in adding new types of assets into the system so the developer guide would mostly focus on that.

### Repository

Before we move on to actually implementing asset classes, we would first need to understand how to interact with the Intelligence Database as we will be interacting with it when we derive related assets from our asset classes.

The source code for the Intelligence Database is stored in the `inquisitor/__init__.py` file. The actual name for the logical wrapper of the Intelligence Database is called `IntelligenceRepository`.

You only need to call the `IntelligenceRepository.get_asset_string` function from asset classes as appending new assets onto the Intelligence Database is the responsibility of the `scan` module in the `inq` script. You would mostly use this function to create instances of assets or retrieve them from the database if they exist. This function is important when returning assets from the `related` and `transform` functions of your asset classes as creating new asset objects is expensive since some of them use network resources during initialization.

```
Function

  IntelligenceRepository.get_asset_string(asset_type, identifier, create=False, store=False)

Description
    
    Retrieves the primary key and asset object for the asset with the provided 
    type and identifier.

Parameters

    asset_type: class, required

        The type of the asset to retrieve from the Intelligence Database. You
        will actually have to pass the class object of the asset type you want
        to retrieve.

    identifier: any, required

        The identifier of the asset to retrieve. Consider the identifier as the
        unique attribute of an asset object. As for which attribute is to be
        used to identify an asset, it depends on the contents of the OBJECT_ID
        variable in the asset module.

    create: bool, optional, default=False

        When no matching asset object is found, a new one will be created and 
        returned if this parameter is set to True. The new asset will not
        necessarily be stored in the Intelligence Database unless specified
        using the "store" parameter. However, I suggest you do not do this as
        adding assets to the Intelligence Database is the responsibility of
        another module.

    store: bool, optional, default=False

        When a new asset is created when none is found, the new one will be
        stored in the Intelligence Database. As said previously, I suggest that
        you do not do this as adding assets to the Intelligence Database is the
        responsibility of another module.

Returns

    A two-element tuple where the first element is the database primary key of 
    the element returned, and the second element is the deserialized asset 
    object retrieved from the database.

    None if the asset was not found.

    If the asset was not found and the create flag was set to True, the primary
    key member of the tuple will be set to None.

```

### Assets

To create a new asset type, create a new file inside the `inquisitor/assets` directory and paste the following skeleton code inside:

```python
import inquisitor.assets

class ASSET_NAMEValidateException(Exception):
    pass

def canonicalize(ASSET_IDENTIFIER):
    return ASSET_IDENTIFIER

def main_classify_args(parser):
    parser.add_argument(
        '-aASSET_NAME_LETTER', '--accept-ASSET_NAME',
        metavar='ASSET_NAME',
        type=canonicalize,
        nargs='+',
        help='Specifies a ASSET_NAME to classify as accepted.',
        dest='ASSET_NAMEs_accepted',
        default=list(),
    )
    parser.add_argument(
        '-uASSET_NAME_LETTER', '--unmark-ASSET_NAME',
        metavar='ASSET_NAME',
        type=canonicalize,
        nargs='+',
        help='Specifies a ASSET_NAME to classify as unmarked.',
        dest='ASSET_NAMEs_unmarked',
        default=list(),
    )
    parser.add_argument(
        '-rASSET_NAME_LETTER', '--reject-ASSET_NAME',
        metavar='ASSET_NAME',
        type=canonicalize,
        nargs='+',
        help='Specifies a ASSET_NAME to classify as rejected.',
        dest='ASSET_NAME_rejected',
        default=list(),
    )

def main_classify_canonicalize(args):
    accepted = set(args.ASSET_NAMEs_accepted)
    unmarked = set(args.ASSET_NAMEs_unmarked)
    rejected = set(args.ASSET_NAME_rejected)
    redundant = set.intersection(accepted, unmarked, rejected)
    if redundant:
        raise ValueError(
            ('Conflicting classifications for ASSET_NAMEs '
            ': {}').format(list(redundant))
        )
    accepted = set([canonicalize(a) for a in accepted])
    unmarked = set([canonicalize(a) for a in unmarked])
    rejected = set([canonicalize(a) for a in rejected])
    return (accepted, unmarked, rejected)

class ASSET_NAME(inquisitor.assets.Asset):

    def __init__(self, ASSET_IDENTIFIER, owned=None):
        super(self.__class__, self).__init__(owned=owned)
        self.ASSET_IDENTIFIER = canonicalize(ASSET_IDENTIFIER)
        # TODO: Perform other initialization actions here

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return False
        return self.ASSET_IDENTIFIER == other.ASSET_IDENTIFIER

    def related(self, repo):
        # Prepare the results
        results = set()
        # TODO: Create related assets here based on the attributes of this asset
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
                # TODO: Perform Google queries here and the results to 'subassets'
                # Cache The Transform
                self.cache_transform_store('google', subassets)
            assets.update(subassets)
        # Shodan Transforms
        if sources.get('shodan'):
            subassets = self.cache_transform_get('shodan', repo)
            if not subassets:
                # Acquire API
                shodan = sources['shodan']
                # TODO: Perform Google queries here and the results to 'subassets'
                # Cache The Transform
                self.cache_transform_store('shodan', subassets)
            assets.update(subassets)
        # Return the results
        return assets

    def is_owned(self, repo):
        if self.owned:
            return True
        # TODO: Automatically determine ownership based on repo contents
        return False

    def parent_asset(self, repo):
        # TODO: Return parent asset based on repo contents
        return None

REPOSITORY = 'ASSET_REPOSITORY'
ASSET_CLASS = ASSET_NAME
OBJECT_ID = 'ASSET_IDENTIFIER'
```

Now replace the following strings with the appropriate values
* `ASSET_NAME` : Proper name of your asset (e.g. Registrant, Host, etc.)
* `ASSET_IDENTIFIER` : The name of the identifier attribute of your asset
* `ASSET_NAME_LETTER` : The first letter of your asset in lowercase
* `ASSET_REPOSITORY` : Lower case of the plural form of your asset name

Finally, in `inquisitor/__init__.py`, register your asset in the `ASSET_MODULES` list. Make sure you import your new asset from the file in question.

Congratulations! By this point, you now have a new working asset type!

However, you are going to need to implement the following methods to make sure your assets get correlated with other asset types:

```
Function

    related

Description
  
      Returns the set of assets directly related to the asset in question (i.e.
      those that can be derived without querying a search engine).

      When creating asset objects, make sure you use the 
      IntelligenceRepository.get_asset_string method instead of instatiating a 
      new one your self so the asset can be returned from the repository if it 
      exists.

      Set the create flag to True when calling the method in question in order
      to return a new object when one isn't found.

      Set the store flag to False as appending assets is the job of another
      module.

Parameters

    repo: IntelligenceRepository

        The Intelligence Repository that is being used in the current context.

Returns

    Set of assets directly related to the asset in question. 

```

```
Function

    transform

Description
  
      Returns the set of assets potentially related to the asset in question
      (i.e. those that can be derived by querying a search engine).

      You may access search engine objects through the provided sources
      parameter.

      Each search engine object has a transform method which automatically
      creates asset objects for you. You just need to provide it the repository
      and your query string, and then append the objects it returns to the set
      of assets to be returned by your asset's transform method.

Parameters

    repo: IntelligenceRepository

        The Intelligence Repository that is being used in the current context.

    sources: dict

        The list of search engine objects that are available for use.

Returns

    Set of assets potentially related to the asset in question.
    
```

```
Function

    is_owned

Description
  
     Determines if there is high confidence that this asset does indeed belong
     to the target. Usually checks for any "strong" classification tag first by
     looking at the contents of the "owned" variable, before performing
     automatic evaluation.

     Automatic evaluation depends on what type of asset you're writing. For
     example, for a Host asset, the secondary sources of determining ownership
     would include looking if its registrant is owned by the target, if it's
     parent domain is owned by the target. etc.

Parameters

    repo: IntelligenceRepository

        The Intelligence Repository that is being used in the current context.

Returns

    True it is determined with high confidence that this asset does indeed 
    belong to the target.
    
```

```
Function

    parent_asset

Description
  
     Returns the asset object that is considered the parent of this asset
     object.

Parameters

    repo: IntelligenceRepository

Returns

    The asset object that this asset falls under (e.g. a Block is under a 
    Registrant, a Host is under a Block, a Host is under another Host, an Email
    is under a Host, etc. This is primarily used for visualization.
    
```

After implementing the above methods, make sure you set the `REPOSITORY`, `ASSET_CLASS`, and `OBJECT_ID` variables on the bottom of your asset's source code.

## Contact and Notes

The scan mode isn't fully tested because of quotas concerning the search engines involved. Also, this project was made in a rush as part of a week-long hackaton challenge so there might be a lot of problems lying around. Please create an issue ticket or contact me at penafieljlm@gmail.com if you find a bug or have some questions.

## Future Developments

I should probably add a filter feature to dump and classify (especially classify, so classifications can be made en masse, e.g. "reject all hosts under fb.com" or something like that).
