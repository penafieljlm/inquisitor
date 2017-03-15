# Inquisitor

Inquisitor is a simple for gathering information on companies and organizations through the use of Open Source Intelligence (OSINT) sources.

The key features of Inquisitor include:

1. The ability to cascade the ownership label of an asset (e.g. if a Registrant Name is known to belong to the target organization, then the hosts and networks registered with that name shall be marked as belonging to the target organization)
2. The ability transform assets into other potentially related assets through querying open sources such as Google and Shodan
3. The ability to visualize the relationships of those assets through a zoomable pack layout

It is heavily inspired from how Maltego operates, except in this tool, all transforms are performed automatically.

## Installation

To install Inquisitor, simply clone the repository, enter it, and execute the installation script.
```
git clone git@github.com:penafieljlm/inquisitor.git
cd inquisitor
python setup.py install
```

## Usage

Inquisitor has five basic commands which include `scan`, `status`, `classify`, `dump`, and `visualize`.
```
usage: inquisitor.py [-h] {scan,status,classify,dump,visualize} ...

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
usage: inquisitor.py scan [-h] [--google-dev-key GOOGLE_DEV_KEY]
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
usage: inquisitor.py status [-h] [-s] DATABASE

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
usage: inquisitor.py classify [-h] [-ar REGISTRANT [REGISTRANT ...]]
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
usage: inquisitor.py dump [-h] [-j FILE] [-a] DATABASE

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
usage: inquisitor.py visualize [-h] DATABASE

positional arguments:
  DATABASE    The path to the intelligence database to use. If specified file
              does not exist, a new one will be created.

optional arguments:
  -h, --help  show this help message and exit
```
