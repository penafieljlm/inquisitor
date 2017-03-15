import argparse
import inquisitor
import inquisitor.sources.google_search
import inquisitor.sources.shodan_search
import json
import logging
import os
import SimpleHTTPServer
import SocketServer
import sys
import tabulate
import webbrowser

# Ininitialize Logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

def database(path):
    return inquisitor.IntelligenceRepository(path)

def scan(
    repository,
    google_dev_key=None, 
    google_cse_id=None, 
    google_limit=None, 
    shodan_api_key=None,
    shodan_limit=None,
):
    sources = dict()
    # Initialize Google as a transform source
    if not google_dev_key or not google_cse_id:
        if not google_dev_key:
            logger.warning(
                'Skipping Google Transforms. No GOOGLE_DEV_KEY provided. '
                'Please provide the GOOGLE_DEV_KEY using the --google-dev-key '
                'parameter.'
            )
        if not google_cse_id:
            logger.warning(
                'Skipping Google Transforms. No GOOGLE_CSE_ID provided. '
                'Please provide the GOOGLE_CSE_ID using the --google-cse-id '
                'parameter.'
            )
    else:
        sources['google'] = inquisitor.sources.google_search.GoogleAPI(
            google_dev_key, google_cse_id, limit=google_limit
        )
        if not google_limit:
            logger.warning(
                'Google Search limit not set. This may potentially exhaust '
                'the daily quota of your Google API Key.'
            )
    # Initialize Shodan as a transform source
    if not shodan_api_key:
        logger.warning(
            'Skipping Shodan Transforms. No SHODAN_API_KEY provided. '
            'Please provide the SHODAN_API_KEY using the --shodan-api-key '
            'parameter.'
        )
    else:
        sources['shodan'] = inquisitor.sources.shodan_search.ShodanAPI(
            shodan_api_key, limit=shodan_limit
        )
        if not shodan_limit:
            logger.warning(
                'Shodan Search limit not set. This may potentially exhaust '
                'the daily quota of your Shodan API Key.'
            )
    # Check if any sources detected
    if not sources:
        logger.error('No valid transform sources available. Quitting.')
        exit(1)
    # Perform transforms on owned assets only
    found = 0
    logger.info('Initializing Inquisitor scan mode')
    owned = repository.get_assets(include=lambda o,d: o.is_owned(repository))
    if not owned:
        logger.error(
            'No assets available to transform. Please seed your database '
            'using the "classify" command.'
        )
        exit(1)
    for asset in owned:
        asset_type = asset.__class__
        asset_module_name = asset_type.__module__
        asset_module = sys.modules[asset_module_name]
        asset_identifier = getattr(asset, asset_module.OBJECT_ID)
        logger.info('Transforming: {}: {}'.format(
            asset_module_name,
            asset_identifier,
        ))
        for result in asset.transform(repository, sources):
            __id = repository.put_asset_object(result)
            if __id:
                result_type = result.__class__
                result_module_name = result_type.__module__
                result_module = sys.modules[result_module_name]
                result_identifier = getattr(result, result_module.OBJECT_ID)
                logger.info('Found: {}: {}'.format(
                    result_module_name,
                    result_identifier,
                ))
            found += 1
        repository.put_asset_object(asset, overwrite=True)
    logger.info('New assets found: {}'.format(found))
    logger.info('Inquisitor has completed')

def status(repository, strong):
    table = [
        ['Asset', 'Accepted', 'Unknown', 'Rejected', 'Total'],
        list(),
    ]
    for asset_module in inquisitor.ASSET_MODULES:
        asset_type = asset_module.ASSET_CLASS
        total = 0
        row = [asset_type.__name__]
        for owned in [True, None, False]:
            results = repository.get_assets(
                include=(
                    lambda o,d:
                        isinstance(o, asset_type) and (
                            (not strong and o.is_owned(repository) is owned) or
                            (strong and d['owned'] is owned)
                        )
                )
            )
            row.append(len(results))
            total += len(results)
        row.append(total)
        table.append(row)
    if not strong:
        table[0][3] = 'Not Accepted'
        for row in table:
            if row:
                del row[2]
    print tabulate.tabulate(table)

def classify(repository, args):
    for asset_module in inquisitor.ASSET_MODULES:
        # Extract assets from arguments
        classified = asset_module.main_classify_canonicalize(args)
        accepted, unmarked, rejected = classified
        targets = [
            (accepted, True),
            (unmarked, None),
            (rejected, False),
        ]
        # Execute asset classification
        for target, owned in targets:
            for identifier in target:
                repository.put_asset_string(
                    asset_module.ASSET_CLASS,
                    identifier,
                    owned=owned,
                    overwrite=True
                )

def dump(repository, path, all_flag):
    repo_dict = dict()
    for asset_module in inquisitor.ASSET_MODULES:
        asset_type = asset_module.ASSET_CLASS
        asset_list = list()
        results = repository.get_assets(
            include=lambda o,d: isinstance(o, asset_type)
        )
        for asset in results:
            if all_flag or asset.owned is not False:
                asset_entry = dict(asset.__dict__)
                asset_entry['owned'] = asset.is_owned(repository)
                asset_entry['strong_owned'] = asset.owned
                asset_list.append(asset_entry)
        repo_dict[asset_module.REPOSITORY] = list(reversed(sorted(
            asset_list, key=lambda a: a['owned']
        )))
    if path is None:
        print json.dumps(repo_dict, indent=4, sort_keys=True)
    else:
        with open(path, 'w') as handle:
            json.dump(repo_dict, handle, indent=4, sort_keys=True)

def visualize(repository):
    # TODO: use circle packing https://bl.ocks.org/mbostock/7607535
    def traverse(node, asset):
        # Determine name of node
        if asset:
            asset_type = asset.__class__
            asset_module = sys.modules[asset_type.__module__]
            node['name'] = '{} : {}'.format(
                asset_type.__name__,
                getattr(asset, asset_module.OBJECT_ID)
            )
        else:
            node['name'] = 'root'
        # Determine node children
        children = repository.get_assets(
            include=lambda o,d:
                o.is_owned(repository) and
                o.parent_asset(repository) == asset
        )
        if children:
            node['children'] = list()
            for child in children:
                subnode = dict()
                traverse(subnode, child)
                node['children'].append(subnode)
        else:
            node['size'] = 1
    # Start traversal
    root = {}
    traverse(root, None)
    # Initialize web server directory
    web_dir = os.path.join(os.path.dirname(__file__), 'report')
    os.chdir(web_dir)
    # Dump visualization to JSON file
    with open(os.path.join(web_dir, 'report.json'), 'w') as handle:
        json.dump(root, handle, indent=4, sort_keys=True)
    # Start HTTP Server
    port = 8080
    webbrowser.open('http://localhost:{}/index.html'.format(port), new=2)
    http_handler = SimpleHTTPServer.SimpleHTTPRequestHandler
    httpd = SocketServer.TCPServer(("", port), http_handler)
    httpd.serve_forever()

# Entry Point
if __name__ == '__main__':
    
    # Create main argument parser
    parent_parser = argparse.ArgumentParser(add_help=False)
    parent_parser.add_argument(
        'database',
        metavar='DATABASE',
        type=database,
        help=(
            'The path to the intelligence database to use. If specified file '
            'does not exist, a new one will be created.'
        ),
    )

    # Create subcommand parsers
    main_parser = argparse.ArgumentParser()    
    commands_subparsers = main_parser.add_subparsers(
        title='command',
        help='The action to perform.',
        dest='command',
    )

    # Parse arguments for scan command
    scan_parser = commands_subparsers.add_parser(
        'scan',
        help=(
            'Search OSINT sources for intelligence based on known assets '
            'belonging to the target.'
        ),
        parents=[parent_parser],
    )
    scan_parser.add_argument(
        '--google-dev-key',
        metavar='GOOGLE_DEV_KEY',
        type=str,
        help=(
            'Specifies the developer key to use to query Google Custom '
            'Search. Visit the Google APIs Console '
            '(http://code.google.com/apis/console) to get an API key. If not'
            'specified, the script will simply skip asset transforms that '
            'involve Google Search.'
        ),
        dest='google_dev_key',
    )
    scan_parser.add_argument(
        '--google-cse-id',
        metavar='GOOGLE_CSE_ID',
        type=str,
        help=(
            'Specifies the custom search engine to query. Visit the Google '
            'Custom Search Console (https://cse.google.com/cse/all) to create '
            'your own Google Custom Search Engine. If not specified, the '
            'script will simply skip asset transforms that involve Google '
            'Search.'
        ),
        dest='google_cse_id',
    )
    scan_parser.add_argument(
        '--google-limit',
        metavar='GOOGLE_LIMIT',
        type=int,
        help=(
            'The number of pages to limit Google Search to. This is to avoid '
            'exhausting your daily quota.'
        ),
        default=None,
    )
    scan_parser.add_argument(
        '--shodan-api-key',
        metavar='SHODAN_API_KEY',
        type=str,
        help=(
            'Specifies the API key to use to query Shodan. Log into your '
            'Shodan account (https://www.shodan.io/) and look at the top '
            'right corner of the page in order to view your API key. If not '
            'specified, the script will simply skip asset transforms that '
            'involve Shodan.'
        ),
        dest='shodan_api_key',
    )
    scan_parser.add_argument(
        '--shodan-limit',
        metavar='SHODAN_LIMIT',
        type=int,
        help=(
            'The number of pages to limit Shodan Search to. This is to avoid '
            'exhausting your daily quota.'
        ),
        default=None,
    )

    # Parse arguments for status command
    status_parser = commands_subparsers.add_parser(
        'status',
        help=(
            'Prints out the current status of the specified intelligence '
            'database.'
        ),
        parents=[parent_parser],
    )
    status_parser.add_argument(
        '-s', '--strong',
        help=(
            'Indicates if the status will be based on the strong ownership '
            'classification.'
        ),
        action='store_true',
        default=False,
    )
    
    # Parse arguments for classify command
    classify_parser = commands_subparsers.add_parser(
        'classify',
        help=(
            'Classifies an existing asset as either belonging or not '
            'belonging to the target. Adds a new asset with the specified '
            'classification if none is present.'
        ),
        parents=[parent_parser],
    )
    for asset_module in inquisitor.ASSET_MODULES:
        asset_module.main_classify_args(classify_parser)

    # Parse arguments for dump command
    dump_parser = commands_subparsers.add_parser(
        'dump',
        help='Dumps the contents of the database into a JSON file',
        parents=[parent_parser],
    )
    dump_parser.add_argument(
        '-j', '--json',
        metavar='FILE',
        type=str,
        help='The path to dump the JSON file to. Overwrites existing files.',
    )
    dump_parser.add_argument(
        '-a', '--all',
        help='Include rejected assets in dump.',
        action='store_true',
        default=False,
    )

    # Parse arguments for visualize command
    visualize_parser = commands_subparsers.add_parser(
        'visualize',
        help=(
            'Create a D3.js visualization based on the contents of the '
            'specified intelligence database.'
        ),
        parents=[parent_parser],
    )

    # Perform actual parsing of arguments
    args = main_parser.parse_args()

    # Determine chosen command and pass to appropriate subroutine
    if args.command == 'scan':
        scan(
            args.database, 
            google_dev_key=args.google_dev_key, 
            google_cse_id=args.google_cse_id, 
            google_limit=args.google_limit,
            shodan_api_key=args.shodan_api_key,
            shodan_limit=args.shodan_limit,
        )
        exit(0)
    if args.command == 'status':
        status(args.database, args.strong)
        exit(0)
    if args.command == 'classify':
        classify(args.database, args)
        exit(0)
    if args.command == 'dump':
        dump(args.database, args.json, args.all)
        exit(0)
    if args.command == 'visualize':
        visualize(args.database)
        exit(0)
