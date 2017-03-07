import argparse
import inquisitor
import json
import tabulate

def database(path):
    return inquisitor.IntelligenceRepository(path)

def scan(repository):
    # TODO: implement
    # TODO: don't transform non owned assets
    pass

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
        targets = (
            (accepted, True),
            (unmarked, None),
            (rejected, False),
        )
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
        results = repository.get_assets(asset_types=[asset_type])
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

def visualize(repository, visualize_path):
    # TODO: implement
    pass

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
        dest='GOOGLE_DEV_KEY',
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
        dest='GOOGLE_CSE_KEY',
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
        dest='SHODAN_API_KEY',
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
    visualize_parser.add_argument(
        'visualize_path',
        metavar='HTML_FILE',
        type=str,
        help=(
            'The path to dump the visualization file to. Overwrites existing '
            'files.'
        ),
    )

    # Perform actual parsing of arguments
    args = main_parser.parse_args()

    # Determine chosen command and pass to appropriate subroutine
    if args.command == 'scan':
        scan(args.database)
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
        visualize(args.database, args.visualize_path)
        exit(0)
