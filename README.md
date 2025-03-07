# Splunk Log Downloader

A Python utility for efficiently downloading logs and search results from Splunk.

## Features

- Download Splunk search results in multiple formats (CSV, JSON, raw logs)
- Debug mode with detailed logging
- Session persistence
- SID caching for faster debugging iterations
- Support for large result sets with automatic pagination

## Prerequisites

- Python 3.6 or higher
- `requests` library (install with `pip install requests`)
- Access to a Splunk instance

## Installation

1. Clone or download this repository
2. Ensure Python 3.6+ is installed on your system
3. Install required dependencies:

```bash
pip install requests
```

## Configuration

Create a `config.json` file in the same directory as the script with the following structure:

```json
{
  "splunk_url": "https://your-splunk-server.example.com",
  "username": "your_username",
  "password": "your_password",
  "search_query": "your search query here | table field1 field2",
  "output_mode": "csv",
  "page_size": 10000,
  "earliest": "2023-01-01T00:00:00",
  "latest": "2023-01-31T23:59:59",
  "output_file": "output.csv",
  "job_app": "search",
  "debug": false
}
```

### Configuration Options

| Option | Description | Default |
|--------|-------------|---------|
| `splunk_url` | URL of your Splunk instance (required) | - |
| `username` | Splunk username (required) | - |
| `password` | Splunk password (required) | - |
| `search_query` | Splunk search query (required) | - |
| `output_mode` | Output format: `csv`, `json`, or `log` | `csv` |
| `page_size` | Number of results to fetch per request | 10000 |
| `earliest` | Start time for search (Splunk time format) | - |
| `latest` | End time for search (Splunk time format) | - |
| `output_file` | Filename for output | Based on output_mode |
| `job_app` | Splunk app context for the search | `search` |
| `debug` | Enable debug logging and SID caching | `false` |

## Usage

Run the script from the command line:

```bash
python splunk-downloader.py
```

### Command-line Arguments

| Argument | Description |
|----------|-------------|
| `--force-new-job` | Force creation of a new search job even if a saved SID exists |

## Output Modes

### CSV Mode (`output_mode: "csv"`)

Downloads results in CSV format. Useful for:
- Data analysis in spreadsheet applications
- Importing into databases
- Large result sets

### JSON Mode (`output_mode: "json"`)

Downloads results in JSON format. Useful for:
- Programmatic processing
- Complex data structures
- Preserving types and hierarchies

### Log Mode (`output_mode: "log"`)

Downloads raw log events. Useful for:
- Getting the complete, unprocessed log entries
- Maximum fidelity to original data
- Forensic analysis

⚠️ **IMPORTANT WARNING**: Raw log mode is incompatible with transforming commands in your search query. Commands like `table`, `stats`, `chart`, `rex`, `timechart`, etc. transform the data and make raw logs unavailable. If your query contains any of these commands:

1. Use `csv` or `json` mode instead (recommended)
2. Remove all transforming commands (everything after the first pipe `|`) from your query

The script attempts three different methods to retrieve raw logs:
1. Using the export endpoint with the SID
2. Using the results endpoint with output_mode=raw
3. Using the export endpoint with the original search query

This multi-method approach increases the chances of successfully retrieving raw logs, as different Splunk configurations and search types may require different approaches.

## Debugging Features

### Debug Mode

Enable debug mode in the config:

```json
{
  "debug": true
}
```

This will:
- Show detailed logging
- Save search job SIDs for reuse
- Allow faster iteration when debugging

### SID Caching

When debug mode is enabled, the script caches the search job SID to a `.debug_sid.json` file. This allows you to rerun the script multiple times without waiting for the search job to be recreated and completed each time.

To force a new job creation:

```bash
python splunk-downloader.py --force-new-job
```

## Troubleshooting

### Common Issues

1. **"All methods to retrieve raw logs failed"**
   - **Primary cause**: Using transforming commands with raw log mode
   - Splunk cannot provide raw logs when using commands like `table`, `stats`, `rex`, etc.
   - These commands transform the data from its original format
   
   **Solutions:**
   - Use `csv` or `json` output mode instead (recommended)
   - Remove all transforming commands from your query (everything after the first pipe `|`)
   - Example: Change `search index=main | stats count by host` to just `search index=main`

2. **"Raw export using SID returned empty"**
   - Check if your search actually returns results
   - Verify the search job is still valid (jobs expire after their TTL)
   - Ensure your query doesn't have issues with raw export

3. **"Error during login"**
   - Check your username and password
   - Verify the Splunk URL is correct
   - Confirm network connectivity to Splunk server

4. **"Error creating job"**
   - Verify your search query syntax
   - Check if you have permissions to run searches
   - Make sure the specified app exists

5. **Results limited to 10,000 events**
   - Remove `sort` commands from your search query
   - Use a more specific search to reduce the result set

## License

This script is provided as-is with no warranty. Use at your own risk. 