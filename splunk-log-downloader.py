#!/usr/bin/env python3
import os
import sys
import json
import time
import requests
import xml.etree.ElementTree as ET
import logging
from urllib3.exceptions import InsecureRequestWarning
import argparse  # Added for command line arguments

# Suppress insecure request warnings (for self-signed certificates, etc.)
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

def load_config():
    """Automatically load configuration from config.json."""
    config_path = "config.json"
    if not os.path.exists(config_path):
        script_dir = os.path.dirname(os.path.abspath(__file__))
        config_path = os.path.join(script_dir, "config.json")
    if not os.path.exists(config_path):
        print("Error: config.json not found in current directory or script directory.")
        sys.exit(1)
    try:
        with open(config_path, "r") as f:
            config = json.load(f)
        return config
    except Exception as e:
        print("Failed to load config file:", e)
        sys.exit(1)

def save_sid(sid, search_query, earliest, latest):
    """Save the SID to a file for future reuse in debug mode."""
    sid_data = {
        'sid': sid,
        'search_query': search_query,
        'earliest': earliest,
        'latest': latest,
        'timestamp': time.time()
    }
    try:
        with open('.debug_sid.json', 'w') as f:
            json.dump(sid_data, f, indent=2)
        logging.info(f"SID saved to .debug_sid.json for future debugging: {sid}")
    except Exception as e:
        logging.warning(f"Failed to save SID for debugging: {str(e)}")

def load_saved_sid():
    """Load a previously saved SID for debugging purposes."""
    try:
        if os.path.exists('.debug_sid.json'):
            with open('.debug_sid.json', 'r') as f:
                sid_data = json.load(f)
            logging.info(f"Loaded saved SID for debugging: {sid_data['sid']}")
            return sid_data
        return None
    except Exception as e:
        logging.warning(f"Failed to load saved SID: {str(e)}")
        return None

def create_session(splunk_url, username, password):
    """Create a persistent session, log in to Splunk, and set the authorization header."""
    session = requests.Session()
    session.verify = False
    login_url = f"{splunk_url}/services/auth/login"
    data = {'username': username, 'password': password}
    logging.info("Logging in to Splunk...")
    response = session.post(login_url, data=data)
    logging.debug(f"Login response status: {response.status_code}")
    logging.debug("Login response: " + response.text)
    if response.status_code != 200:
        logging.error("Error during login: " + response.text)
        sys.exit(1)
    try:
        root = ET.fromstring(response.text)
        session_key = root.findtext('sessionKey')
        if not session_key:
            logging.error("Error: No sessionKey found in login response.")
            sys.exit(1)
        session.headers.update({"Authorization": f"Splunk {session_key}"})
        logging.debug("Obtained session token: " + session_key[:10] + "...")
        return session
    except Exception as e:
        logging.error("Failed to parse login response: " + str(e))
        sys.exit(1)

def create_search_job(splunk_url, session, search_query, params, job_app):
    """
    Creates a search job on Splunk and returns the job SID.
    The job is forced into the specified app.
    """
    url = f"{splunk_url}/services/search/jobs"
    data = {
        'search': search_query,
        'output_mode': 'json',
        'app': job_app
    }
    if params.get('earliest'):
        data['earliest_time'] = params['earliest']
    if params.get('latest'):
        data['latest_time'] = params['latest']
    
    logging.info("Creating search job...")
    response = session.post(url, data=data)
    logging.debug("Job creation response: " + response.text)
    if response.status_code not in [200, 201]:
        logging.error("Error creating job: " + response.text)
        sys.exit(1)
    try:
        job_info = response.json()
        sid = job_info['sid']
        logging.info(f"Job created with SID: {sid}")
        return sid
    except Exception as e:
        logging.error("Failed to parse job creation response: " + str(e))
        sys.exit(1)

def poll_job(splunk_url, session, sid, username, password):
    """
    Polls the Splunk job until it is complete.
    Logs the 'doneProgress' field (as a percentage) every 2 seconds.
    If a session expiration is detected, re-authenticate and retry.
    """
    url = f"{splunk_url}/services/search/jobs/{sid}"
    while True:
        response = session.get(url, params={'output_mode': 'json'})
        try:
            job_info = response.json()
        except Exception as e:
            logging.error("Failed to parse polling response: " + str(e))
            sys.exit(1)
        if "entry" not in job_info:
            messages = job_info.get("messages", [])
            for msg in messages:
                if "not properly authenticated" in msg.get("text", "").lower():
                    logging.warning("Session expired, re-authenticating...")
                    session = create_session(splunk_url, username, password)
                    time.sleep(2)
                    break
            else:
                logging.error("Unexpected response during polling: " + json.dumps(job_info))
                sys.exit(1)
            continue  # Retry with updated session.
        content = job_info["entry"][0]["content"]
        state = content.get("dispatchState")
        progress = content.get("doneProgress")
        if progress is not None:
            progress_percent = round(progress * 100, 2)
            logging.info(f"Job state: {state}. Progress: {progress_percent}% done.")
        else:
            logging.info(f"Job state: {state}.")
        if state is None:
            logging.error("Unexpected job info response: " + json.dumps(job_info))
            sys.exit(1)
        if state.upper() == 'DONE':
            logging.info("Job completed.")
            break
        else:
            logging.debug("Polling: waiting 2 seconds before next check.")
            time.sleep(2)
    return session  # Return the (possibly updated) session.

def get_results(splunk_url, session, sid, offset, count, output_mode):
    """Fetch a page of results from a completed job (for CSV/JSON modes)."""
    url = f"{splunk_url}/services/search/jobs/{sid}/results"
    params = {'output_mode': output_mode, 'offset': offset, 'count': count}
    logging.debug(f"Fetching results: offset {offset}, count {count}")
    response = session.get(url, params=params)
    if response.status_code != 200:
        logging.error("Error fetching results: " + response.text)
        sys.exit(1)
    return response.text

def get_raw_results(splunk_url, session, sid, search_query, earliest, latest):
    """
    Fetch raw results using the export endpoint with SID.
    If that fails, try alternative methods to retrieve raw logs.
    """
    # First, verify the job status and details for debugging
    job_url = f"{splunk_url}/services/search/jobs/{sid}"
    logging.debug(f"Verifying job status at: {job_url}")
    
    # Check if the query contains transforming commands that would prevent raw output
    transforming_commands = ['table', 'stats', 'chart', 'timechart', 'top', 'rare', 'contingency', 'join']
    has_transforming_commands = any(cmd in search_query.lower() for cmd in transforming_commands)
    
    if has_transforming_commands:
        logging.warning("Your search query contains transforming commands that may prevent raw log output.")
        logging.warning("Commands like 'table', 'stats', 'chart' transform the data and remove raw events.")
        logging.warning("Consider using CSV or JSON mode for this query, or remove transforming commands.")
    
    try:
        job_response = session.get(job_url, params={'output_mode': 'json'})
        logging.debug(f"Job status response code: {job_response.status_code}")
        
        if job_response.status_code == 200:
            job_info = job_response.json()
            job_content = job_info['entry'][0]['content']
            job_status = job_content.get('dispatchState', 'UNKNOWN')
            event_count = job_content.get('resultCount', 'UNKNOWN')
            scan_count = job_content.get('scanCount', 'UNKNOWN')
            event_available = job_content.get('resultPreviewCount', 'UNKNOWN')
            
            logging.debug(f"Job status: {job_status}")
            logging.debug(f"Total events: {event_count}")
            logging.debug(f"Scanned events: {scan_count}")
            logging.debug(f"Available for preview: {event_available}")
            
            # Additional job details that might impact raw export
            is_done = job_content.get('isDone', False)
            is_finalized = job_content.get('isFinalized', False)
            is_saved = job_content.get('isSaved', False)
            ttl = job_content.get('ttl', 'UNKNOWN')
            
            logging.debug(f"Job done: {is_done}, finalized: {is_finalized}, saved: {is_saved}, TTL: {ttl}")
    except Exception as e:
        logging.warning(f"Failed to retrieve job details: {str(e)}")
    
    # First attempt: Try using the export endpoint with SID (standard method)
    try:
        logging.info(f"Method 1: Using SID with export endpoint for raw log export. SID: {sid}")
        url = f"{splunk_url}/services/search/jobs/export"
        data = {
            'sid': sid, 
            'output_mode': 'raw'
        }
        
        logging.debug(f"Export URL: {url}")
        logging.debug(f"Export request data: {data}")
        
        response = session.post(url, data=data)
        logging.debug(f"Export response status code: {response.status_code}")
        
        if response.status_code == 200 and response.text.strip() and "Empty search" not in response.text:
            logging.info("Method 1 successful: Retrieved raw logs using export endpoint with SID")
            return response.text
        else:
            logging.warning(f"Method 1 failed: Export returned status {response.status_code}")
            logging.debug(f"Response preview: {response.text[:200]}")
    except Exception as e:
        logging.warning(f"Method 1 exception: {str(e)}")
    
    # Second attempt: Try using the results endpoint with output_mode=raw
    try:
        logging.info("Method 2: Using results endpoint with output_mode=raw")
        url = f"{splunk_url}/services/search/jobs/{sid}/results"
        params = {
            'output_mode': 'raw',
            'count': 0  # Get all results
        }
        
        logging.debug(f"Results URL: {url}")
        logging.debug(f"Results request params: {params}")
        
        response = session.get(url, params=params)
        logging.debug(f"Results response status code: {response.status_code}")
        
        if response.status_code == 200 and response.text.strip() and "Empty search" not in response.text:
            logging.info("Method 2 successful: Retrieved raw logs using results endpoint")
            return response.text
        else:
            logging.warning(f"Method 2 failed: Results returned status {response.status_code}")
            logging.debug(f"Response preview: {response.text[:200]}")
    except Exception as e:
        logging.warning(f"Method 2 exception: {str(e)}")
    
    # Third attempt: Try using the export endpoint with search query and exec_mode=blocking
    try:
        logging.info("Method 3: Using export endpoint with original search query")
        url = f"{splunk_url}/services/search/jobs/export"
        
        # Create a modified search query by stripping transforming commands if any exist
        modified_search = search_query
        if has_transforming_commands:
            # Simple approach: extract everything before the first pipe
            if '|' in search_query:
                modified_search = search_query.split('|')[0].strip()
                logging.info(f"Trying with modified search query (transforming commands removed): {modified_search}")
        
        data = {
            'search': modified_search,
            'output_mode': 'raw',
            'exec_mode': 'blocking'  # Wait for results before returning
        }
        if earliest:
            data['earliest_time'] = earliest
        if latest:
            data['latest_time'] = latest
        
        logging.debug(f"Export URL: {url}")
        logging.debug(f"Export request data: {data}")
        
        response = session.post(url, data=data)
        logging.debug(f"Export response status code: {response.status_code}")
        
        # Check if we have actual content despite a 200 status
        response_has_content = bool(response.text.strip())
        logging.debug(f"Response has content: {response_has_content}")
        
        if response.status_code == 200 and response_has_content and "Empty search" not in response.text:
            logging.info("Method 3 successful: Retrieved raw logs using export with modified search query")
            return response.text
        else:
            logging.warning(f"Method 3 failed: Export returned status {response.status_code}, has content: {response_has_content}")
            if response.text:
                logging.debug(f"Response preview: {response.text[:200]}")
            else:
                logging.debug("Response was empty (no content)")
    except Exception as e:
        logging.warning(f"Method 3 exception: {str(e)}")
    
    # If we've reached here, all methods failed
    logging.error("All methods to retrieve raw logs failed")
    if has_transforming_commands:
        logging.error("MAIN ISSUE: Your search query contains transforming commands (table, rex, etc.)")
        logging.error("Raw log mode cannot be used with transforming commands. Options:")
        logging.error("1. Use 'output_mode': 'csv' or 'json' instead")
        logging.error("2. Remove transforming commands from your query")
        logging.error("   Original: " + search_query)
        if '|' in search_query:
            logging.error("   Try: " + search_query.split('|')[0].strip())
    else:
        logging.error("This may be because:")
        logging.error("1. The Splunk instance might restrict raw log exports")
        logging.error("2. The search may need to be a 'search' command at the beginning")
        logging.error("3. The specific indexes or sourcetypes might not support raw output")
    sys.exit(1)

def get_total_count(splunk_url, session, sid):
    """Retrieve the total number of results for the search job."""
    url = f"{splunk_url}/services/search/jobs/{sid}"
    response = session.get(url, params={'output_mode': 'json'})
    if response.status_code != 200:
        logging.error("Error retrieving job info: " + response.text)
        sys.exit(1)
    job_info = response.json()
    total = int(job_info['entry'][0]['content'].get('resultCount', 0))
    logging.info(f"Total results to fetch: {total}")
    return total

def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Splunk log downloader script')
    parser.add_argument('--force-new-job', action='store_true', 
                      help='Force creation of a new search job even if a saved SID exists')
    args = parser.parse_args()

    # Load configuration
    config = load_config()
    debug_flag = config.get("debug", False)
    log_level = logging.DEBUG if debug_flag else logging.INFO
    logging.basicConfig(level=log_level, format='%(asctime)s %(levelname)s: %(message)s')

    splunk_url   = config.get('splunk_url')
    username     = config.get('username')
    password     = config.get('password')
    search_query = config.get('search_query')
    user_output_mode = config.get('output_mode', 'csv').lower()  # Supported: csv, json, log
    page_size    = config.get('page_size', 10000)
    earliest     = config.get('earliest')
    latest       = config.get('latest')
    output_file  = config.get('output_file', 'output.csv')
    job_app      = config.get('job_app', 'search')

    if not splunk_url or not search_query:
        logging.error("Please ensure that 'splunk_url' and 'search_query' are set in config.json.")
        sys.exit(1)
    if not (username and password):
        logging.error("Username and password must be provided in config.json.")
        sys.exit(1)

    # Check for incompatible use of raw log mode with transforming commands
    if user_output_mode == "log":
        transforming_commands = ['table', 'stats', 'chart', 'timechart', 'top', 'rare', 
                               'contingency', 'join', 'rex', 'eval', 'fields', 'dedup', 'rename']
        has_transforming_commands = any(cmd in search_query.lower() for cmd in transforming_commands)
        
        if has_transforming_commands:
            logging.warning("=" * 80)
            logging.warning("⚠️  WARNING: You are using 'log' mode with transforming commands in your query.")
            logging.warning("Raw log mode is incompatible with commands like 'table', 'stats', 'chart', 'rex', etc.")
            logging.warning("These commands transform the data making raw logs unavailable.")
            logging.warning("")
            logging.warning("RECOMMENDATIONS:")
            logging.warning("1. Use 'csv' or 'json' mode instead (change 'output_mode' in config.json)")
            logging.warning("2. Or remove transforming commands from your query (everything after the first pipe '|')")
            logging.warning("")
            logging.warning("Modified query without transforming commands would be:")
            base_query = search_query.split('|')[0].strip() if '|' in search_query else search_query
            logging.warning(f"  {base_query}")
            logging.warning("=" * 80)
            
            # Prompt user to continue or abort
            try:
                response = input("Continue anyway with 'log' mode? This likely won't work. (y/n): ").strip().lower()
                if response != 'y':
                    logging.info("Aborting script run. Please modify your configuration and try again.")
                    sys.exit(0)
            except KeyboardInterrupt:
                logging.info("\nAborted by user.")
                sys.exit(0)

    # Warn if using "sort" in the query (applies to all modes)
    if "sort" in search_query.lower():
        logging.warning("Warning: Using 'sort' in your query caps results to 10,000 events.")

    # Create a persistent session.
    session = create_session(splunk_url, username, password)
    
    # Check for saved SID in debug mode
    saved_sid_data = None
    if debug_flag and not args.force_new_job:
        saved_sid_data = load_saved_sid()
    
    # Use saved SID or create new job
    if saved_sid_data and not args.force_new_job:
        # Verify if the saved SID matches current search parameters
        if (saved_sid_data['search_query'] == search_query and
            saved_sid_data['earliest'] == earliest and
            saved_sid_data['latest'] == latest):
            sid = saved_sid_data['sid']
            logging.info(f"Reusing saved SID: {sid}")
            # Log a URL to view the job details in JSON
            rest_job_url = f"{splunk_url}/services/search/jobs/{sid}?output_mode=json"
            logging.info(f"View this job (JSON output) here: {rest_job_url}")
        else:
            logging.info("Search parameters changed, creating new job instead of using saved SID")
            params = {'earliest': earliest, 'latest': latest}
            sid = create_search_job(splunk_url, session, search_query, params, job_app)
            # Poll until the job is complete
            session = poll_job(splunk_url, session, sid, username, password)
            # Save SID for future debugging if in debug mode
            if debug_flag:
                save_sid(sid, search_query, earliest, latest)
    else:
        # Create the search job (forcing it into the specified app)
        params = {'earliest': earliest, 'latest': latest}
        sid = create_search_job(splunk_url, session, search_query, params, job_app)
        
        # Log a URL (REST API endpoint) to view the job details in JSON
        rest_job_url = f"{splunk_url}/services/search/jobs/{sid}?output_mode=json"
        logging.info(f"View this job (JSON output) here: {rest_job_url}")

        # Poll until the job is complete
        session = poll_job(splunk_url, session, sid, username, password)
        
        # Save SID for future debugging if in debug mode
        if debug_flag:
            save_sid(sid, search_query, earliest, latest)
    
    total_results = get_total_count(splunk_url, session, sid)

    if user_output_mode in ["csv", "json"]:
        offset = 0
        logging.info(f"Starting to fetch results with output mode: {user_output_mode}")
        if user_output_mode == "csv":
            with open(output_file, 'w') as f_out:
                while offset < total_results:
                    logging.info(f"Fetching CSV results from offset {offset}...")
                    page_text = get_results(splunk_url, session, sid, offset, page_size, "csv")
                    f_out.write(page_text)
                    offset += page_size
                    time.sleep(1)
            logging.info(f"All CSV results written to {output_file}")
        else:  # json mode
            all_results = []
            while offset < total_results:
                logging.info(f"Fetching JSON results from offset {offset}...")
                page_text = get_results(splunk_url, session, sid, offset, page_size, "json")
                try:
                    data = json.loads(page_text)
                    results = data.get("results", [])
                    logging.debug(f"Fetched {len(results)} events at offset {offset}")
                    all_results.extend(results)
                except Exception as e:
                    logging.error("Error parsing JSON results: " + str(e))
                    sys.exit(1)
                offset += page_size
                time.sleep(1)
            with open(output_file, 'w') as f_out:
                json.dump(all_results, f_out, indent=2)
            logging.info(f"All JSON results written to {output_file}")

    elif user_output_mode == "log":
        logging.info("Fetching raw log results using export endpoint...")
        raw_text = get_raw_results(splunk_url, session, sid, search_query, earliest, latest)
        num_events = len(raw_text.strip().splitlines())
        logging.info(f"Downloaded {num_events} raw log events.")
        with open(output_file, 'w') as f_out:
            f_out.write(raw_text)
        logging.info(f"All raw log results written to {output_file}")

    else:
        logging.error("Unsupported output_mode specified in config.json. Use 'csv', 'json', or 'log'.")
        sys.exit(1)

if __name__ == '__main__':
    main()
