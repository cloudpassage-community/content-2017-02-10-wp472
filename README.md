# Wordpress 4.7.2 authentication bypass vulnerability detection

## What it does:

This tool interrogates your CloudPassage Halo-protected workloads to look for
vulnerable installs of Wordpress (specifically, 4.7 and 4.7.1).

## Requirements:

* `cloudpassage` Python packge
* docker-compose (only if you want to use the testing environment)

## How it works:

This tool will:

1. Enumerate all servers in your account
1. Examine SVA inventory to locate all Wordpress installs
  * Retain a list of all Wordpress installs (and versions) for final report
1. Install targeted CSM policy and configure for every group with a web server with or without the Wordpress package installed
1. Examine SVA inventory, looking for installations of Nginx and Apache
  * If any are found, we inject FIM policies into the groups and force baselines
    * Baselines will be examined for:
      * Hashes of known vulnerable php files
      * Strings in file paths which may indicate that you're running the WP restful API
    * Record all suspect hosts, file paths, and hashes for final report
1. Print the final report


## Usage:

Make sure you have these environment variables set before you run the tool:

* `HALO_API_KEY` This must be an administrative key.  Read-only (audit) keys cannot initiate scans.
* `HALO_API_SECRET_KEY` This is the secret corresponding to the `HALO_API_KEY`, above

## Testing
If you're wanting to test without installing Wordpress into your environment, here's
a quick way to do it:

1. Set the environment variable `AGENT_KEY` to your CloudPassage Halo agent installation key.
1. From the root directory of the repository, run `docker-compose up -d --build`
    * This will build and run four test containers with Halo (not an officially-supported configuration, but it works great for testing.)
    * The containers will register to your account and appear in the group associated with the agent key.
1. `cd app/ && python ./runme.py`
    * This will run the tool against your account.
