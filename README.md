# Wordpress 4.7.2 authentication bypass vulnerability detection


Running this script will do these things:

1. Enumerate all servers on your account
1. Examine SVA inventory to locate all Wordpress installs
  * Retain a list of all Wordpress installs (and versions) for final report
1. Examine SVA inventory, looking for installations of Nginx and Apache
  * If any are found, we inject FIM policies into the groups and force baselines
    * Baselines will be examined for:
      * Hashes of known vulnerable php files
      * Strings in file paths which may indicate that you're running a vulnerable WP API
    * Record all suspect hosts, file paths, and hashes for final report
1. Install LIDS policies to all groups containing servers which appear to have Wordpress installed
  * LIDS policies will need you to specify the path to W3C logs from your Wordpress application
1. Print final report
