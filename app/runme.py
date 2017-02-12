import json
import os
import pprint
import re
import time
from wpchecker import Halo

here_dir = here_dir = os.path.dirname(os.path.abspath(__file__))
hashes_file = os.path.join(here_dir, "hashes.txt")
paths_file = os.path.join(here_dir, "paths.txt")

csm_policy = json.load(open(os.path.join(here_dir, "wpchecker/templates/Mitigation_WordPress_47.csm.policy.json"), 'r'))["policy"]


halo_api_key = os.getenv("HALO_API_KEY")
halo_api_secret_key = os.getenv("HALO_API_SECRET_KEY")

halo_api = Halo(halo_api_key, halo_api_secret_key)


def get_lines_from_file(file_path):
    with open(file_path) as file_obj:
        retval = (file_obj.read().split('\n'))
    return retval


def fim_webroot(info_tup):
    """info_tup = (server_id, package_name, package_version)"""
    webroot_reference = {"wordpress": "/usr/share/wordpress",
                         "nginx": "/usr/share/nginx/html",
                         "httpd": "/var/www/html",
                         "apache2": "/var/www/html",
                         "apache": "/var/www/html"}
    return webroot_reference[info_tup[1]]


def generate_fim_policy(webroot):
    name = "Wordpress hunter for %s" % webroot
    return {
          "fim_policy": {
            "name": name,
            "description": "Collecting hashes, looking for Wordpress installs",
            "platform": "linux",
            "rules": [{
              "target":  webroot,
              "description": "All webroot files",
              "recurse": True,
              "patterns": []}, {
              "target": str("%s/wordpress/wp-includes/rest-api/endpoints/class-wp-rest-posts-controller.php" % webroot),
              "description": "Specifically looking for endpoints",
              "recurse": True,
              "patterns": []
            }]
          }
        }


def fim_path_suspect(path):
    for matcher in get_lines_from_file(paths_file):
        if matcher == "":
            continue
        m = re.compile(matcher)
        if m.match(path):
            return True
    return False


def fim_hash_suspect(fim_hash):
    if fim_hash in get_lines_from_file(hashes_file):
        return True
    return False


def get_group_for_server_id(reference, server_id):
    for server in reference:
        if server["id"] == server_id:
            return server["group_id"]
    return False


def main():
    print("Getting a list of all servers...")
    server_reference = halo_api.list_all_servers()

    print("Installing CSM policy")
    csm_policy_id = halo_api.install_csm_policy({"policy": csm_policy})

    targets = []
    target_group_ids = []
    # fim_policy_ids = []
    running_baseline_ids = []
    running_csm_ids = []
    csm_scan_servers = []
    fim_scan_servers = []
    baseline_alert_messages = ""
    csm_alert_messages = ""
    wp_package_alert_message = ""

    print("Checking for installed web server and Wordpress packages...")
    for server in server_reference:
        targets.extend(halo_api.server_is_a_webserver(server["id"]))
    for target in targets:
        if target[1] == "wordpress":
            wp_package_alert_message += str("%s is running %s version %s\n" % target)

    print("Attaching CSM policy to every group containing a web server...")
    for target in targets:
        grp_id = get_group_for_server_id(server_reference, target[0])
        if grp_id not in target_group_ids:
            target_group_ids.append(grp_id)
    for target_group_id in target_group_ids:
        print("    Attaching CSM policy to group with ID %s" % target_group_id)
        halo_api.assign_csm_policy_to_group(csm_policy_id, target_group_id)
    for target in targets:
        if target[0] not in csm_scan_servers:
            csm_scan_servers.append(target[0])
            print("    Triggering CSM scan against server with ID %s" % target[0])
            running_csm_ids.append((target[0], halo_api.trigger_csm_scan(target[0])))

    print("Now installing FIM policies and triggering baselines...")
    for target in targets:
        if target[0] not in fim_scan_servers:
            fim_scan_servers.append(target[0])
            fim_policy_id = halo_api.install_fim_policy(generate_fim_policy(fim_webroot(target)))
            print("    Triggering baseline for server with ID %s" % target[0])
            running_baseline_ids.append((target[0], halo_api.create_baseline(target[0], fim_policy_id), fim_policy_id))

    print("Checking CSM scan results:")
    while running_csm_ids:
        for (server, scan) in running_csm_ids:
            time.sleep(10)  # Don't beat on the API
            meta = halo_api.get_command_meta(server, scan["id"])
            if meta["status"] == "completed":
                running_csm_ids.remove((server, scan))
                print("    Completed: Server with ID %s" % server)
                if halo_api.get_server_csm_state(server)["scan"]["critical_findings_count"] > 0:
                    csm_alert_messages += str("    Critical CSM issues exist on server with ID %s\n" % server)
            elif meta["status"] == "failed":
                running_csm_ids.remove((server, scan))
                print("  FAILED:")
                print(meta)
            elif halo_api.server_is_not_active(server):
                running_csm_ids.remove((server, scan))
            else:
                continue

    print("Analyzing FIM baselines...")
    while running_baseline_ids:
        for (server, baseline_id, policy_id) in running_baseline_ids:
            time.sleep(10)  # Don't beat on the API
            baseline = halo_api.get_fim_baseline(policy_id, baseline_id)["baseline"]["details"]
            running_baseline_ids.remove((server, baseline_id, policy_id))
            pp = pprint.PrettyPrinter(indent=4)

            if "targets" not in baseline:
                continue
            for target in baseline["targets"]:
                for obj in target["objects"]:
                    # pp.pprint(obj)
                    if fim_path_suspect(obj["filename"]):
                        baseline_alert_messages += str("    Potential issue on server %s (path: %s)\n" % (server, obj["filename"]))
                    if fim_hash_suspect(obj["contents"]):
                        baseline_alert_messages += str("    Bad hash match: Server %s file %s\n" % (server, obj["filename"]))

    # Print results
    print("Baseline alerts:")
    print(baseline_alert_messages)
    print("Packages detected:")
    print(wp_package_alert_message)
    print("CSM alert messages:")
    print(csm_alert_messages)


if __name__ == "__main__":
    main()
