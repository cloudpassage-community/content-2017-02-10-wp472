import json
import os
import pprint
import re
import time
from wpchecker import Halo, Utility

here_dir = here_dir = os.path.dirname(os.path.abspath(__file__))
hashes_file = os.path.join(here_dir, "hashes.txt")
paths_file = os.path.join(here_dir, "paths.txt")

csm_policy = json.load(open(os.path.join(here_dir, "wpchecker/templates/Mitigation_WordPress_47.csm.policy.json"), 'r'))["policy"]


halo_api_key = os.getenv("HALO_API_KEY")
halo_api_secret_key = os.getenv("HALO_API_SECRET_KEY")

halo_api = Halo(halo_api_key, halo_api_secret_key)


def main():
    print("Getting a list of all servers...")
    server_reference = halo_api.list_all_servers()

    print("Installing CSM policy")
    csm_policy_id = halo_api.install_csm_policy({"policy": csm_policy})

    targets = []
    target_group_ids = []
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
        grp_id = Utility.get_group_for_server_id(server_reference, target[0])
        if grp_id not in target_group_ids:
            target_group_ids.append(grp_id)
    for target_group_id in target_group_ids:
        print("    Attaching CSM policy to group with ID %s" % target_group_id)
        halo_api.assign_csm_policy_to_group(csm_policy_id, target_group_id)
        time.sleep(3)
    for target in targets:
        if target[0] not in csm_scan_servers:
            csm_scan_servers.append(target[0])
            print("    Triggering CSM scan against server with ID %s" % target[0])
            running_csm_ids.append((target[0], halo_api.trigger_csm_scan(target[0])))

    print("Now installing FIM policies and triggering baselines...")
    for target in targets:
        if target[0] not in fim_scan_servers:
            fim_scan_servers.append(target[0])
            fim_policy_id = halo_api.install_fim_policy(Utility.generate_fim_policy(Utility.fim_webroot(target)))
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
            if "targets" not in baseline:
                continue
            for target in baseline["targets"]:
                for obj in target["objects"]:
                    if Utility.fim_path_suspect(obj["filename"], paths_file):
                        baseline_alert_messages += str("    Potential issue on server %s (path: %s)\n" % (server, obj["filename"]))
                    if Utility.fim_hash_suspect(obj["contents"], hashes_file):
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
