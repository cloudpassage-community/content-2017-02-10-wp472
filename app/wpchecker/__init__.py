import cloudpassage
import sys


class Halo(object):
    def __init__(self, halo_key, halo_secret):
        self.halo_key = halo_key
        self.halo_secret = halo_secret
        self.halo_session = cloudpassage.HaloSession(self.halo_key,
                                                     self.halo_secret)
        self.server_module = cloudpassage.Server(self.halo_session)
        self.group_module = cloudpassage.ServerGroup(self.halo_session)
        self.fim_policy_module = cloudpassage.FimPolicy(self.halo_session)
        self.fim_baseline_module = cloudpassage.FimBaseline(self.halo_session)
        self.csm_policy_module = cloudpassage.ConfigurationPolicy(self.halo_session)
        self.scan_module = cloudpassage.Scan(self.halo_session)

    def list_all_servers(self):
        return self.server_module.list_all()

    def server_is_a_webserver(self, server_id):
        """If it is, we return a list of tuples:
        (server_id, package_name, package_version)
        """

        retval = []
        target_packages = ["nginx", "httpd", "apache", "wordpress"]
        server_software_inventory = self.scan_module.last_scan_results(server_id,
                                                                       "svm")
        for target_package in target_packages:
            if "scan" not in server_software_inventory:
                print("Server with ID %s has no SVM scan information!" % server_id)
            for finding in server_software_inventory["scan"]["findings"]:
                if target_package in finding["package_name"]:
                    hit = (server_id, target_package,
                           finding["package_version"])
                    retval.append(hit)
        return retval

    def install_fim_policy(self, fim_policy):
        """Creates if it doesn't exist already, returns ID"""
        try:
            pol_id = self.fim_policy_module.create(fim_policy)
            return pol_id
        except cloudpassage.exceptions.CloudPassageValidation:
            for policy in self.fim_policy_module.list_all():
                if policy["name"] == fim_policy["fim_policy"]["name"]:
                    return policy["id"]
        print("Unable to install FIM policy!!")
        sys.exit(2)
        return None

    def install_csm_policy(self, csm_policy):
        """Creates if it doesn't exist already, returns ID"""
        try:
            pol_id = self.csm_policy_module.create(csm_policy)
            return pol_id
        except cloudpassage.exceptions.CloudPassageValidation:
            for policy in self.csm_policy_module.list_all():
                if policy["name"] == csm_policy["policy"]["name"]:
                    return policy["id"]
        except cloudpassage.exceptions.CloudPassageAuthorization:
            print("Unauthorized!  Check Halo API key scope! (Must be R+W)")
        print("Unable to install CSM policy!!")
        return None

    def create_baseline(self, policy_id, server_id):
        baseline_id = self.fim_baseline_module.create(server_id, policy_id)
        return baseline_id

    def assign_csm_policy_to_group(self, policy_id, group_id):
        """Add CSM policy by ID to server group"""
        current_policies = self.group_module.describe(group_id)["policy_ids"]
        if policy_id not in current_policies:
            current_policies.append(policy_id)
            self.group_module.update(group_id, policy_ids=current_policies)
        return

    def trigger_csm_scan(self, server_id):
        """Trigger a CSM scan on a server, returns commnd ID"""
        return self.scan_module.initiate_scan(server_id, "csm")

    def get_server_csm_state(self, server_id):
        return self.scan_module.last_scan_results(server_id, "csm")

    def get_fim_baseline(self, policy_id, baseline_id):
        hh = cloudpassage.HttpHelper(self.halo_session)
        url = "/v1/fim_policies/%s/baselines/%s/details" % (policy_id, baseline_id)
        return hh.get(url)

    def get_command_meta(self, server_id, command_id):
        return self.server_module.command_details(server_id, command_id)

    def server_is_not_active(self, server_id):
        if self.server_module.describe(server_id)["state"] != "active":
            print("Server %s is not active anymore!" % server_id)
            return True
        else:
            return False
