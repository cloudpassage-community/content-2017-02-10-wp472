import re


class Utility(object):
    @classmethod
    def get_lines_from_file(cls, file_path):
        with open(file_path) as file_obj:
            retval = (file_obj.read().split('\n'))
        return retval

    @classmethod
    def fim_path_suspect(cls, path, paths_file):
        for matcher in Utility.get_lines_from_file(paths_file):
            if matcher == "":
                continue
            m = re.compile(matcher)
            if m.match(path):
                return True
        return False

    @classmethod
    def fim_hash_suspect(cls, fim_hash, hashes_file):
        if fim_hash in Utility.get_lines_from_file(hashes_file):
            return True
        return False

    @classmethod
    def get_group_for_server_id(cls, reference, server_id):
        for server in reference:
            if server["id"] == server_id:
                return server["group_id"]
        print("Unable to get group for server ID %s" % server_id)

    @classmethod
    def fim_webroot(cls, info_tup):
        """info_tup = (server_id, package_name, package_version)"""
        webroot_reference = {"wordpress": "/usr/share/wordpress",
                             "nginx": "/usr/share/nginx/html",
                             "httpd": "/var/www/html",
                             "apache2": "/var/www/html",
                             "apache": "/var/www/html"}
        return webroot_reference[info_tup[1]]

    @classmethod
    def generate_fim_policy(cls, webroot):
        name = "Wordpress hunter for %s" % webroot
        return {
              "fim_policy": {
                "name": name,
                "description": "Looking for Wordpress installs",
                "platform": "linux",
                "rules": [{
                  "target":  webroot,
                  "description": "All webroot files",
                  "recurse": True,
                  "patterns": []}, {
                  "target": str("%s/wordpress/wp-includes/rest-api/endpoints/class-wp-rest-posts-controller.php" % webroot),  # NOQA
                  "description": "Specifically looking for endpoints",
                  "recurse": True,
                  "patterns": []
                }]
              }
            }
