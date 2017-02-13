import imp
import json
import os
import sys

module_name = 'wpchecker'
here_dir = os.path.dirname(os.path.abspath(__file__))
module_path = os.path.join(here_dir, '../../')
fixture_path = os.path.join(here_dir, '../fixtures/')
sys.path.append(module_path)
fp, pathname, description = imp.find_module(module_name)
wpchecker = imp.load_module(module_name, fp, pathname, description)

util = wpchecker.Utility


class TestUnitUtility:
    def test_utility_get_lines_from_file(self):
        path_to_file = os.path.join(fixture_path, "lines_from_file.txt")
        assert len(util.get_lines_from_file(path_to_file)) == 3

    def test_utility_fim_path_suspect(self):
        path_to_file = os.path.join(fixture_path, "fim_paths.txt")
        path_1 = "/dev/null"
        path_2 = "/dev/nullify"
        path_3 = "/var/www/html/allthethingsyoueverwantedtohack"
        assert util.fim_path_suspect(path_1, path_to_file)
        assert not util.fim_path_suspect(path_2, path_to_file)
        assert util.fim_path_suspect(path_3, path_to_file)

    def test_utility_fim_hash_suspect(self):
        path_to_file = os.path.join(fixture_path, "fim_hashes.txt")
        hash_1 = "willnotmatch"
        hash_2 = "abc123"
        assert not util.fim_hash_suspect(hash_1, path_to_file)
        assert util.fim_hash_suspect(hash_2, path_to_file)

    def test_get_group_for_server_id(self):
        struct = [{"id": "asdfasdfasdfasfd",
                   "group_id": "helloworld"},
                  {"id": "neverevencalledmebymyname",
                   "group_id": "steve_goodman"}]
        test_id = "neverevencalledmebymyname"
        assert util.get_group_for_server_id(struct, test_id) == "steve_goodman"

    def test_unit_fim_webroot(self):
        test_tup = ("000", "wordpress", "111")
        assert util.fim_webroot(test_tup) == "/usr/share/wordpress"

    def test_unit_generate_fim_policy(self):
        webroot = "/dev/null"
        policy = util.generate_fim_policy(webroot)
        assert policy["fim_policy"]["rules"][0]["target"] == webroot
