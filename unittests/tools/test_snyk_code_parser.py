from ..dojo_test_case import DojoTestCase
from dojo.models import Test
from dojo.tools.snyk.parser import SnykParser


class TestSnykCodeParser(DojoTestCase):

    def test_snykParser_single_has_no_finding(self):
        testfile = open("unittests/scans/snyk_code/single_project_no_vulns.json")
        parser = SnykParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(0, len(findings))
        testfile.close()

    def test_snykParser_single_has_one_finding(self):
        testfile = open("unittests/scans/snyk_code/single_project_one_vuln.json")
        parser = SnykParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(1, len(findings))
        testfile.close()

    def test_snykParser_single_has_many_findings(self):
        testfile = open("unittests/scans/snyk_code/single_project_many_vulns.json")
        parser = SnykParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(34, len(findings))