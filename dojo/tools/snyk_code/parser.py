import json

from cvss.cvss3 import CVSS3
from dojo.models import Finding

# The class name must be the Python module name without underscores plus Parser
class SnykCodeParser(object):

    def get_scan_types(self):
        return ["Snyk Code Scan"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type  # no custom label for now

    def get_description_for_scan_types(self, scan_type):
        return "Snyk Code output file (snyk code test --json > snyk.json) can be imported in JSON format."

    def get_findings(self, json_output, test):

        reportTree = self.parse_json(json_output)

        if type(reportTree) is list:
            temp = []
            for moduleTree in reportTree:
                temp += self.process_tree(moduleTree, test)
            return temp
        else:
            return self.process_tree(reportTree, test)

    def process_tree(self, tree, test):
        if tree:
            return [data for data in self.get_items(tree, test)]
        else:
            return []

    def parse_json(self, json_output):
        try:
            data = json_output.read()
            try:
                tree = json.loads(str(data, 'utf-8'))
            except:
                tree = json.loads(data)
        except:
            raise Exception("Invalid format")

        return tree

    def get_severity_for_score(self, score):
        # Following the CVSS Scoring per https://nvd.nist.gov/vuln-metrics/cvss
        if score <= 390:
            return 'Low'
        elif score >= 400 and score < 690:
            return 'Medium'
        elif score >= 700 and score < 890:
            return 'High'
        return 'Critical'

    def get_items(self, tree, test):

        items = {}

        if 'runs' not in tree:
            raise Exception("Unable to find 'runs' in tree")
        runs = tree['runs']
        if len(runs) == 0:
            raise Exception("Zero runs!")
        run = runs[0]

        if 'results' not in run:
            raise Exception("Unable to find results in tree")
        results = run['results']

        if 'tool' not in run:
            raise Exception("Unable to find 'tool' in 'run'")
        tool = run['tool']
        if 'driver' not in tool:
             raise Exception("Unable to find 'driver' in 'tool'")
        driver = tool['driver']
        if 'rules' not in driver:
            raise Exception("Unable to find rules in tree")
        rules = driver['rules']

        for node in results:
            rule = [a for a in rules if a['id'] == node['ruleId']]
            if len(rule) == 0:
                raise Exception("Unable to find rule that matches result")
            elif len(rule) > 1:
                raise Exception("Found more that one rule that matches result")
            rule = rule[0]
            title = rule['shortDescription']['text']
            details = rule['help']['markdown']
            message = node['message']['text']
            mitigation_divider = 'Best practices for prevention'
            mitigation = ''
            if mitigation_divider in details:
                mitigation = '# ' + mitigation_divider + '\n' + details.split(mitigation_divider)[1].strip()
            description = details.split(mitigation_divider)[0].strip() + '\n' + message
            score = node['properties']['priorityScore']
            cwes = rule['properties']['cwe']
            vuln_path = ''
            for location in node['locations']:
                vuln_path += location['physicalLocation']['artifactLocation']['uri']
            unique_key = node['ruleId'] + '-' + node['fingerprints']['0']        
            item = self.get_item(unique_key, title, description, mitigation, vuln_path, score, cwes, test)
            items[unique_key] = item
        return list(items.values())

    def get_item(self, unique_key, title, description, mitigation, vuln_path, score, cwes, test):

        try:
            score = int(score)
        except:
            score = 0
        severity = self.get_severity_for_score(score)
        severity_justification = "Issue severity of: **" + severity + "** from a base CVSS score of: **" + str(score) + "**"


        component_name = 'unknown'
        component_version = 'unknown'

        # create the finding object
        finding = Finding(
            title=title,
            test=test,
            severity=severity,
            severity_justification=severity_justification,
            description=description,
            mitigation=mitigation,
            component_name=component_name,
            component_version=component_version,
            false_p=False,
            duplicate=False,
            out_of_scope=False,
            impact=severity,
            static_finding=True,
            dynamic_finding=False,
            file_path=vuln_path,
            vuln_id_from_tool=unique_key
        )

        try:
            cwe = int(cwes[0].split('CWE-')[1])
        except:
            cwe = 913

        finding.cwe = cwe
        finding.references = 'N/A'

        return finding