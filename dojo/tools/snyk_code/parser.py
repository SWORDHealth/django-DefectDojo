import json

from cvss.cvss3 import CVSS3
from dojo.models import Finding

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
            unique_key = node['ruleId'] + '-' + node['fingerprints']['0']
            title = rule['shortDescription']['text']

            # parses vulnerability details
            message = node['message']['text'] or 'N/A'
            description = '\n## Vulnerability Details\n' + message

            # parses general info about vulnerability type
            mitigation_dividers = ['Best practices for prevention', 'How to prevent']
            details = rule['help']['markdown']
            description += '\n## General Info\n'
            details = details.replace('## Details', '')
            general_info = ''
            for divider in mitigation_dividers:
                if divider in details:
                    general_info = details.split(divider)[0].strip()
            description += general_info

            # parses mitigation
            mitigation = ''
            for divider in mitigation_dividers:
                if divider in details:
                    mitigation = '# ' + divider + '\n' + details.split(divider)[1].strip() + '\n'
        
            if rule['properties'] is not None and rule['properties']['exampleCommitFixes'] is not None:
                mitigation += '\n## Example Commit Fixes'
                for example in rule['properties']['exampleCommitFixes']:
                    mitigation += '\n- [' + example['commitURL'] + '](' + example['commitURL'] + ')'

            # parses vulnerable filepath
            vuln_path = ''
            for location in node['locations']:
                vuln_path += location['physicalLocation']['artifactLocation']['uri']
                vuln_path += '#L' + str(location['physicalLocation']['region']['startLine'])
                vuln_path += '-L' + str(location['physicalLocation']['region']['endLine'])

            # parses severity score
            score = node['properties']['priorityScore']

            # parses cwe

            cwe: int = None
            try:
                cwe = int(rule['properties']['cwe'][0].split('CWE-')[1])
            except:
                pass

            item = self.get_item(
                unique_key=unique_key,
                title=(title + ' on ' + vuln_path) if vuln_path != '' else title,
                description=description,
                mitigation=mitigation,
                vuln_path=vuln_path,
                score=score,
                cwe=cwe,
                test=test
            )
            items[unique_key] = item
        return list(items.values())

    def get_item(
        self,
        unique_key: str,
        title: str,
        description: str,
        mitigation: str,
        vuln_path: str,
        score,
        cwe: int,
        test
    ):

        score = 0
        try:
            score = int(score)
        except Exception as exception:
            raise Exception('Unable to parse score for finding!') from exception

        severity = self._get_severity_for_score(score)
        severity_justification = "Issue severity of: **" + severity + "** from a base priority score of: **" + str(score) + "**"

        # create the finding object
        finding = Finding(
            title=title,
            cwe=cwe,
            test=test,
            severity=severity,
            severity_justification=severity_justification,
            file_path=vuln_path,
            description=description,
            mitigation=mitigation,
            out_of_scope=False,
            impact=severity,
            static_finding=True,
            dynamic_finding=False,
            vuln_id_from_tool=unique_key
        )
        return finding

    def _get_severity_for_score(self, score: int) -> str:
        # Following the CVSS Scoring per https://nvd.nist.gov/vuln-metrics/cvss
        if score <= 390:
            return 'Low'
        elif score >= 400 and score < 690:
            return 'Medium'
        elif score >= 700 and score < 890:
            return 'High'
        return 'Critical'
