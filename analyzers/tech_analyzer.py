import os
import re
import yaml
from typing import Dict, List
from models import Technology


class TechAnalyzer:
    def __init__(self, signatures_file: str = "tech_signatures.yaml"):
        self.signatures = self._load_signatures(signatures_file)
        
        self.garbage_versions = {
            'next', 'Next', 'min', 'js', 'true', 'false', 'undefined', 
            'function', 'var', 'return', 'new', 'this', 'null', 'length',
            'latest', 'stable', 'beta', 'alpha', 'dev', 'production'
        }

    def _load_signatures(self, filepath: str) -> list:
        if not os.path.exists(filepath):
            print(f"  [!] Tech signatures file not found: {filepath}")
            return []
        
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
            
            techs = data.get('technologies', [])
            print(f"  [+] Loaded {len(techs)} technology signatures from {filepath}")
            return techs
        except Exception as e:
            print(f"  [!] Error loading tech signatures: {e}")
            return []

    def analyze_text(self, text: str, source: str) -> List[Dict]:
        results = []
        
        for tech in self.signatures:
            name = tech.get('name')
            detection_patterns = tech.get('detection_patterns', [])
            version_patterns = tech.get('version_patterns') or []

            is_detected = False
            for pattern in detection_patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    is_detected = True
                    break

            if is_detected:
                version = "N/A"
                indicator = "Detected"

                if version_patterns:
                    for v_info in version_patterns:
                        v_pattern = v_info.get('pattern')
                        v_desc = v_info.get('description', "Version {version}")
                        
                        matches = re.findall(v_pattern, text, re.IGNORECASE)
                        if matches:
                            for match in matches:
                                ver = match if isinstance(match, str) else "N/A"
                                if ver not in self.garbage_versions and len(ver) > 1 and re.search(r'\d', ver):
                                    version = ver
                                    indicator = v_desc.format(version=ver)
                                    break
                            
                            if version != "N/A":
                                break

                results.append({
                    'name': name,
                    'version': version,
                    'source': source,
                    'indicator': indicator
                })
        
        return results

    def analyze_js_files(self, js_dir: str) -> List[Technology]:
        all_findings = []
        
        if not os.path.exists(js_dir):
            return []
            
        for filename in os.listdir(js_dir):
            if not filename.endswith('.js'):
                continue
            filepath = os.path.join(js_dir, filename)
            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    text = f.read()
                    findings = self.analyze_text(text, f"JS File: {filename}")
                    all_findings.extend(findings)
            except Exception:
                pass
        
        tech_groups: Dict[str, Dict] = {}
        
        for finding in all_findings:
            name = finding['name']
            
            if name not in tech_groups:
                tech_groups[name] = {
                    'name': name,
                    'version': finding['version'],
                    'indicator': finding['indicator'],
                    'sources': set()
                }
            
            tech_groups[name]['sources'].add(finding['source'])
            
            if finding['version'] != "N/A" and tech_groups[name]['version'] == "N/A":
                tech_groups[name]['version'] = finding['version']
                tech_groups[name]['indicator'] = finding['indicator']
        
        result = []
        for name, group in tech_groups.items():
            sources_list = sorted(list(group['sources']))
            sources_str = ", ".join(sources_list[:5])
            if len(sources_list) > 5:
                sources_str += f" ... and {len(sources_list) - 5} more"
            
            indicator = f"{group['indicator']} | Found in: {sources_str}"
            
            result.append(Technology(
                name=group['name'],
                version=group['version'],
                source=sources_str,
                indicator=indicator
            ))
        
        return result

    def analyze_html(self, html_content: str, url: str) -> List[Technology]:
        findings = self.analyze_text(html_content, f"HTML Response: {url}")
        
        tech_groups: Dict[str, Dict] = {}
        for finding in findings:
            name = finding['name']
            if name not in tech_groups:
                tech_groups[name] = {
                    'name': name,
                    'version': finding['version'],
                    'indicator': finding['indicator'],
                    'sources': set()
                }
            tech_groups[name]['sources'].add(finding['source'])
            if finding['version'] != "N/A" and tech_groups[name]['version'] == "N/A":
                tech_groups[name]['version'] = finding['version']
                tech_groups[name]['indicator'] = finding['indicator']
        
        result = []
        for name, group in tech_groups.items():
            sources_list = sorted(list(group['sources']))
            sources_str = ", ".join(sources_list)
            indicator = f"{group['indicator']} | Found in: {sources_str}"
            
            result.append(Technology(
                name=group['name'],
                version=group['version'],
                source=sources_str,
                indicator=indicator
            ))
        
        return result