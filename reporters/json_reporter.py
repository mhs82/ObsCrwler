import json
import os
from models import CrawlResult


class JSONReporter:
    def generate(self, result: CrawlResult, output_dir: str):
        reports_dir = os.path.join(output_dir, "reports")
        os.makedirs(reports_dir, exist_ok=True)
        
        visited_pages_list = sorted(list(result.visited_pages)) if result.visited_pages else []
        all_links_list = sorted(list(result.all_links)) if result.all_links else []
        
        sensitive_paths_list = []
        for s in result.sensitive_paths:
            if hasattr(s, 'to_dict'):
                sensitive_paths_list.append(s.to_dict())
            else:
                sensitive_paths_list.append(s)
        
        # 🔑 فرمت‌بندی API ها با اطلاعات کامل
        apis_list = []
        for api in result.js_apis:
            apis_list.append({
                'endpoint': api.get('endpoint', ''),
                'source_file': api.get('source_file', ''),
                'severity': api.get('severity', 'MEDIUM'),
                'line': api.get('line'),
                'context': api.get('context', ''),
                'pattern_type': api.get('pattern_type', '')
            })
        
        # 🔑 فرمت‌بندی WebSocket ها با اطلاعات کامل
        websockets_list = []
        for ws in result.websockets:
            if isinstance(ws, dict):
                websockets_list.append(ws)
            else:
                websockets_list.append({'url': ws})
        
        data = {
            "target": result.target,
            "summary": {
                "visited_pages": len(result.visited_pages),
                "links": len(result.all_links),
                "forms": len(result.all_forms),
                "parameters": len(result.all_parameters),
                "injection_targets": len(result.injection_targets),
                "vulnerabilities": len(result.vulnerabilities),
                "technologies_found": len(result.technologies),
                "js_files": len(result.all_js_files),
                "api_endpoints": len(result.js_apis),
                "websockets": len(result.websockets),
                "sensitive_paths": len(result.sensitive_paths),
                "active_scan_results": len(result.active_scan_results),
                "api_domains": len(result.api_domains)
            },
            "api_domains": result.api_domains,
            "visited_pages": visited_pages_list,
            "all_links": all_links_list,
            "forms": [f.to_dict() if hasattr(f, 'to_dict') else f for f in result.all_forms],
            "parameters": [p.to_dict() if hasattr(p, 'to_dict') else p for p in result.all_parameters],
            "parameter_groups": result.parameter_groups,
            "technologies": [t.to_dict() if hasattr(t, 'to_dict') else t for t in result.technologies],
            "injection_targets": [t.to_dict() if hasattr(t, 'to_dict') else t for t in result.injection_targets],
            "vulnerabilities": [v.to_dict() if hasattr(v, 'to_dict') else v for v in result.vulnerabilities],
            "js_analysis": {
                "apis": apis_list,
                "sensitive_paths": sensitive_paths_list,
                "websockets": websockets_list
            },
            "network_logs": result.network_logs[:100],
            "active_scan_results": result.active_scan_results,
            "pwa_info": result.pwa_info
        }
        
        filepath = os.path.join(reports_dir, "scan_results.json")
        
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False, default=str)
            print(f"[+] JSON report saved to: {filepath}")
            return filepath
        except Exception as e:
            print(f"[!] Error saving JSON report: {e}")
            import traceback
            traceback.print_exc()
            return None