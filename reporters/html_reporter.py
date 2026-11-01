import os
import time
from html import escape as html_escape
from models import CrawlResult
from reporters.base import BaseReporter


class HTMLReporter(BaseReporter):

    def generate(self, result: CrawlResult, output_path: str):
        filepath = os.path.join(output_path, "report.html")

        sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        cat_counts = {}
        for s in result.sensitive_paths:
            sev_counts[s.severity] = sev_counts.get(s.severity, 0) + 1
            cat_counts[s.category] = cat_counts.get(s.category, 0) + 1

        html = self._build_html(result, sev_counts, cat_counts)

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html)
        print(f"[+] HTML report saved to: {filepath}")
        return filepath

    def _build_html(self, result: CrawlResult, sev_counts: dict, cat_counts: dict) -> str:
        host = result.target.split("//")[-1].split("/")[0]

        overview_html = self._build_overview(result, sev_counts, cat_counts)
        pages_html = self._build_pages_list(result)
        links_html = self._build_links(result)
        forms_html = self._build_forms(result)
        params_html = self._build_parameters(result)
        param_groups_html = self._build_param_groups(result)
        injection_targets_html = self._build_injection_targets(result)
        sensitive_html = self._build_sensitive(result)
        ws_html = self._build_websockets(result)
        active_html = self._build_active(result)
        apis_html = self._build_apis(result)
        tech_html = self._build_technologies(result)
        api_domains_html = self._build_api_domains(result)

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Obscura Report - {html_escape(host)}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #f1f5f9; color: #1e293b; padding: 20px; }}
  .container {{ max-width: 1400px; margin: 0 auto; }}
  header {{ background: linear-gradient(135deg, #0f172a, #1e293b); color: white; padding: 30px; border-radius: 12px; margin-bottom: 20px; }}
  header h1 {{ font-size: 24px; margin-bottom: 8px; }}
  header p {{ color: #cbd5e1; font-size: 14px; }}
  
  .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 12px; margin-bottom: 20px; }}
  .stat-card {{ background: white; padding: 16px; border-radius: 10px; border-left: 4px solid #3b82f6; box-shadow: 0 1px 3px rgba(0,0,0,0.05); }}
  .stat-card.critical {{ border-left-color: #dc2626; }}
  .stat-card.high {{ border-left-color: #ea580c; }}
  .stat-card.medium {{ border-left-color: #d97706; }}
  .stat-card.low {{ border-left-color: #16a34a; }}
  .stat-card.ws {{ border-left-color: #8b5cf6; }}
  .stat-card.forms {{ border-left-color: #0891b2; }}
  .stat-card.params {{ border-left-color: #6366f1; }}
  .stat-card.tech {{ border-left-color: #ec4899; }}
  .stat-card.api {{ border-left-color: #f59e0b; }}
  .stat-label {{ font-size: 11px; color: #64748b; text-transform: uppercase; letter-spacing: 0.5px; }}
  .stat-value {{ font-size: 26px; font-weight: 700; margin-top: 4px; }}
  
  .tabs {{ display: flex; gap: 4px; border-bottom: 2px solid #e2e8f0; margin-bottom: 16px; flex-wrap: wrap; background: white; padding: 8px; border-radius: 10px 10px 0 0; }}
  .tab {{ padding: 10px 16px; cursor: pointer; background: none; border: none; font-weight: 600; color: #64748b; border-bottom: 3px solid transparent; margin-bottom: -11px; font-size: 13px; border-radius: 6px 6px 0 0; }}
  .tab.active {{ color: #0f172a; border-bottom-color: #3b82f6; background: #f8fafc; }}
  .tab:hover {{ color: #0f172a; background: #f8fafc; }}
  .tab .count {{ background: #e2e8f0; color: #475569; padding: 2px 8px; border-radius: 999px; font-size: 11px; margin-left: 4px; }}
  .tab.active .count {{ background: #3b82f6; color: white; }}
  
  .panel {{ display: none; }}
  .panel.active {{ display: block; }}
  
  .finding {{ background: white; padding: 14px; border-radius: 8px; margin-bottom: 8px; border-left: 4px solid #94a3b8; box-shadow: 0 1px 2px rgba(0,0,0,0.05); }}
  .finding.CRITICAL {{ border-left-color: #dc2626; background: #fef2f2; }}
  .finding.HIGH {{ border-left-color: #ea580c; background: #fff7ed; }}
  .finding.MEDIUM {{ border-left-color: #d97706; background: #fffbeb; }}
  .finding.LOW {{ border-left-color: #16a34a; background: #f0fdf4; }}
  .finding.INFO {{ border-left-color: #64748b; }}
  .finding.ws {{ border-left-color: #8b5cf6; background: #faf5ff; }}
  .finding.link {{ border-left-color: #3b82f6; }}
  .finding.form {{ border-left-color: #0891b2; }}
  .finding.param {{ border-left-color: #6366f1; }}
  .finding.page {{ border-left-color: #059669; }}
  .finding.tech {{ border-left-color: #ec4899; background: #fdf2f8; }}
  .finding.api {{ border-left-color: #f59e0b; background: #fffbeb; }}
  
  .finding-header {{ display: flex; justify-content: space-between; flex-wrap: wrap; gap: 8px; margin-bottom: 6px; align-items: center; }}
  .badge {{ display: inline-block; padding: 3px 10px; border-radius: 999px; font-size: 11px; font-weight: 700; }}
  .badge.CRITICAL {{ background: #dc2626; color: white; }}
  .badge.HIGH {{ background: #ea580c; color: white; }}
  .badge.MEDIUM {{ background: #d97706; color: white; }}
  .badge.LOW {{ background: #16a34a; color: white; }}
  .badge.INFO {{ background: #64748b; color: white; }}
  .badge.ws {{ background: #8b5cf6; color: white; }}
  .badge.tech {{ background: #ec4899; color: white; }}
  .badge.api {{ background: #f59e0b; color: white; }}
  .badge.category {{ background: #e0e7ff; color: #3730a3; }}
  .badge.status {{ font-family: monospace; }}
  .badge.method-get {{ background: #10b981; color: white; }}
  .badge.method-post {{ background: #f59e0b; color: white; }}
  .badge.method-put {{ background: #3b82f6; color: white; }}
  .badge.method-delete {{ background: #ef4444; color: white; }}
  .badge.sensitive {{ background: #fee2e2; color: #991b1b; }}
  .badge.numeric {{ background: #dbeafe; color: #1e40af; }}
  .badge.line {{ background: #e0e7ff; color: #3730a3; font-family: monospace; }}
  
  .match {{ font-family: 'Courier New', monospace; font-size: 13px; font-weight: 600; color: #0f172a; word-break: break-all; margin: 4px 0; }}
  .match a {{ color: #3b82f6; text-decoration: none; }}
  .match a:hover {{ text-decoration: underline; }}
  .meta {{ font-size: 12px; color: #64748b; margin-top: 4px; }}
  .meta a {{ color: #3b82f6; text-decoration: none; }}
  .meta a:hover {{ text-decoration: underline; }}
  .context {{ background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 6px; padding: 8px; margin-top: 6px; font-family: monospace; font-size: 12px; max-height: 150px; overflow-y: auto; word-break: break-all; color: #475569; white-space: pre-wrap; }}
  
  .filter-bar {{ background: white; padding: 12px; border-radius: 8px; margin-bottom: 12px; display: flex; gap: 10px; flex-wrap: wrap; align-items: center; box-shadow: 0 1px 2px rgba(0,0,0,0.05); }}
  .filter-bar input, .filter-bar select {{ padding: 8px 12px; border: 1px solid #cbd5e1; border-radius: 6px; font-size: 14px; }}
  .filter-bar input {{ flex: 1; min-width: 200px; }}
  .filter-bar input:focus, .filter-bar select:focus {{ outline: none; border-color: #3b82f6; }}
  
  details {{ background: white; padding: 12px; border-radius: 8px; margin-bottom: 8px; border-left: 4px solid #0891b2; box-shadow: 0 1px 2px rgba(0,0,0,0.05); }}
  details[open] {{ background: #f0fdfa; }}
  summary {{ cursor: pointer; font-weight: 600; padding: 4px; }}
  summary:hover {{ color: #0891b2; }}
  
  .inputs-table {{ width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 13px; }}
  .inputs-table th {{ background: #f1f5f9; padding: 8px; text-align: left; font-weight: 600; border-bottom: 2px solid #cbd5e1; }}
  .inputs-table td {{ padding: 6px 8px; border-bottom: 1px solid #e2e8f0; font-family: monospace; }}
  .inputs-table tr:hover {{ background: #f8fafc; }}
  
  .empty {{ text-align: center; padding: 40px; color: #64748b; background: white; border-radius: 8px; }}
  
  .section-title {{ font-size: 18px; font-weight: 700; margin: 20px 0 12px; color: #0f172a; }}
  .section-subtitle {{ font-size: 14px; color: #64748b; margin-bottom: 16px; }}
  
  .grid-2 {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 12px; }}
  .info-box {{ background: white; padding: 16px; border-radius: 8px; box-shadow: 0 1px 2px rgba(0,0,0,0.05); }}
  .info-box h3 {{ font-size: 14px; color: #64748b; margin-bottom: 8px; text-transform: uppercase; letter-spacing: 0.5px; }}
  .info-box .value {{ font-size: 20px; font-weight: 700; color: #0f172a; }}
  
  .url-list {{ background: white; padding: 12px; border-radius: 8px; max-height: 500px; overflow-y: auto; }}
  .url-item {{ padding: 6px 10px; border-bottom: 1px solid #f1f5f9; font-family: monospace; font-size: 12px; word-break: break-all; }}
  .url-item:hover {{ background: #f8fafc; }}
  .url-item a {{ color: #3b82f6; text-decoration: none; }}
  .url-item a:hover {{ text-decoration: underline; }}
  
  .tech-card {{ background: white; padding: 16px; border-radius: 8px; border-left: 4px solid #ec4899; box-shadow: 0 1px 3px rgba(0,0,0,0.05); margin-bottom: 12px; }}
  .tech-card h4 {{ font-size: 18px; color: #0f172a; margin-bottom: 8px; }}
  .tech-card .tech-version {{ font-family: monospace; color: #ec4899; font-weight: 600; font-size: 14px; margin-bottom: 8px; }}
  .tech-card .tech-indicator {{ font-family: monospace; font-size: 12px; color: #475569; background: #f1f5f9; padding: 6px 10px; border-radius: 4px; margin-bottom: 10px; word-break: break-all; }}
  .tech-card .tech-sources {{ margin-top: 10px; }}
  .tech-card .tech-sources h5 {{ font-size: 12px; color: #64748b; margin-bottom: 6px; text-transform: uppercase; }}
  .tech-card .source-item {{ font-family: monospace; font-size: 11px; color: #475569; background: #f8fafc; padding: 4px 8px; border-radius: 4px; margin-bottom: 4px; word-break: break-all; }}
  
  .api-card {{ background: white; padding: 16px; border-radius: 8px; border-left: 4px solid #f59e0b; box-shadow: 0 1px 3px rgba(0,0,0,0.05); margin-bottom: 12px; }}
  .api-card .api-endpoint {{ font-family: monospace; font-size: 14px; font-weight: 600; color: #0f172a; word-break: break-all; margin-bottom: 8px; }}
  .api-card .api-meta {{ display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 8px; }}
  .api-card .api-context {{ background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 6px; padding: 8px; margin-top: 8px; font-family: monospace; font-size: 11px; max-height: 100px; overflow-y: auto; word-break: break-all; color: #475569; white-space: pre-wrap; }}
  
  footer {{ text-align: center; padding: 20px; color: #64748b; font-size: 12px; margin-top: 20px; }}
</style>
</head>
<body>
<div class="container">

<header>
  <h1>Obscura Crawler Report</h1>
  <p>Target: <strong>{html_escape(host)}</strong> &bull; Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}</p>
</header>

<div class="stats-grid">
  <div class="stat-card"><div class="stat-label">Pages Crawled</div><div class="stat-value">{len(result.visited_pages)}</div></div>
  <div class="stat-card"><div class="stat-label">Links Found</div><div class="stat-value">{len(result.all_links)}</div></div>
  <div class="stat-card forms"><div class="stat-label">Forms</div><div class="stat-value">{len(result.all_forms)}</div></div>
  <div class="stat-card params"><div class="stat-label">Parameters</div><div class="stat-value">{len(result.all_parameters)}</div></div>
  <div class="stat-card"><div class="stat-label">JS Files</div><div class="stat-value">{len(result.all_js_files)}</div></div>
  <div class="stat-card api"><div class="stat-label">API Endpoints</div><div class="stat-value">{len(result.js_apis)}</div></div>
  <div class="stat-card ws"><div class="stat-label">WebSockets</div><div class="stat-value">{len(result.websockets)}</div></div>
  <div class="stat-card tech"><div class="stat-label">Technologies</div><div class="stat-value">{len(result.technologies)}</div></div>
  <div class="stat-card critical"><div class="stat-label">Critical</div><div class="stat-value">{sev_counts.get('CRITICAL',0)}</div></div>
  <div class="stat-card high"><div class="stat-label">High</div><div class="stat-value">{sev_counts.get('HIGH',0)}</div></div>
  <div class="stat-card medium"><div class="stat-label">Medium</div><div class="stat-value">{sev_counts.get('MEDIUM',0)}</div></div>
</div>

<div class="tabs">
  <button class="tab active" onclick="showPanel('overview', event)">Overview</button>
  <button class="tab" onclick="showPanel('pages', event)">Pages <span class="count">{len(result.visited_pages)}</span></button>
  <button class="tab" onclick="showPanel('links', event)">Links <span class="count">{len(result.all_links)}</span></button>
  <button class="tab" onclick="showPanel('forms', event)">Forms <span class="count">{len(result.all_forms)}</span></button>
  <button class="tab" onclick="showPanel('params', event)">Params <span class="count">{len(result.all_parameters)}</span></button>
  <button class="tab" onclick="showPanel('groups', event)">Groups <span class="count">{len(result.parameter_groups)}</span></button>
  <button class="tab" onclick="showPanel('targets', event)">Targets <span class="count">{len(result.injection_targets)}</span></button>
  <button class="tab" onclick="showPanel('apis', event)">APIs <span class="count">{len(result.js_apis)}</span></button>
  <button class="tab" onclick="showPanel('sensitive', event)">Sensitive <span class="count">{len(result.sensitive_paths)}</span></button>
  <button class="tab" onclick="showPanel('ws', event)">WS <span class="count">{len(result.websockets)}</span></button>
  <button class="tab" onclick="showPanel('tech', event)">Technologies <span class="count">{len(result.technologies)}</span></button>
  <button class="tab" onclick="showPanel('api_domains', event)">API Domains <span class="count">{len(result.api_domains)}</span></button>
  <button class="tab" onclick="showPanel('active', event)">Active <span class="count">{len(result.active_scan_results)}</span></button>
</div>

<div id="overview" class="panel active">
  {overview_html}
</div>

<div id="pages" class="panel">
  <div class="filter-bar">
    <input type="text" id="pagesSearch" placeholder="Search pages..." oninput="filterSimple('pagesList','pagesSearch')">
  </div>
  <div id="pagesList" class="url-list">
    {pages_html}
  </div>
</div>

<div id="links" class="panel">
  <div class="filter-bar">
    <input type="text" id="linksSearch" placeholder="Search links..." oninput="filterSimple('linksList','linksSearch')">
  </div>
  <div id="linksList" class="url-list">
    {links_html}
  </div>
</div>

<div id="forms" class="panel">
  <div class="filter-bar">
    <input type="text" id="formsSearch" placeholder="Search forms, actions, inputs..." oninput="filterSimple('formsList','formsSearch')">
  </div>
  <div id="formsList">
    {forms_html}
  </div>
</div>

<div id="params" class="panel">
  <div class="filter-bar">
    <input type="text" id="paramsSearch" placeholder="Search parameters..." oninput="filterSimple('paramsList','paramsSearch')">
    <select id="paramsTypeFilter" onchange="filterByData('paramsList','ptype','paramsTypeFilter')">
      <option value="">All Types</option>
      <option value="query">Query String</option>
      <option value="path">Path Segment</option>
    </select>
  </div>
  <div id="paramsList">
    {params_html}
  </div>
</div>

<div id="groups" class="panel">
  <div class="filter-bar">
    <input type="text" id="groupsSearch" placeholder="Search parameter names..." oninput="filterSimple('groupsList','groupsSearch')">
    <select id="groupsPriorityFilter" onchange="filterByData('groupsList','priority','groupsPriorityFilter')">
      <option value="">All Priorities</option>
      <option value="high">High Priority</option>
      <option value="medium">Medium Priority</option>
      <option value="low">Low Priority</option>
    </select>
  </div>
  <div id="groupsList">
    {param_groups_html}
  </div>
</div>

<div id="targets" class="panel">
  <div class="filter-bar">
    <input type="text" id="targetsSearch" placeholder="Search targets (name, url, type)..." oninput="filterSimple('targetsList','targetsSearch')">
    <select id="targetsTypeFilter" onchange="filterByData('targetsList','ttype','targetsTypeFilter')">
      <option value="">All Types</option>
      <option value="url_param">URL Parameters</option>
      <option value="form_input">Form Inputs</option>
    </select>
    <select id="targetsMethodFilter" onchange="filterByData('targetsList','tmethod','targetsMethodFilter')">
      <option value="">All Methods</option>
      <option value="GET">GET</option>
      <option value="POST">POST</option>
    </select>
  </div>
  <div id="targetsList">
    {injection_targets_html}
  </div>
</div>

<div id="apis" class="panel">
  <div class="filter-bar">
    <input type="text" id="apisSearch" placeholder="Search API endpoints..." oninput="filterSimple('apisList','apisSearch')">
    <select id="apisSeverityFilter" onchange="filterByData('apisList','severity','apisSeverityFilter')">
      <option value="">All Severities</option>
      <option value="HIGH">High</option>
      <option value="MEDIUM">Medium</option>
      <option value="LOW">Low</option>
    </select>
  </div>
  <div id="apisList">{apis_html}</div>
</div>

<div id="sensitive" class="panel">
  <div class="filter-bar">
    <input type="text" id="s1" placeholder="Search..." oninput="filterAdv()">
    <select id="s2" onchange="filterAdv()">
      <option value="">All Severities</option>
      <option value="CRITICAL">Critical</option>
      <option value="HIGH">High</option>
      <option value="MEDIUM">Medium</option>
      <option value="LOW">Low</option>
    </select>
  </div>
  <div id="fL">{sensitive_html}</div>
</div>

<div id="ws" class="panel">
  <div class="filter-bar">
    <input type="text" id="w1" placeholder="Search..." oninput="filterSimple('wsL','w1')">
  </div>
  <div id="wsL">{ws_html}</div>
</div>

<div id="tech" class="panel">
  <div class="filter-bar">
    <input type="text" id="techSearch" placeholder="Search technologies..." oninput="filterSimple('techList','techSearch')">
  </div>
  <div id="techList">{tech_html}</div>
</div>

<div id="api_domains" class="panel">
  <div class="filter-bar">
    <input type="text" id="apiDomainsSearch" placeholder="Search API domains..." oninput="filterSimple('apiDomainsList','apiDomainsSearch')">
  </div>
  <div id="apiDomainsList">{api_domains_html}</div>
</div>

<div id="active" class="panel">
  <div class="filter-bar">
    <input type="text" id="a1" placeholder="Search..." oninput="filterSimple('aL','a1')">
  </div>
  <div id="aL">{active_html}</div>
</div>

<footer>Generated by Obscura Crawler &bull; OOP Edition</footer>
</div>

<script>
function showPanel(id, evt) {{
  document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.getElementById(id).classList.add('active');
  evt.target.classList.add('active');
}}

function filterSimple(listId, searchId) {{
  const s = document.getElementById(searchId).value.toLowerCase();
  const container = document.getElementById(listId);
  if (!container) return;
  container.querySelectorAll('.finding, .url-item, details, .tech-card, .api-card').forEach(el => {{
    const text = (el.dataset.search || el.innerText || '').toLowerCase();
    el.style.display = (!s || text.includes(s)) ? '' : 'none';
  }});
}}

function filterByData(listId, dataKey, selectId) {{
  const val = document.getElementById(selectId).value;
  const container = document.getElementById(listId);
  if (!container) return;
  container.querySelectorAll('.finding, details, .api-card').forEach(el => {{
    el.style.display = (!val || el.dataset[dataKey] === val) ? '' : 'none';
  }});
}}

function filterAdv() {{
  const s = document.getElementById('s1').value.toLowerCase();
  const sev = document.getElementById('s2').value;
  document.querySelectorAll('#fL .finding').forEach(el => {{
    const ms = !s || (el.dataset.search || '').includes(s);
    const mv = !sev || el.dataset.sev === sev;
    el.style.display = (ms && mv) ? '' : 'none';
  }});
}}
</script>
</body>
</html>"""

    def _build_overview(self, result: CrawlResult, sev_counts: dict, cat_counts: dict) -> str:
        total_inputs = sum(
            len(f.inputs) if hasattr(f, 'inputs') else len(f.get('inputs', []))
            for f in result.all_forms
        )
        
        html = f"""
  <h2 class="section-title">Discovery Overview</h2>
  <p class="section-subtitle">Summary of all discovered data during the crawl process</p>
  
  <div class="grid-2">
    <div class="info-box">
      <h3>Pages Crawled</h3>
      <div class="value">{len(result.visited_pages)}</div>
      <div class="meta">Visited pages</div>
    </div>
    <div class="info-box">
      <h3>Unique Links</h3>
      <div class="value">{len(result.all_links)}</div>
      <div class="meta">Unique links in scope</div>
    </div>
    <div class="info-box">
      <h3>Forms Discovered</h3>
      <div class="value">{len(result.all_forms)}</div>
      <div class="meta">Forms with {total_inputs} inputs</div>
    </div>
    <div class="info-box">
      <h3>Parameters</h3>
      <div class="value">{len(result.all_parameters)}</div>
      <div class="meta">URL parameters</div>
    </div>
    <div class="info-box">
      <h3>API Endpoints</h3>
      <div class="value">{len(result.js_apis)}</div>
      <div class="meta">Extracted from JS</div>
    </div>
    <div class="info-box" style="border-left: 4px solid #ec4899;">
      <h3>Technologies</h3>
      <div class="value" style="color:#ec4899;">{len(result.technologies)}</div>
      <div class="meta">Unique technologies</div>
    </div>
    <div class="info-box" style="border-left: 4px solid #f59e0b;">
      <h3>API Domains</h3>
      <div class="value" style="color:#f59e0b;">{len(result.api_domains)}</div>
      <div class="meta">Discovered API hosts</div>
    </div>
  </div>
  
  <h2 class="section-title" style="margin-top:30px;">Security Findings</h2>
  <div class="grid-2">
    <div class="info-box" style="border-left: 4px solid #dc2626;">
      <h3>Critical</h3>
      <div class="value" style="color:#dc2626;">{sev_counts.get('CRITICAL',0)}</div>
    </div>
    <div class="info-box" style="border-left: 4px solid #ea580c;">
      <h3>High</h3>
      <div class="value" style="color:#ea580c;">{sev_counts.get('HIGH',0)}</div>
    </div>
    <div class="info-box" style="border-left: 4px solid #d97706;">
      <h3>Medium</h3>
      <div class="value" style="color:#d9770c;">{sev_counts.get('MEDIUM',0)}</div>
    </div>
    <div class="info-box" style="border-left: 4px solid #16a34a;">
      <h3>Low</h3>
      <div class="value" style="color:#16a34a;">{sev_counts.get('LOW',0)}</div>
    </div>
  </div>
"""
        if cat_counts:
            html += """
  <h2 class="section-title" style="margin-top:30px;">Findings by Category</h2>
  <div class="grid-2">
"""
            for cat, count in sorted(cat_counts.items(), key=lambda x: -x[1]):
                html += f"""    <div class="info-box">
      <h3>{html_escape(cat)}</h3>
      <div class="value">{count}</div>
    </div>
"""
            html += "  </div>\n"
        
        return html

    def _build_pages_list(self, result: CrawlResult) -> str:
        if not result.visited_pages:
            return '<div class="empty">No pages crawled.</div>'
        
        html = ""
        for url in sorted(result.visited_pages):
            html += f'<div class="url-item" data-search="{html_escape(url.lower())}"><a href="{html_escape(url)}" target="_blank">{html_escape(url)}</a></div>\n'
        return html

    def _build_links(self, result: CrawlResult) -> str:
        if not result.all_links:
            return '<div class="empty">No links found.</div>'
        
        html = ""
        for link in sorted(result.all_links):
            html += f'<div class="url-item finding link" data-search="{html_escape(link.lower())}"><a href="{html_escape(link)}" target="_blank">{html_escape(link)}</a></div>\n'
        return html

    def _build_forms(self, result: CrawlResult) -> str:
        if not result.all_forms:
            return '<div class="empty">No forms found.</div>'
        
        html = ""
        for idx, form in enumerate(result.all_forms, 1):
            if hasattr(form, 'to_dict'):
                f = form.to_dict()
            elif hasattr(form, 'action'):
                f = {"action": form.action, "method": form.method, "title": form.title, 
                     "source_url": form.source_url, "inputs": [i.to_dict() if hasattr(i, 'to_dict') else i for i in form.inputs]}
            else:
                f = form
            
            action = f.get('action', '')
            method = f.get('method', 'GET').upper()
            title = f.get('title', '') or f'Form #{idx}'
            source = f.get('source_url', '')
            inputs = f.get('inputs', [])
            
            method_class = f"method-{method.lower()}"
            search_text = f"{action} {title} {source} {' '.join(i.get('name','') for i in inputs)}".lower()
            
            html += f"""
    <details class="finding form" data-search="{html_escape(search_text)}">
      <summary>
        <span class="badge {method_class}">{method}</span>
        <span style="margin-left:8px; font-weight:600;">{html_escape(title[:60])}</span>
        <span class="meta" style="margin-left:8px;">({len(inputs)} inputs)</span>
      </summary>
      <div style="margin-top:10px;">
        <div class="meta"><strong>Action:</strong> <a href="{html_escape(action)}" target="_blank">{html_escape(action)}</a></div>
        <div class="meta"><strong>Source:</strong> <a href="{html_escape(source)}" target="_blank">{html_escape(source[:80])}</a></div>
"""
            if inputs:
                html += """
        <table class="inputs-table">
          <thead>
            <tr>
              <th>Name</th>
              <th>Type</th>
              <th>Value</th>
              <th>Required</th>
            </tr>
          </thead>
          <tbody>
"""
                for inp in inputs:
                    name = html_escape(inp.get('name', '') or '<em>unnamed</em>')
                    itype = html_escape(inp.get('type', 'text'))
                    value = html_escape(str(inp.get('value', ''))[:50])
                    required = '&#10003;' if inp.get('required') else ''
                    html += f"""            <tr>
              <td><strong>{name}</strong></td>
              <td>{itype}</td>
              <td>{value}</td>
              <td>{required}</td>
            </tr>
"""
                html += "          </tbody>\n        </table>\n"
            
            html += "      </div>\n    </details>\n"
        
        return html

    def _build_parameters(self, result: CrawlResult) -> str:
        if not result.all_parameters:
            return '<div class="empty">No parameters found.</div>'
        
        html = ""
        sensitive_names = {'id', 'user', 'email', 'q', 'search', 'cmd', 'file', 'path', 'token'}
        
        for p in result.all_parameters:
            if hasattr(p, 'to_dict'):
                pd = p.to_dict()
            elif hasattr(p, 'name'):
                pd = {"name": p.name, "sample_value": p.sample_value, "source_url": p.source_url, 
                      "path": p.path, "location": p.location}
            else:
                pd = p
            
            name = pd.get('name', '')
            sample = pd.get('sample_value', '')
            source = pd.get('source_url', '')
            location = pd.get('location', 'query')
            
            guessed = "string"
            if sample and str(sample).isdigit():
                guessed = "numeric"
            elif sample and "@" in str(sample):
                guessed = "email"
            
            search_text = f"{name} {sample} {source}".lower()
            badge_type = "numeric" if guessed == "numeric" else "category"
            is_sensitive = name.lower() in sensitive_names
            sensitive_badge = '<span class="badge sensitive">sensitive</span>' if is_sensitive else ''
            
            html += f"""
    <div class="finding param" data-search="{html_escape(search_text)}" data-ptype="{location}">
      <div class="finding-header">
        <div>
          <span class="badge {badge_type}">{html_escape(name)}</span>
          <span class="badge INFO">{location}</span>
          {sensitive_badge}
        </div>
      </div>
      <div class="meta"><strong>Sample:</strong> <code>{html_escape(sample)}</code></div>
      <div class="meta"><strong>Source:</strong> <a href="{html_escape(source)}" target="_blank">{html_escape(source[:80])}</a></div>
    </div>
"""
        return html

    def _build_param_groups(self, result: CrawlResult) -> str:
        if not result.parameter_groups:
            return '<div class="empty">No parameter groups found.</div>'
        
        sensitive_names = {'id', 'user', 'user_id', 'email', 'q', 'query', 'search', 'cmd', 'file', 'path', 'token', 'name'}
        
        html = ""
        for name, group in result.parameter_groups.items():
            if hasattr(group, 'to_dict'):
                gd = group.to_dict()
            elif hasattr(group, 'name'):
                gd = {
                    "name": group.name,
                    "total_occurrences": group.total_occurrences if hasattr(group, 'total_occurrences') else len(group.occurrences),
                    "unique_urls_count": len(group.unique_urls) if hasattr(group, 'unique_urls') else 0,
                    "sample_values": [p.sample_value for p in (group.occurrences[:5] if hasattr(group, 'occurrences') else [])],
                }
            else:
                gd = group
            
            total = gd.get('total_occurrences', 0)
            urls_count = gd.get('unique_urls_count', 0)
            samples = gd.get('sample_values', [])[:3]
            
            if name.lower() in sensitive_names:
                priority = "high"
                priority_badge = '<span class="badge CRITICAL">HIGH PRIORITY</span>'
            elif total >= 3:
                priority = "medium"
                priority_badge = '<span class="badge MEDIUM">MEDIUM</span>'
            else:
                priority = "low"
                priority_badge = '<span class="badge LOW">LOW</span>'
            
            search_text = f"{name} {' '.join(str(s) for s in samples)}".lower()
            
            html += f"""
    <div class="finding param" data-search="{html_escape(search_text)}" data-priority="{priority}">
      <div class="finding-header">
        <div>
          <span class="badge category">{html_escape(name)}</span>
          {priority_badge}
        </div>
        <div class="meta">{total} occurrences &bull; {urls_count} URLs</div>
      </div>
      <div class="meta"><strong>Sample values:</strong> <code>{html_escape(', '.join(str(s) for s in samples))}</code></div>
    </div>
"""
        return html

    def _build_injection_targets(self, result: CrawlResult) -> str:
        if not result.injection_targets:
            return '<div class="empty">No injection targets found.</div>'
        
        html = ""
        for t in result.injection_targets:
            t_dict = t.to_dict() if hasattr(t, 'to_dict') else t
            
            t_type = t_dict.get('target_type', '')
            name = t_dict.get('param_name', '')
            url = t_dict.get('url', '')
            method = t_dict.get('method', 'GET')
            sample = t_dict.get('sample_value', '')
            form_title = t_dict.get('form_title', '')
            
            type_badge = "badge category" if t_type == "url_param" else "badge forms"
            type_text = "URL Param" if t_type == "url_param" else "Form Input"
            method_class = f"method-{method.lower()}"
            
            search_text = f"{name} {url} {form_title} {t_type}".lower()
            
            html += f"""
    <div class="finding param" data-search="{html_escape(search_text)}" data-ttype="{t_type}" data-tmethod="{method}">
      <div class="finding-header">
        <div>
          <span class="badge {type_badge}">{html_escape(type_text)}</span>
          <span class="badge {method_class}">{method}</span>
          <span class="badge INFO" style="font-family:monospace;">{html_escape(name)}</span>
        </div>
      </div>
      <div class="meta"><strong>Target URL/Action:</strong> <a href="{html_escape(url)}" target="_blank">{html_escape(url[:100])}</a></div>
      {f'<div class="meta"><strong>Form:</strong> {html_escape(form_title)}</div>' if form_title else ''}
      <div class="meta"><strong>Sample Value:</strong> <code>{html_escape(sample)}</code></div>
    </div>
"""
        return html

    def _build_apis(self, result: CrawlResult) -> str:
        """نمایش API ها با شماره خط و context"""
        if not result.js_apis:
            return '<div class="empty">No APIs found.</div>'
        
        html = ""
        for api in result.js_apis:
            endpoint = api.get('endpoint', '')
            source_file = api.get('source_file', '')
            severity = api.get('severity', 'MEDIUM')
            line = api.get('line')
            context = api.get('context', '')
            pattern_type = api.get('pattern_type', '')
            
            search_text = f"{endpoint} {source_file} {context}".lower()
            
            html += f"""
    <div class="api-card" data-search="{html_escape(search_text)}" data-severity="{severity}">
      <div class="api-meta">
        <span class="badge {severity}">{severity}</span>
        <span class="badge api">{html_escape(pattern_type or 'API')}</span>
        {f'<span class="badge line">Line {line}</span>' if line else ''}
      </div>
      <div class="api-endpoint">{html_escape(endpoint)}</div>
      <div class="meta">📁 Source: <code>{html_escape(source_file)}</code></div>
      {f'<div class="api-context">💻 Code: {html_escape(context)}</div>' if context else ''}
    </div>
"""
        return html

    def _build_sensitive(self, result: CrawlResult) -> str:
        if not result.sensitive_paths:
            return '<div class="empty">No sensitive paths found.</div>'
        
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        sorted_sens = sorted(result.sensitive_paths, key=lambda x: sev_order.get(x.severity, 5))
        
        html = ""
        for f in sorted_sens:
            meta = f.metadata or {}
            search_text = f"{f.match} {meta.get('file','')} {f.context or ''}".lower()
            html += f"""
    <div class="finding {f.severity}" data-sev="{f.severity}" data-cat="{f.category}" data-search="{html_escape(search_text)}">
      <div class="finding-header">
        <div>
          <span class="badge {f.severity}">{f.severity}</span>
          <span class="badge category">{html_escape(f.category)}</span>
          {f'<span class="badge line">Line {f.line}</span>' if f.line else ''}
        </div>
        <div class="meta">📁 {html_escape(meta.get('file',''))}</div>
      </div>
      <div class="match">{html_escape(f.match)}</div>
      {f'<div class="context">{html_escape(f.context or "")}</div>' if f.context else ''}
    </div>"""
        return html

    def _build_websockets(self, result: CrawlResult) -> str:
        if not result.websockets:
            return '<div class="empty">No WebSockets found.</div>'
        
        html = ""
        for w in result.websockets:
            if isinstance(w, dict):
                ws_url = w.get('url', '')
                source = w.get('source_file', '')
                line = w.get('line')
                context = w.get('context', '')
                search_text = f"{ws_url} {source}".lower()
                
                html += f"""
    <div class="finding ws" data-search="{html_escape(search_text)}">
      <div class="finding-header">
        <span class="badge ws">WebSocket</span>
        {f'<span class="badge line">Line {line}</span>' if line else ''}
      </div>
      <div class="match">{html_escape(ws_url)}</div>
      <div class="meta">📁 Source: <code>{html_escape(source)}</code></div>
      {f'<div class="context">{html_escape(context)}</div>' if context else ''}
    </div>"""
            else:
                html += f"""
    <div class="finding ws">
      <div class="match">{html_escape(str(w))}</div>
    </div>"""
        return html

    def _build_active(self, result: CrawlResult) -> str:
        if not result.active_scan_results:
            return '<div class="empty">No active scan results.</div>'
        
        html = ""
        for a in result.active_scan_results:
            sev = a.get('final_severity', 'INFO')
            st = a.get('status')
            status_badge = f'<span class="badge status">{st}</span>' if st else f'<span class="badge INFO">{html_escape(a.get("status_text",""))}</span>'
            search_text = f"{a['url']} {a['category']}".lower()
            html += f"""
    <div class="finding {sev}" data-search="{html_escape(search_text)}">
      <div class="finding-header">
        <div>
          <span class="badge {sev}">{sev}</span>
          <span class="badge category">{html_escape(a['category'])}</span>
          {status_badge}
        </div>
      </div>
      <div class="match"><a href="{html_escape(a['url'])}" target="_blank" style="color:inherit;">{html_escape(a['url'])}</a></div>
    </div>"""
        return html

    def _build_technologies(self, result: CrawlResult) -> str:
        """نمایش تکنولوژی‌ها به صورت گروه‌بندی شده"""
        if not result.technologies:
            return '<div class="empty">No technologies identified.</div>'
        
        html = ""
        for t in result.technologies:
            if hasattr(t, 'to_dict'):
                td = t.to_dict()
            elif hasattr(t, 'name'):
                td = {"name": t.name, "version": t.version, "source": t.source, "indicator": t.indicator}
            else:
                td = t
            
            name = td.get('name', '')
            version = td.get('version', 'N/A')
            source = td.get('source', '')
            indicator = td.get('indicator', '')
            
            search_text = f"{name} {version} {source} {indicator}".lower()
            
            # 🔑 استخراج لیست منابع از indicator
            sources_list = []
            if 'Found in:' in indicator:
                sources_part = indicator.split('Found in:')[-1].strip()
                sources_list = [s.strip() for s in sources_part.split(',') if s.strip()]
            elif source:
                sources_list = [source]
            
            html += f"""
    <div class="tech-card" data-search="{html_escape(search_text)}">
      <h4>{html_escape(name)}</h4>
      <div class="tech-version">v{html_escape(version)}</div>
      <div class="tech-indicator">🔍 {html_escape(indicator.split('|')[0] if '|' in indicator else indicator)}</div>
      {f'''
      <div class="tech-sources">
        <h5>📁 Found in {len(sources_list)} file(s):</h5>
        {"".join(f'<div class="source-item">{html_escape(s)}</div>' for s in sources_list[:10])}
        {f'<div class="source-item" style="color:#64748b;">... and {len(sources_list) - 10} more</div>' if len(sources_list) > 10 else ''}
      </div>
      ''' if sources_list else ''}
    </div>
"""
        return html

    def _build_api_domains(self, result: CrawlResult) -> str:
        """نمایش دامنه‌های API کشف شده"""
        if not result.api_domains:
            return '<div class="empty">No API domains discovered.</div>'
        
        html = ""
        for domain in sorted(result.api_domains):
            search_text = domain.lower()
            html += f"""
    <div class="finding api" data-search="{html_escape(search_text)}">
      <div class="finding-header">
        <span class="badge api">API Domain</span>
      </div>
      <div class="match">{html_escape(domain)}</div>
    </div>
"""
        return html