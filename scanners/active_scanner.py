import json
from typing import Optional
from urllib.parse import urljoin, urlparse
import httpx
from models import Finding
from scanners.base import BaseScanner


class ActiveScanner(BaseScanner):
    name = "active"
    description = "HTTP status check for sensitive paths"

    def __init__(self, base_url: str, dry_run: bool = True, rate_limit: float = 0.5):
        self.base_url = base_url
        self.dry_run = dry_run
        self.rate_limit = rate_limit

    async def scan(self, findings: list, *args, **kwargs) -> list:
        results = []
        
        if not findings:
            print("  [!] No findings to scan.")
            return results

        print(f"\n  [*] Starting active scan on {len(findings)} findings...")
        
        if self.dry_run:
            print(f"  [🔍] DRY-RUN MODE: Only listing URLs, not sending requests")
        else:
            print(f"  [⚠️] LIVE MODE: Sending actual HTTP requests")

        for idx, finding in enumerate(findings, 1):
            if not hasattr(finding, 'match') or not finding.match:
                continue
            
            original_match = finding.match
            
            if original_match.startswith('this.') or original_match.startswith('Ie.'):
                print(f"\n  [{idx}/{len(findings)}] Skipping invalid match: {original_match}")
                continue
            
            if original_match.startswith('http://') or original_match.startswith('https://'):
                url = original_match
            else:
                url = urljoin(self.base_url, original_match)
            
            print(f"\n  [{idx}/{len(findings)}] Testing: {url}")
            print(f"      Original match: {original_match}")
            print(f"      Category: {finding.category}")
            
            if self.dry_run:
                print(f"      [🔍] DRY-RUN: Would test this URL")
                result = self._build_result(finding, url, None, "DRY-RUN - Not tested")
                results.append(result)
            else:
                try:
                    async with httpx.AsyncClient(
                        verify=False,
                        timeout=15.0,
                        follow_redirects=True,
                        headers={
                            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0"
                        }
                    ) as client:
                        response = await client.get(url)
                        status = response.status_code
                        status_text = response.reason_phrase
                        
                        print(f"      [✓] Status: {status} {status_text}")
                        
                        result = self._build_result(finding, url, status, status_text)
                        results.append(result)
                        
                except Exception as e:
                    print(f"      [!] Error: {str(e)[:60]}")
                    result = self._build_result(finding, url, None, f"Error: {str(e)[:50]}")
                    results.append(result)
            
            import asyncio
            await asyncio.sleep(self.rate_limit)

        print(f"\n  [+] Active scan complete: {len(results)} results")
        return results

    def _build_result(self, finding: Finding, url: str, status: Optional[int], status_text: str) -> dict:
        if status is None:
            final_severity = "INFO"
        elif status == 200:
            final_severity = finding.severity
        elif status == 403:
            final_severity = "LOW"
        elif status == 404:
            final_severity = "INFO"
        else:
            final_severity = "MEDIUM"

        return {
            "url": url,
            "original_match": finding.match,
            "category": finding.category,
            "base_severity": finding.severity,
            "status": status,
            "status_text": status_text,
            "final_severity": final_severity,
            "source_file": finding.source if hasattr(finding, 'source') else ""
        }