from urllib.parse import urlparse
from models import CrawlResult, InjectionTarget
from analyzers.page_analyzer import GENERAL_JUNK_PARAMS


class InjectionTargetExtractor:
    def extract(self, result: CrawlResult) -> list[InjectionTarget]:
        targets = []
        seen = set()
        url_depth_map = getattr(result, 'url_depth_map', {})

        url_targets = self._extract_url_params(result.all_parameters, seen, url_depth_map)
        targets.extend(url_targets)

        form_targets = self._extract_form_inputs(result.all_forms, seen, url_depth_map)
        targets.extend(form_targets)

        return targets

    def _get_depth(self, url: str, url_depth_map: dict) -> int:
        if url in url_depth_map:
            return url_depth_map[url]
        # fuzzy match — بدون query string
        base = url.split('?')[0].rstrip('/')
        for k, v in url_depth_map.items():
            if k.split('?')[0].rstrip('/') == base:
                return v
        return 0

    def _extract_url_params(self, parameters: list, seen: set, url_depth_map: dict) -> list[InjectionTarget]:
        targets = []
        for param in parameters:
            p_dict = param.to_dict() if hasattr(param, 'to_dict') else param
            source_url = p_dict.get('source_url', '')
            param_name = p_dict.get('name', '')

            if not param_name or not source_url:
                continue
            if param_name.lower() in GENERAL_JUNK_PARAMS:
                continue

            url_path = urlparse(source_url).path
            key = (url_path, param_name)
            if key in seen:
                continue
            seen.add(key)

            depth = self._get_depth(source_url, url_depth_map)

            targets.append(InjectionTarget(
                target_type="url_param",
                url=source_url,
                method="GET",
                param_name=param_name,
                param_location="query",
                sample_value=p_dict.get('sample_value', ''),
                content_type="N/A",
                crawl_depth=depth,
            ))
        return targets

    def _extract_form_inputs(self, forms: list, seen: set, url_depth_map: dict) -> list[InjectionTarget]:
        targets = []
        skip_types = {'submit', 'button', 'reset', 'image', 'hidden'}

        for form in forms:
            f_dict = form.to_dict() if hasattr(form, 'to_dict') else form

            action  = f_dict.get('action', '')
            method  = f_dict.get('method', 'GET').upper()
            title   = f_dict.get('title', 'Unknown Form')
            ct      = f_dict.get('content_type', 'application/x-www-form-urlencoded')

            if not action:
                continue

            action_path = urlparse(action).path

            # همه فیلدهای قابل inject این فرم رو جمع می‌کنیم
            # تا بعداً scanner بتونه اونایی که target نیستن رو با مقدار تستی پر کنه
            all_injectable = []
            for inp in f_dict.get('inputs', []):
                iname = inp.get('name', '')
                itype = inp.get('type', 'text').lower()
                if not iname or itype in skip_types:
                    continue
                all_injectable.append({
                    'name':  iname,
                    'type':  itype,
                    'value': inp.get('value', ''),
                    'hints': ' '.join([
                        iname,
                        inp.get('id', ''),
                        inp.get('placeholder', ''),
                        inp.get('autocomplete', ''),
                        itype,
                    ]).lower(),
                })

            source_url = f_dict.get('source_url', action)
            depth = self._get_depth(source_url, url_depth_map)

            for field in all_injectable:
                fname = field['name']

                if fname.lower() in GENERAL_JUNK_PARAMS:
                    continue

                key = (action_path, fname)
                if key in seen:
                    continue
                seen.add(key)

                sibling_fields = [f for f in all_injectable if f['name'] != fname]

                if method == "GET":
                    targets.append(InjectionTarget(
                        target_type="url_param",
                        url=action,
                        method="GET",
                        param_name=fname,
                        param_location="query",
                        sample_value=field['value'],
                        content_type="N/A",
                        form_title=title,
                        form_fields=sibling_fields,
                        form_page_url=source_url,
                        crawl_depth=depth,
                    ))
                else:
                    targets.append(InjectionTarget(
                        target_type="form_input",
                        url=action,
                        method=method,
                        param_name=fname,
                        param_location="body",
                        sample_value=field['value'],
                        content_type=ct,
                        form_title=title,
                        form_fields=sibling_fields,
                        form_page_url=source_url,
                        crawl_depth=depth,
                    ))

        return targets