"""URL classification based on patterns, parameters, and extensions."""
import re
from typing import List, Set, Dict, Any


class URLClassifier:
    """Classify URLs into categories: xss, ssrf, redirect, api, js, etc."""
    
    # Parameter patterns for various vulnerabilities
    XSS_PARAMS = re.compile(r'(q|search|query|s|keyword|term|callback|input|msg|message|text|comment|name|value|page|sort|order|filter)$', re.I)
    SSRF_PARAMS = re.compile(r'(url|uri|link|src|source|dest|destination|host|domain|callback|fetch|load|path|file|document|redirect|return|next|goto)', re.I)
    REDIRECT_PARAMS = re.compile(r'(url|redirect|return|next|goto|out|path|dest|destination|redir|redirect_uri)', re.I)
    IDOR_PARAMS = re.compile(r'(id|user_id|account_id|profile_id|order_id|transaction_id|doc_id|file_id|post_id|article_id|product_id|customer_id)', re.I)
    
    # Path patterns
    API_PATHS = re.compile(r'/(api|v[0-9]+|graphql|rest|swagger|openapi|rpc)/', re.I)
    ADMIN_PATHS = re.compile(r'/(admin|dashboard|console|manager|administrator|control|system|config|settings)', re.I)
    JS_PATHS = re.compile(r'\.js$|/js/|/javascript/|/static/js/', re.I)
    STATIC_EXT = re.compile(r'\.(css|png|jpg|jpeg|gif|ico|svg|woff|ttf|eot|pdf|zip|tar|gz)$', re.I)
    
    def classify_urls(self, urls: List[str], params: List[str], paths: List[str]) -> List[Dict[str, Any]]:
        """Classify each URL and return list with categories."""
        results = []
        for url in urls:
            categories = set()
            # Check path patterns
            if self.API_PATHS.search(url):
                categories.add("api")
            if self.ADMIN_PATHS.search(url):
                categories.add("admin")
            if self.JS_PATHS.search(url) or url.endswith('.js'):
                categories.add("js")
            if self.STATIC_EXT.search(url):
                categories.add("static")
            
            # Parameter-based classification
            # Extract query parameters from URL
            query_params = self._extract_params(url)
            for param in query_params:
                if self.XSS_PARAMS.match(param):
                    categories.add("xss")
                if self.SSRF_PARAMS.match(param):
                    categories.add("ssrf")
                if self.REDIRECT_PARAMS.match(param):
                    categories.add("redirect")
                if self.IDOR_PARAMS.match(param):
                    categories.add("idor")
            
            # If URL has any parameter, it's potential for injection
            if query_params and not categories:
                categories.add("parameterized")
            
            # Default
            if not categories:
                categories.add("other")
            
            results.append({
                "url": url,
                "categories": list(categories),
                "params": query_params
            })
        return results
    
    def _extract_params(self, url: str) -> List[str]:
        """Extract query parameter names from URL."""
        if '?' not in url:
            return []
        query_part = url.split('?', 1)[1]
        params = []
        for pair in query_part.split('&'):
            if '=' in pair:
                param_name = pair.split('=', 1)[0]
                params.append(param_name)
        return list(set(params))