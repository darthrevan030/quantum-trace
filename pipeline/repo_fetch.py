"""Validate and shallow-clone public GitHub/GitLab repositories without running their code."""

import os
import re
import subprocess
from urllib.parse import urlsplit


def repository_url(value):
    if not isinstance(value, str):
        raise ValueError("Enter a GitHub or GitLab HTTPS repository URL.")
    url = urlsplit(value.strip())
    parts = url.path.rstrip('/').removesuffix('.git').strip('/').split('/')
    if (url.scheme != 'https' or url.netloc not in {'github.com', 'gitlab.com'} or url.query or url.fragment
            or len(parts) < 2 or (url.netloc == 'github.com' and len(parts) != 2)
            or any(not re.fullmatch(r'[\w.-]+', part, re.ASCII) or part in {'.', '..', '-'} for part in parts)):
        raise ValueError("Use a repository-root HTTPS URL on github.com or gitlab.com, without credentials, ports, queries, or fragments.")
    return f"https://{url.netloc}/{'/'.join(parts)}.git", '/'.join(parts)


def clone(url, target, timeout=120):
    """Shallow-clone url into target with hooks, redirects and non-HTTPS protocols disabled."""
    environment = {**os.environ, 'GIT_TERMINAL_PROMPT': '0', 'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': os.devnull}
    result = subprocess.run(['git', '-c', f'core.hooksPath={os.devnull}', '-c', 'http.followRedirects=false',
                             '-c', 'protocol.allow=never', '-c', 'protocol.https.allow=always',
                             'clone', '--depth', '1', '--', url, str(target)],
                            capture_output=True, text=True, env=environment, timeout=timeout)
    if result.returncode:
        raise ValueError('Repository clone failed. Check that the repository is public and its URL is correct. ' + result.stderr[-600:])
