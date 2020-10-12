#!/usr/bin/env python3
"""
gnu-pass export

Raw export of passwords managed by gnu passwordstore: https://www.passwordstore.org/

Depends on gitpython and gpg-python
"""


import os
import sys
import time
import typing

import git
import gnupg

_PASSWORD_STORE_ROOT = os.path.expanduser("~/.password-store/")

_GPG = None


def _gpg() -> gnupg.GPG:
    """Singleton for gpg instance"""
    global _GPG
    if _GPG is None:
        _GPG = gnupg.GPG()
    return _GPG


def _version_info(path: str = _PASSWORD_STORE_ROOT) -> str:
    repo = git.Repo(path)
    sha = repo.heads.master.commit.hexsha
    t = repo.heads.master.commit.committed_date
    timestamp = time.asctime(time.gmtime(t))
    return f"""commit sha: {sha}
last commit: {timestamp}

"""


def _crawl_password_store(path: str = _PASSWORD_STORE_ROOT) -> typing.List[str]:
    """Crawl password store root and find all encrypted files"""
    result = []
    for root, dirs, files in os.walk(path):
        for f in files:
            ext = os.path.splitext(f)[1]
            if ext == ".gpg":
                result.append(os.path.join(root, f))
    return result


def _title(path: str, root: str = _PASSWORD_STORE_ROOT) -> str:
    common = os.path.commonpath((root, path))
    remainder = path[len(common) :].lstrip("/")
    return os.path.splitext(remainder)[0]


def _decrypt(filename: str) -> typing.Tuple[str, str]:
    """Decrypt and format contents for encrypted file"""
    with open(filename, "rb") as fh:
        decrypted = _gpg().decrypt_file(fh)
    return decrypted.data.decode()


def main():
    sys.stdout.write("# GNU pass dump\n")
    sys.stdout.write(_version_info())
    files = _crawl_password_store()
    files = sorted(files, key=_title)
    for filename in files:
        title = _title(filename)
        plaintext = _decrypt(filename)
        plaintext = "\n".join(" " * 4 + line for line in plaintext.splitlines())
        sys.stdout.write(
            f"""# {title}

{plaintext}

"""
        )


if __name__ == "__main__":
    sys.exit(main())
