"""Link README workflow badges to a GitHub repository without publishing anything."""
import argparse
import re
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
START = '<!-- badges:start -->'
END = '<!-- badges:end -->'


def repository_name(value):
    value = value.strip()
    if value.startswith('https://'):
        url = urlsplit(value)
        if url.netloc != 'github.com' or url.query or url.fragment:
            raise ValueError('Eine GitHub-URL ohne Parameter oder OWNER/REPO angeben')
        value = url.path.strip('/')
    elif value.startswith('git@github.com:'):
        value = value[len('git@github.com:'):].rstrip('/')
    if value.endswith('.git'):
        value = value[:-4]
    if not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9_.-]{1,100}', value):
        raise ValueError('Repository im Format OWNER/REPO angeben')
    if value.split('/')[1] in ('.', '..'):
        raise ValueError('Ungültiger Repository-Name')
    return value


def badge_block(repository):
    base = f'https://github.com/{repository}/actions/workflows'
    return '\n'.join([
        START,
        f'[![CI]({base}/ci.yml/badge.svg)]({base}/ci.yml)',
        f'[![Docker und Browser]({base}/docker.yml/badge.svg)]({base}/docker.yml)',
        f'[![Lint]({base}/lint.yml/badge.svg)]({base}/lint.yml)',
        f'[![Security]({base}/security.yml/badge.svg)]({base}/security.yml)',
        f'[![Secret Scan]({base}/secrets.yml/badge.svg)]({base}/secrets.yml)',
        f'[![Dependabot-Konfiguration]({base}/dependabot.yml/badge.svg)]({base}/dependabot.yml)',
        '![Python 3.14](docs/badges/python.svg)',
        '![Lokale UniFi API](docs/badges/local-api.svg)',
        END,
    ])


def update_readme(text, repository):
    if text.count(START) != 1 or text.count(END) != 1 or text.index(START) >= text.index(END):
        raise ValueError('README muss genau einen vollständigen badges:start/badges:end-Block enthalten')
    first, last = text.index(START), text.index(END) + len(END)
    return text[:first] + badge_block(repository_name(repository)) + text[last:]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('repository', help='OWNER/REPO oder https://github.com/OWNER/REPO')
    args = parser.parse_args()
    path = ROOT / 'README.md'
    try:
        updated = update_readme(path.read_text(encoding='utf-8'), args.repository)
    except ValueError as error:
        parser.error(str(error))
    path.write_text(updated, encoding='utf-8')
    print('README-Status-Badges aktualisiert; keine Daten an GitHub übertragen.')


if __name__ == '__main__':
    main()
