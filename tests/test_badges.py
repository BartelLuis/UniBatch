import pytest

from tools.configure_badges import END, START, repository_name, update_readme


@pytest.mark.parametrize('value', [
    'agency/unifi-batch', 'https://github.com/agency/unifi-batch',
    'https://github.com/agency/unifi-batch.git/', 'git@github.com:agency/unifi-batch.git',
])
def test_badge_repository_formats(value):
    assert repository_name(value) == 'agency/unifi-batch'


@pytest.mark.parametrize('value', [
    'https://example.org/agency/unifi-batch', 'https://github.com/agency/unifi-batch?token=secret',
    'https://user:secret@github.com/agency/unifi-batch', 'agency/../other', 'agency/..',
    'agency/repo#fragment', 'owner-only',
])
def test_invalid_badge_repository_is_rejected(value):
    with pytest.raises(ValueError):
        repository_name(value)


def test_badge_update_preserves_readme_and_is_idempotent():
    original = f'# Tool\n\n{START}\nlocal badges\n{END}\n\nBehördennetz\n'
    result = update_readme(original, 'agency/unifi-batch')
    assert result.startswith('# Tool\n\n') and result.endswith('\n\nBehördennetz\n')
    assert 'https://github.com/agency/unifi-batch/actions/workflows/ci.yml/badge.svg' in result
    assert 'https://github.com/agency/unifi-batch/actions/workflows/docker.yml/badge.svg' in result
    for workflow in ('lint', 'security', 'secrets', 'dependabot'):
        assert f'https://github.com/agency/unifi-batch/actions/workflows/{workflow}.yml/badge.svg' in result
    assert 'docs/badges/python.svg' in result and 'docs/badges/local-api.svg' in result
    assert update_readme(result, 'agency/unifi-batch') == result


@pytest.mark.parametrize('value', ['', END + START, START + END + START])
def test_missing_reversed_or_duplicate_badge_markers_are_rejected(value):
    with pytest.raises(ValueError):
        update_readme(value, 'agency/unifi-batch')
