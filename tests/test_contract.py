import copy
from uuid import uuid4

import pytest

from app.contract import create_defaults, deep_merge, default_wifi, redact, validate_patch, write_payload


def test_full_wlan_projection_keeps_documented_advanced_fields():
    value = default_wifi('Verwaltung', passphrase='secure-test-phrase')
    value.update({'id': str(uuid4()), 'metadata': {'origin': 'USER_DEFINED'},
                  'dtimPeriodByFrequencyGHzOverride': {'2.4': 3, '5': 3, '6': 3},
                  'basicDataRateKbpsByFrequencyGHz': {'2.4': 2000, '5': 6000},
                  'clientFilteringPolicy': {'action': 'ALLOW', 'macAddressFilter': ['aa:bb:cc:dd:ee:ff']},
                  'blackoutScheduleConfiguration': {'days': [{'type': 'TIME_RANGE', 'day': 'MON',
                      'timeRanges': [{'startTime': '22:00', 'endTime': '23:00'}]}]},
                  'broadcastingDeviceFilter': {'type': 'DEVICE_TAGS', 'deviceTagIds': [str(uuid4())]}})
    payload = write_payload('wifi', value)
    assert 'id' not in payload and 'metadata' not in payload
    assert payload['blackoutScheduleConfiguration'] == value['blackoutScheduleConfiguration']
    assert payload['clientFilteringPolicy'] == value['clientFilteringPolicy']
    assert value['id']


@pytest.mark.parametrize('patch', [
    {'enabled': 'false'}, {'enabled': 0}, {'name': 'ü' * 17}, {'name': '\x00SSID'},
    {'password': 'unrecognized'}, {'broadcastingFrequenciesGHz': [2.4, 2.4]},
    {'broadcastingFrequenciesGHz': [7]}, {'broadcastingFrequenciesGHz': [True]},
    {'dtimPeriodByFrequencyGHzOverride': {'2.4': 256}},
    {'securityConfiguration': {'type': 'WPA3', 'passphrase': 'secret-phrase'}},
    {'securityConfiguration': {'passphrase': '<redacted>'}},
    {'securityConfiguration': {'passphrase': '********'}},
    {'securityConfiguration': {'passphrase': 'short'}},
    {'network': {'type': 'SPECIFIC', 'networkId': 'not-a-uuid'}},
    {'clientFilteringPolicy': {'action': 'ALLOW', 'macAddressFilter': ['invalid']}},
    {'blackoutScheduleConfiguration': {'days': [{'type': 'TIME_RANGE', 'day': 'MON',
        'timeRanges': [{'startTime': '25:00', 'endTime': '12:00'}]}]}},
])
def test_invalid_nested_patch_is_rejected(patch):
    with pytest.raises(ValueError):
        validate_patch('wifi', patch)


@pytest.mark.parametrize('patch', [
    {'management': 'GATEWAY'}, {'management': 'SWITCH'}, {'vlanId': True},
    {'vlanId': 1}, {'vlanId': 4010}, {'vlanId': 0},
    {'ipv4Configuration': {}}, {'dhcpGuarding': {'trustedDhcpServerIpAddresses': ['bad']}},
])
def test_only_external_vlans_are_allowed(patch):
    with pytest.raises(ValueError):
        validate_patch('network', patch)


def test_vlan_defaults_and_default_network_protection():
    assert create_defaults('network', {'name': 'Verwaltungsnetz', 'vlanId': 100}) == {
        'name': 'Verwaltungsnetz', 'vlanId': 100, 'management': 'UNMANAGED', 'enabled': True}
    with pytest.raises(ValueError):
        write_payload('network', {'name': 'Default', 'vlanId': 1, 'management': 'UNMANAGED', 'enabled': True})
    with pytest.raises(ValueError):
        write_payload('network', {'name': 'Default', 'vlanId': 100, 'management': 'UNMANAGED', 'enabled': True, 'default': True})


def test_missing_secret_and_unknown_remote_fields_fail_closed():
    value = default_wifi('Verwaltung', passphrase='secret-test-phrase')
    for modification in ({'unfamiliarNewFeature': True}, {'securityConfiguration': {'type': 'WPA2_PERSONAL'}},
                         {'securityConfiguration': {'type': 'WPA2_PERSONAL', 'passphrase': '<redacted>'}}):
        with pytest.raises(ValueError):
            write_payload('wifi', value | modification)


@pytest.mark.parametrize('security_type', ['WPA2_PERSONAL', 'WPA3_PERSONAL', 'WPA2_WPA3_PERSONAL'])
def test_personal_security_modes_have_complete_defaults(security_type):
    value = default_wifi('Secure WLAN', security_type, 'secret-test-phrase')
    assert write_payload('wifi', value) == value
    if 'WPA3_PERSONAL' in security_type:
        assert value['securityConfiguration']['saeConfiguration']['syncTimeSeconds'] == 5


def test_enterprise_nested_radius_contract():
    radius = {'profileId': str(uuid4()), 'nasId': {'type': 'DERIVED', 'source': 'SITE_NAME'}}
    value = create_defaults('wifi', {'name': 'Enterprise', 'securityConfiguration': {
        'type': 'WPA3_ENTERPRISE', 'radiusConfiguration': radius, 'coaEnabled': True, 'securityMode': 'HIGH_SECURITY_192_BIT'}})
    assert value['securityConfiguration']['radiusConfiguration'] == radius
    with pytest.raises(ValueError):
        create_defaults('wifi', {'name': 'Enterprise', 'securityConfiguration': {
            'type': 'WPA3_ENTERPRISE', 'radiusConfiguration': radius | {'nasId': {'type': 'DERIVED', 'source': 'INVALID'}},
            'coaEnabled': True, 'securityMode': 'HIGH_SECURITY_192_BIT'}})


def test_creation_requires_explicit_security_and_6ghz_requires_wpa3():
    with pytest.raises(ValueError):
        create_defaults('wifi', {'name': 'SSID'})
    with pytest.raises(ValueError):
        create_defaults('wifi', {'name': 'SSID', 'broadcastingFrequenciesGHz': [6],
            'securityConfiguration': {'type': 'WPA2_PERSONAL', 'passphrase': 'secret-test-phrase'}})
    value = create_defaults('wifi', {'name': 'SSID', 'broadcastingFrequenciesGHz': [6],
        'securityConfiguration': {'type': 'WPA3_PERSONAL', 'passphrase': 'secret-test-phrase'}})
    assert value['broadcastingFrequenciesGHz'] == [6]


def test_deep_merge_preserves_fields_and_replaces_security_subtype():
    before = default_wifi('SSID', passphrase='previous-test-phrase')
    preserved = copy.deepcopy(before)
    merged = deep_merge(before, {'securityConfiguration': {'passphrase': 'updated-test-phrase'}, 'enabled': False})
    assert merged['securityConfiguration']['type'] == 'WPA2_PERSONAL'
    assert before == preserved
    switched = deep_merge(before, {'securityConfiguration': {'type': 'OPEN'}})
    assert switched['securityConfiguration'] == {'type': 'OPEN'}
    assert 'passphrase' not in switched['securityConfiguration']
    assert write_payload('wifi', switched)['securityConfiguration'] == {'type': 'OPEN'}


def test_secret_redaction_and_errors_do_not_expose_secret_values():
    value = {'passphrase': 'value1', 'nested': [{'radiusSecret': 'value2'}], 'api_key': 'value3',
             'bindPassword': 'value4', 'normal': 'kept'}
    redacted = redact(value)
    assert redacted['normal'] == 'kept'
    assert all(secret not in str(redacted) for secret in ('value1', 'value2', 'value3', 'value4'))
    assert value['passphrase'] == 'value1'
    with pytest.raises(ValueError) as error:
        validate_patch('wifi', {'securityConfiguration': {'passphrase': 's'}})
    assert str(error.value).endswith('ungültige Textlänge')


def test_unknown_kinds_and_delete_configuration_are_rejected():
    with pytest.raises(ValueError):
        validate_patch('firewall', {'name': 'x'})
    assert validate_patch('network', {}, operation='delete') == {}
    with pytest.raises(ValueError):
        validate_patch('network', {'enabled': False}, operation='delete')
