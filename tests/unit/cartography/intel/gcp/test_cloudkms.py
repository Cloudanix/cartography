from unittest.mock import MagicMock

from googleapiclient.errors import HttpError

import cartography.intel.gcp.cloudkms

KEY = 'projects/p1/locations/global/keyRings/ring/cryptoKeys/key'


def _kms(response=None, error=None):
    kms = MagicMock()
    request = kms.projects.return_value.locations.return_value.keyRings.return_value.cryptoKeys.return_value \
        .getIamPolicy.return_value
    if error:
        request.execute.side_effect = error
    else:
        request.execute.return_value = response
    return kms


def test_crypto_key_policy_bindings_are_read_per_key():
    kms = _kms({'bindings': [{'role': 'roles/cloudkms.cryptoKeyEncrypterDecrypter', 'members': ['allUsers']}]})

    bindings = cartography.intel.gcp.cloudkms.get_crypto_key_policy_bindings(kms, {'id': KEY, 'name': KEY}, 'p1')

    assert bindings == [{'role': 'roles/cloudkms.cryptoKeyEncrypterDecrypter', 'members': ['allUsers']}]
    kms.projects.return_value.locations.return_value.keyRings.return_value.cryptoKeys.return_value \
        .getIamPolicy.assert_called_once_with(resource=KEY)
    rows = cartography.intel.gcp.cloudkms.transform_crypto_key_policy_bindings(bindings, KEY, 'p1')
    assert rows[0]['id'] == f'projects/p1/cryptokey/{KEY}/role/roles/cloudkms.cryptoKeyEncrypterDecrypter'


def test_crypto_key_policy_bindings_skip_a_key_we_may_not_read():
    denied = HttpError(
        MagicMock(status=403), b'{"error": {"code": 403, "status": "PERMISSION_DENIED", "message": "x"}}',
    )

    assert cartography.intel.gcp.cloudkms.get_crypto_key_policy_bindings(
        _kms(error=denied), {'id': KEY, 'name': KEY}, 'p1',
    ) == []
