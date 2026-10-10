from unittest.mock import MagicMock
from unittest.mock import patch

import main


def _params(**overrides):
    params = {
        "templateType": "BITBUCKETINVENTORYVIEWS",
        "eventId": "evt-1",
        "workspace": {"account_id": "ws", "id_string": "acct", "data_center": "US"},
        "services": [],
    }
    params.update(overrides)
    return params


@patch("main.publish_response")
@patch("main.cartography.cli.run_bitbucket")
def test_uses_only_access_token(run_bitbucket, _publish):
    run_bitbucket.return_value = {"status": "success"}

    params = _params(accessToken="at-1", refreshToken="rt", workspaceAccessToken="wat")
    main.bitbucket_process_request(MagicMock(), params)

    body = run_bitbucket.call_args.args[0]
    assert body["bitbucket"] == {"access_token": "at-1"}


@patch("main.publish_response")
@patch("main.cartography.cli.run_bitbucket")
def test_missing_access_token_fails_without_fallback_or_sync(run_bitbucket, publish):
    # workspaceAccessToken / refreshToken must not be used as a fallback.
    result = main.bitbucket_process_request(MagicMock(), _params(workspaceAccessToken="wat", refreshToken="rt"))

    assert result["status"] == "failure"
    assert result["retry"] is False
    run_bitbucket.assert_not_called()
    resp = publish.call_args.args[2]
    assert resp["status"] == "failure"
    assert "accessToken" in resp["message"]


def test_no_backend_refresh_helper():
    assert not hasattr(main, "get_bitbucket_access_token")
