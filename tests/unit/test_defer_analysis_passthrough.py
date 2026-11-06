# cloudanix-web sends deferAnalysis: true on the service-group subruns of a run that has an
# "analysis" subrun. Each entry point copies only the request keys it names into the params that
# become config.params, so a key left out never reaches post_sync.defer_requested.
from unittest.mock import MagicMock
from unittest.mock import patch

import pytest

import app
import main

NEO4J_ENV = {"CDX_APP_NEO4J_URI": "bolt://x", "CDX_APP_NEO4J_USER": "u", "CDX_APP_NEO4J_PWD": "p"}


def _args(template_type, **extra):
    args = {
        "templateType": template_type,
        "eventId": "evt-1",
        "workspace": {"account_id": "ws", "id_string": "acct"},
        "services": [],
        "dc": "US",
    }
    args.update(extra)
    return args


@pytest.mark.parametrize("sent, expected", [({"deferAnalysis": True}, True), ({}, False)])
@pytest.mark.parametrize(
    "template_type, runner",
    [("AWSINVENTORYVIEWS", "run_aws"), ("AZUREINVENTORYVIEWS", "run_azure")],
)
def test_app_entry_points_pass_defer_analysis(template_type, runner, sent, expected):
    with patch.dict("os.environ", NEO4J_ENV), \
            patch("app.get_auth_creds", return_value={}), \
            patch("app.publish_response"), \
            patch(f"app.cartography.cli.{runner}", return_value={"status": "success"}) as run:
        app.process_request(MagicMock(), _args(template_type, **sent))

    assert run.call_args.args[0]["params"]["deferAnalysis"] is expected


@pytest.mark.parametrize("sent, expected", [({"deferAnalysis": True}, True), ({}, False)])
@pytest.mark.parametrize(
    "handler, runner, extra",
    [
        ("gcp_process_request", "run_gcp", {"accountEmail": "sa@x"}),
        ("oci_process_request", "run_oci", {}),
    ],
)
def test_main_entry_points_pass_defer_analysis(handler, runner, extra, sent, expected):
    with patch.dict("os.environ", {"CDX_TOKEN_URI": "https://x", "OCI_CONFIG": "{}"}), \
            patch("main.publish_response"), \
            patch(f"main.cartography.cli.{runner}", return_value={"status": "success"}) as run:
        getattr(main, handler)(MagicMock(), _args("X", **extra, **sent))

    assert run.call_args.args[0]["params"]["deferAnalysis"] is expected
