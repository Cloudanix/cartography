"""
Unit tests for uniform neo4j interactions in the bitbucket intel modules
(perf plan Phase 3 items 5+6).
"""
from unittest.mock import MagicMock

from cartography.intel.bitbucket import repositories

TEST_UPDATE_TAG = 123456789


class TestLoadLanguages:
    def test_batched_via_dictlist(self):
        session = MagicMock()
        langs = [{"primary_language": "python", "repo_id": "r1"}]

        repositories.load_languages(session, TEST_UPDATE_TAG, langs)

        session.run.assert_not_called()
        call = session.execute_write.call_args
        assert "UNWIND $DictList" in call.args[1]
        assert call.kwargs["DictList"] == langs

    def test_empty_list_writes_nothing(self):
        session = MagicMock()
        repositories.load_languages(session, TEST_UPDATE_TAG, [])
        session.execute_write.assert_not_called()


class TestUpdateRepoLastActivity:
    def test_goes_through_managed_tx(self):
        session = MagicMock()
        branches = [{"name": "main", "date": "2024-01-01T00:00:00+00:00"}]

        repositories._update_repo_last_activity(session, "r1", branches, "main")

        session.run.assert_not_called()
        session.execute_write.assert_called_once()

    def test_no_dates_no_write(self):
        session = MagicMock()

        repositories._update_repo_last_activity(session, "r1", [{"name": "main"}], "main")

        session.execute_write.assert_not_called()
        session.run.assert_not_called()
