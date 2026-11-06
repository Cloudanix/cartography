import threading

from cartography.graph import write_timer
from cartography.graph.session import Session
from unittest.mock import MagicMock


def test_total_starts_at_zero_per_thread():
    results = []

    def worker():
        results.append(write_timer.total())

    t = threading.Thread(target=worker)
    t.start()
    t.join()
    assert results == [0.0]


def test_add_accumulates():
    start = write_timer.total()
    write_timer.add(1.5)
    write_timer.add(0.5)
    assert write_timer.total() - start == 2.0


def test_timed_records_elapsed():
    start = write_timer.total()
    with write_timer.timed():
        pass
    assert write_timer.total() >= start


def test_timed_records_on_exception():
    start = write_timer.total()
    try:
        with write_timer.timed():
            raise ValueError("boom")
    except ValueError:
        pass
    assert write_timer.total() >= start


def test_threads_do_not_share_totals():
    write_timer.add(5.0)
    seen = []

    def worker():
        seen.append(write_timer.total())
        write_timer.add(1.0)
        seen.append(write_timer.total())

    t = threading.Thread(target=worker)
    t.start()
    t.join()
    assert seen == [0.0, 1.0]


def test_session_calls_feed_the_timer():
    session = Session(MagicMock())
    start = write_timer.total()

    session.run("RETURN 1")
    session.execute_write(MagicMock())
    session.execute_read(MagicMock())

    assert write_timer.total() > start
