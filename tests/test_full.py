import os
import sys

CURRENT_DIRECTORY = os.path.dirname(os.path.abspath(__file__))
PARENT_DIRECTORY = os.path.dirname(CURRENT_DIRECTORY)
if PARENT_DIRECTORY not in sys.path:
    sys.path.insert(0, PARENT_DIRECTORY)

from parameters import quick_parameters
from run import run_protocol
from utils import TimingTracker


def test_full_protocol_quick() -> None:
    parameters = quick_parameters()
    tracker = TimingTracker()
    result = run_protocol(parameters, tracker)
    assert result["verification_outcome"] is True
    assert result["accepted_ballots"] == parameters.election.number_of_voters


if __name__ == "__main__":
    test_full_protocol_quick()
    print("protocol test passed.")
