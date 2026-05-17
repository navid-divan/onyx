#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import sys
import time
from typing import Dict, List

CURRENT_DIRECTORY = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIRECTORY not in sys.path:
    sys.path.insert(0, CURRENT_DIRECTORY)

from benchmark import build_report, collect_platform_information, print_phase_timing, print_section_header
from bulletin import BulletinBoard
from fake import FakingProcedure
from parameters import describe_post_quantum_parameters, production_parameters, quick_parameters, SystemParameters
from primitives.samplers import sample_uniform_integer
from register import Registrar
from setup import SetupAuthority
from tally import TallyAuthority
from valid import BallotValidator
from verify import AuditVerifier
from vote import VotingClient
from utils import TimingTracker


def parse_arguments() -> argparse.Namespace:
    argument_parser = argparse.ArgumentParser(
        description="Onyx Post-Quantum Persistent Coercion-Resistant Voting System"
    )
    argument_parser.add_argument(
        "--mode",
        choices=["quick", "production"],
        default="quick",
        help="Parameter regime (quick uses smaller dimensions; production targets concrete security)",
    )
    argument_parser.add_argument(
        "--voters",
        type=int,
        default=None,
        help="Override the configured number of voters",
    )
    argument_parser.add_argument(
        "--candidates",
        type=int,
        default=None,
        help="Override the configured number of candidates",
    )
    argument_parser.add_argument(
        "--json",
        action="store_true",
        help="Print JSON benchmark report at the end",
    )
    return argument_parser.parse_args()


def load_parameters(mode: str, voter_override: int, candidate_override: int) -> SystemParameters:
    if mode == "production":
        base = production_parameters()
    else:
        base = quick_parameters()
    from dataclasses import replace
    election = base.election
    election = replace(
        election,
        number_of_voters=voter_override if voter_override is not None else election.number_of_voters,
        number_of_candidates=candidate_override if candidate_override is not None else election.number_of_candidates,
    )
    return replace(base, election=election)


def run_protocol(parameters: SystemParameters, tracker: TimingTracker) -> Dict[str, object]:
    # print_section_header("Onyx: Post-Quantum Persistent Coercion-Resistant Voting")
    print(describe_post_quantum_parameters(parameters))
    print("")
    bulletin_board = BulletinBoard()
    with tracker.measure("Setup"):
        setup_authority = SetupAuthority(parameters)
        setup_artifacts = setup_authority.run_setup()
        bulletin_board.post("public_parameters", setup_artifacts.public_parameters)
    print_phase_timing("Setup", tracker.get("Setup"))
    with tracker.measure("Register"):
        registrar = Registrar(parameters, setup_artifacts)
        registration_record, voter_states = registrar.register_all_voters()
        bulletin_board.post("registration_roster", registration_record)
    print_phase_timing("Register", tracker.get("Register"))
    voting_client = VotingClient(
        parameters=parameters,
        dfhe=setup_artifacts.deniable_fhe,
        crs=setup_artifacts.public_parameters.nizk_crs,
    )
    cast_states = []
    candidate_pool = list(range(1, parameters.election.number_of_candidates + 1))
    with tracker.measure("Vote"):
        for voter_index, voter_state in enumerate(voter_states):
            chosen_candidate = candidate_pool[voter_index % len(candidate_pool)]
            local_state = voting_client.cast_ballot(chosen_candidate, voter_state)
            cast_states.append(local_state)
    print_phase_timing("Vote", tracker.get("Vote"))
    validator = BallotValidator(setup_artifacts.public_parameters.nizk_crs)
    accepted_ballots = []
    with tracker.measure("Valid"):
        for local_state in cast_states:
            ballot = local_state.ballot
            if validator.validate(ballot, bulletin_board):
                accepted_ballots.append(ballot)
                bulletin_board.post("ballot", ballot)
    print_phase_timing("Valid", tracker.get("Valid"))
    faker = FakingProcedure(
        dfhe=setup_artifacts.deniable_fhe,
        crs=setup_artifacts.public_parameters.nizk_crs,
        trapdoor=setup_artifacts.equivocation_trapdoor,
    )
    with tracker.measure("Fake"):
        coerced_voter_index = 0
        if len(cast_states) > 0:
            coerced_state = cast_states[coerced_voter_index]
            target_vote = candidate_pool[(coerced_voter_index + 1) % len(candidate_pool)]
            target_credential = (coerced_state.credential_value + 1) % parameters.dfhe.ring.plaintext_modulus
            faker.fake_vote(
                coerced_state,
                target_vote,
                target_credential,
                setup_artifacts.public_parameters,
            )
    print_phase_timing("Fake", tracker.get("Fake"))
    tally_authority = TallyAuthority(parameters, setup_artifacts)
    with tracker.measure("Tally"):
        tally_result = tally_authority.execute(accepted_ballots, registration_record)
        bulletin_board.post("tally_result", tally_result.candidate_totals)
    print_phase_timing("Tally", tracker.get("Tally"))
    verifier = AuditVerifier(parameters, setup_artifacts)
    with tracker.measure("Verify"):
        verification_outcome = verifier.verify_all(bulletin_board, accepted_ballots, tally_result)
    print_phase_timing("Verify", tracker.get("Verify"))
    print("-" * 64)
    print(f"Bulletin board entries: {len(bulletin_board.entries)}")
    print(f"Accepted ballots:        {len(accepted_ballots)}")
    print(f"Verification outcome:    {'OK' if verification_outcome else 'FAILED'}")
    print(f"Candidate tallies:       {tally_result.candidate_totals}")
    return {
        "candidate_totals": tally_result.candidate_totals,
        "verification_outcome": verification_outcome,
        "accepted_ballots": len(accepted_ballots),
        "bulletin_entries": len(bulletin_board.entries),
    }


def main() -> int:
    arguments = parse_arguments()
    parameters = load_parameters(arguments.mode, arguments.voters, arguments.candidates)
    tracker = TimingTracker()
    started_at = time.perf_counter()
    metadata = run_protocol(parameters, tracker)
    finished_at = time.perf_counter()
    elapsed_total = finished_at - started_at
    print("-" * 64)
    print(f"Wall-clock total: {elapsed_total:.4f} s")
    print("-" * 64)
    # print("Per-phase report:")
    # print(tracker.report())
    if arguments.json:
        report = build_report(tracker, metadata)
        print("-" * 64)
        print("JSON report:")
        print(report.to_json())
    return 0


if __name__ == "__main__":
    sys.exit(main())
