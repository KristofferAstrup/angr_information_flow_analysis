import angr
import angr.analyses.reaching_definitions.dep_graph as dep_graph
from angrutils import *
import matplotlib.pyplot as plt
import networkx as nx
import pydot
from customutil import util_out
from networkx.drawing.nx_pydot import graphviz_layout

def test_timing_leak(proj, cfg, state, branch):
    #TODO: Check that state has progress already!
    simgr = proj.factory.simgr(state)
    if not state.addr == branch.branch.block.addr:
        simgr.explore(find=branch.branch.addr)
        if len(simgr.found) < 1:
            raise Exception("Could not find branch location")
        simgr = proj.factory.simgr(simgr.found[0])
    simgr.use_technique(angr.exploration_techniques.LoopSeer(cfg=cfg, bound=bound, limit_concrete_loops=False))
    simgr.explore(find=branch.dominator.addr, num_find=bound*10)
    post_progress_states = filter_has_post_progress(simgr.found)
    (min, min_state, max_state, max) = get_min_max_and_diff(post_progress_states)
    if abs(max-min) > 0:
        return TimingLeakProof(branch, min_state, min, max_state, max)
    return None

def filter_has_post_progress(states):
    #TODO: Return only states that have progress going forward (explore find earliest progress)
    return states

def get_min_max(states):
    #TODO: Map each state to a count of instructions by accumulating the history.lineage blocks instruction counts
    return (min_state, min, max_state, max)

class TimingLeakProof:
    def __init__(self, branch, state1, ins_count1, state2, ins_count2):
        self.branch = branch
        self.state1 = state1
        self.ins_count1 = ins_count1
        self.state2 = state2
        self.ins_count2 = ins_count2

    def __repr__(self):
        return "<ProgressLeakProof @ branch: " + str(hex(self.branch.branch.block.addr)) + ", state1: " + str(self.state1.posix.dumps(1)) + ", state2: " + str(self.state2.posix.dumps(1)) + ", diff: " + str(abs(self.ins_count2 - self.ins_count1)) + ">"