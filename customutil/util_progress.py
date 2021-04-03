import angr
import angr.analyses.reaching_definitions.dep_graph as dep_graph
from angrutils import *
import matplotlib.pyplot as plt
import networkx as nx
import pydot
from customutil import util_out
from networkx.drawing.nx_pydot import graphviz_layout

#Returns ProgressLeakProof if a observable diff exists in branch
#TODO: Merging + pruning of states accumulated from loop iterations
#TODO: When finding proof state, consider that we might reach another infinite loop (create approx inf loop list from util.termination)
def test_observer_diff(proj, cfg, state, branch, bound=100):
    simgr = proj.factory.simgr(state)
    if not state.addr == branch.branch.block.addr:
        simgr.explore(find=branch.branch.addr)
        if len(simgr.found) < 1:
            raise Exception("Could not find branch location")
        simgr = proj.factory.simgr(simgr.found[0])
    simgr.use_technique(angr.exploration_techniques.LoopSeer(cfg=cfg, bound=bound, limit_concrete_loops=False))
    simgr.explore(find=branch.dominator.addr, num_find=bound*10) #num_find=bound+10; try to take all while detect inf loops
    diff = test_observer_diff_simgr(simgr)
    if diff:
        return ProgressLeakProof(branch, diff[0], diff[1])

    return None

def test_observer_diff_simgr(simgr):
    prev_state = None
    prev_val = None
    for found in simgr.found:
        val = found.posix.dumps(1)
        if prev_val == None or val == prev_val:
            prev_val = val
            prev_state = found
        else:
            return (prev_state, found)
    return None

class ProgressLeakProof:
    def __init__(self, branch, state1, state2):
        self.branch = branch
        self.state1 = state1
        self.state2 = state2
    
    def __repr__(self):
        return "<ProgressLeakProof @ branch: " + str(hex(self.branch.branch.block.addr)) + ", state1: " + str(self.state1.posix.dumps(1)) + ", state2: " + str(self.state2.posix.dumps(1)) + ">"