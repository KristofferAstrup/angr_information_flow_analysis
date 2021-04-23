import angr
import angr.analyses.reaching_definitions.dep_graph as dep_graph
from angrutils import *
import matplotlib.pyplot as plt
import networkx as nx
import pydot
import sys
from customutil import util_out
from networkx.drawing.nx_pydot import graphviz_layout

#Returns ProgressLeakProof if a observable diff exists in branch
#TODO: Merging + pruning of states accumulated from loop iterations
#TODO: When finding proof state, consider that we might reach another infinite loop (create approx inf loop list from util.termination)
def test_observer_diff(proj, cfg, state, branch, bound=10):
    start_states = [state]
    if not state.addr == branch.branch.block.addr:
        simgr = proj.factory.simgr(state)
        simgr.explore(find=branch.branch.addr)
        if len(simgr.found) < 1:
            raise Exception("Could not find branch location")
        start_states = simgr.found
    for start_state in start_states:
        simgr = proj.factory.simgr(start_state)
        simgr.use_technique(angr.exploration_techniques.LoopSeer(cfg=cfg, bound=bound, limit_concrete_loops=True))
        simgr.run()
        diff = test_observer_diff_simgr(simgr.deadended)#simgr.found)
        if diff:
            return ProgressLeakProof(branch, diff[0], diff[1])
    return None

def test_observer_diff_simgr(states):
    prev_state = None
    prev_val = None
    for state in states:
        val = state.posix.dumps(1)
        if prev_val == None or val == prev_val:
            prev_val = val
            prev_state = state
        else:
            return (prev_state, state)
    return None

#not used atm
def init_progress_recording(proj, state, subject_addrs):
    for subject_addr in subject_addrs:
        proj.hook(subject_addr, lambda s: procedure_hook(proj, s, proc, proc.cc.args))
    state.register_plugin(ProgressRecordPlugin.NAME, ProgressRecordPlugin({}))

def procedure_hook(proj, state, arg_regs):
    plugin = state.plugins[ProcedureRecordPlugin.NAME]
    call = []
    for arg_reg in arg_regs:
        offset, size = proj.arch.registers[arg_reg.reg_name]
        reg = state.registers.load(offset, size)
        val = state.solver.eval(reg)
        call.append(reg,val)
    plugin.records.extend(call)

class ProgressRecordPlugin(angr.SimStatePlugin):
    NAME = 'progress_record_plugin'

    def __init__(self, records):
        super(ProgressRecordPlugin, self).__init__()
        self.records = copy.deepcopy(records)

    @angr.SimStatePlugin.memo
    def copy(self, memo):
        return ProgressRecordPlugin(self.records)

class ProgressLeakProof:
    def __init__(self, branch, state1, state2):
        self.branch = branch
        self.state1 = state1
        self.state2 = state2
    
    def __repr__(self):
        return "<ProgressLeakProof @ branch: " + str(hex(self.branch.branch.block.addr)) + ", state1: " + str(self.state1.posix.dumps(1)) + ", state2: " + str(self.state2.posix.dumps(1)) + ">"