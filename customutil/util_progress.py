import angr
import angr.analyses.reaching_definitions.dep_graph as dep_graph
from angrutils import *
import matplotlib.pyplot as plt
import networkx as nx
import pydot
import copy
import sys
from customutil import util_out, util_information
from networkx.drawing.nx_pydot import graphviz_layout

#Returns ProgressLeakProof if a observable diff exists through branching
#TODO: Merging + pruning of states accumulated from loop iterations
#TODO: When finding proof state, consider that we might reach another infinite loop (create approx inf loop list from util.termination)
def test_observer_diff(proj, cfg, state, branching, bound=10):
    start_states = [state]
    if not state.addr == branching.node.block.addr:
        simgr = proj.factory.simgr(state)
        simgr.explore(find=branching.node.addr)
        if len(simgr.found) < 1:
            raise Exception("Could not find branching location")
        start_states = simgr.found
    for start_state in start_states:
        simgr = proj.factory.simgr(start_state)
        simgr.use_technique(angr.exploration_techniques.LoopSeer(cfg=cfg, bound=bound, limit_concrete_loops=True))
        simgr.run()
        diff = test_observer_diff_simgr(simgr.deadended)#simgr.found)
        if diff:
            return ProgressLeakProof(branching, diff[0], diff[1])
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
# def init_progress_recording(proj, state, subject_addrs):
#     for subject_addr in subject_addrs:
#         proj.hook(subject_addr, lambda s: procedure_hook(proj, s, proc, proc.cc.args))
#     state.register_plugin(ProgressRecordPlugin.NAME, ProgressRecordPlugin({}))

# def procedure_hook(proj, state, arg_regs):
#     plugin = state.plugins[ProcedureRecordPlugin.NAME]
#     call = []
#     for arg_reg in arg_regs:
#         offset, size = proj.arch.registers[arg_reg.reg_name]
#         reg = state.registers.load(offset, size)
#         val = state.solver.eval(reg)
#         call.append(reg,val)
#     plugin.records.extend(call)

def PutsProgressFunction(knowledge_base):
    return ProgressFunction('puts',None,std_out_progress,knowledge_base=knowledge_base)

def PrintfProgressFunction(knowledge_base):
    return ProgressFunction('printf',None,std_out_progress,knowledge_base=knowledge_base)

def std_out_progress(pre_state, post_state):
        pre = pre_state.posix.dumps(1).decode('UTF-8')
        post = post_state.posix.dumps(1).decode('UTF-8')
        ind = post.index(pre)
        return post[ind:]

class ProgressFunction:
    def __init__(self, name, registers, progress_delegate, knowledge_base=None, addrs=None):
        if not knowledge_base and not addrs:
            raise Exception('Must have either knowledge_base or addrs!')
        if not addrs:
            self.addrs = util_information.find_addrs_of_function(knowledge_base,name)
        else:
            self.addrs = addrs
        self.name = name
        self.registers = registers
        self.progress_delegate = progress_delegate

class ProgressRecord:
    def __init__(self, obj, depth, addr, sc):
        self.obj = obj
        self.depth = depth
        self.addr = addr
        self.sc = sc

class ProgressRecordPlugin(angr.SimStatePlugin):
    NAME = 'progress_record_plugin'

    def __init__(self, records, callname, callstate):
        super(ProgressRecordPlugin, self).__init__()
        self.records = copy.deepcopy(records)
        self.callfunction = None
        self.callstate = callstate

    @angr.SimStatePlugin.memo
    def copy(self, memo):
        return ProgressRecordPlugin(self.records, self.callfunction, self.callstate)

class ProgressLeakProof:
    def __init__(self, branching, state1, state2):
        self.branching = branching
        self.state1 = state1
        self.state2 = state2
    
    def __repr__(self):
        return "<ProgressLeakProof @ branching: " + str(hex(self.branching.node.block.addr)) + ", state1: " + str(self.state1.posix.dumps(1)) + ", state2: " + str(self.state2.posix.dumps(1)) + ">"