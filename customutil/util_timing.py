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

def test_timing_leaks(proj, cfg, state, branching, bound=10, epsilon_threshold=0, record_procedures=None):
    if not record_procedures:
        record_procedures = [("sleep", None)]

    start_states = [state]
    simgr = proj.factory.simgr(state)
    if not state.addr == branching.node.block.addr:
        simgr.explore(find=branching.node.addr, num_find=sys.maxsize)
        if len(simgr.found) < 1:
            raise Exception("Could not find branching location")
        start_states = simgr.found

    hook_addrs = []
    for record_procedure in record_procedures:
        proc_name = record_procedure[0]
        proc_addr = util_information.get_sim_proc_addr(proj, proc_name)
        if proc_addr:
            proc = proj._sim_procedures[proc_addr]
            proc_wrapper_funcs = util_information.get_sim_proc_function_wrapper_addrs(proj, proc_name)
            for wrap_addr in proc_wrapper_funcs:
                args = proc.cc.args if not record_procedure[1] else record_procedure[1]
                proj.hook(wrap_addr, lambda s: procedure_hook(proj, s, proc, args))
                hook_addrs.append(wrap_addr)

    leaks = []
    for start_state in start_states:
        progress = start_state.posix.dumps(1)
        simgr = proj.factory.simgr(start_state)
        simgr.use_technique(angr.exploration_techniques.LoopSeer(cfg=cfg, bound=bound, limit_concrete_loops=True))
        
        start_state.register_plugin(ProcedureRecordPlugin.NAME, ProcedureRecordPlugin({}))
        simgr.run()
        states = simgr.deadended + (simgr.spinning if hasattr(simgr, 'spinning') else [])

        for timed_procedure in record_procedures:
            res = get_procedure_diff_acc(states, timed_procedure[0])
            if res:
                leaks.append(TimingProcedureLeakProof(branching, proc, res[0], res[1], res[2], res[3]))

        (min_state, min, max_state, max) = get_min_max(states)
        if min and abs(max-min) > epsilon_threshold:
            leaks.append(TimingEpsilonLeakProof(branching, min_state, min, max_state, max))
    
    for addr in hook_addrs:
        proj.unhook(addr)

    return leaks

def procedure_hook(proj, state, procedure, arg_regs):
    plugin = state.plugins[ProcedureRecordPlugin.NAME]
    call = {}
    for arg_reg in arg_regs:
        offset, size = proj.arch.registers[arg_reg.reg_name]
        reg = state.registers.load(offset, size)
        val = state.solver.eval(reg)
        call[arg_reg.reg_name] = val
    key = procedure.display_name
    record = ProcedureRecord(call, state.history.block_count)
    plugin.map.setdefault(key, []).append(record)

def has_post_progress(proj, state):
    progress = state.posix.dumps(1)
    simgr = proj.factory.simgr(state)
    simgr.explore(find=lambda s: len(s.posix.dumps(1)) > len(progress), num_find=1)
    return simgr.found and len(simgr.found) > 0

def get_post_progress_state(proj, state):
    progress = state.posix.dumps(1)
    simgr = proj.factory.simgr(state)
    simgr.explore(find=lambda s: len(s.posix.dumps(1)) > len(progress), num_find=1)
    return simgr.found[0] if len(simgr.found) > 0 else None

def get_procedure_diff_acc(states, procedure_name):
    comp_acc_tup = None
    for state in states:
        plugin = state.plugins[ProcedureRecordPlugin.NAME]
        calls = plugin.map[procedure_name] if procedure_name in plugin.map else []
        acc_call = {}
        for call in calls:
            for k in call:
                if not k in acc_call:
                    acc_call[k] = 0
                acc_call[k] += call[k]
        if comp_acc_tup:
            for k in list(acc_call.keys()) + list(comp_acc_tup[0].keys()):
                if not k in acc_call or\
                    not k in comp_acc_tup[0] or\
                    acc_call[k] != comp_acc_tup[0][k]:
                    return (state, calls, comp_acc_tup[2], comp_acc_tup[1])
        else:
            comp_acc_tup = (acc_call, calls, state)
    return None

def get_min_max(states):
    state_ins_tup = list(map(lambda s: (s, get_lineage_instruction_count(s)), states))
    min = None
    max = None
    for tup in state_ins_tup:
        if (not min) or tup[1] < min[1]:
            min = tup
        if (not max) or tup[1] > max[1]:
            max = tup
    return (min[0] if min else None,\
            min[1] if min else None,\
            max[0] if max else None,\
            max[1] if max else None)

def get_lineage_instruction_count(state):
    count = 0
    for his in state.history.lineage:
        if his.addr:
            count += len(state.block(his.addr).instruction_addrs)
    return count

class ProcedureRecord:
    def __init__(self, call, depth):
        self.call = call
        self.depth = depth

class ProcedureRecordPlugin(angr.SimStatePlugin):
    NAME = 'procedure_record_plugin'

    def __init__(self, map):
        super(ProcedureRecordPlugin, self).__init__()
        self.map = copy.deepcopy(map)

    @angr.SimStatePlugin.memo
    def copy(self, memo):
        return ProcedureRecordPlugin(self.map)

class TimingProcedureLeakProof:
    def __init__(self, branching, procedure, state1, calls1, state2, calls2):
        self.branching = branching
        self.procedure = procedure
        self.state1 = state1
        self.calls1 = calls1
        self.state2 = state2
        self.calls2 = calls2

    def __repr__(self):
        return "<TimingProcedureLeakProof @ branching: " + str(hex(self.branching.node.block.addr)) + ", sim_proc: " + self.procedure.display_name + ", calls_left: " + str(self.calls1) + ", calls_right: " + str(self.calls2) + ">"

class TimingEpsilonLeakProof:
    def __init__(self, branching, state1, ins_count1, state2, ins_count2):
        self.branching = branching
        self.state1 = state1
        self.ins_count1 = ins_count1
        self.state2 = state2
        self.ins_count2 = ins_count2

    def __repr__(self):
        return "<TimingEpsilonLeakProof @ branching: " + str(hex(self.branching.node.block.addr)) + ", eps: " + str(abs(self.ins_count2 - self.ins_count1)) + ">"