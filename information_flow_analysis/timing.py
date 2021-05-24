import angr
import angr.analyses.reaching_definitions.dep_graph as dep_graph
from angrutils import *
import matplotlib.pyplot as plt
import networkx as nx
import pydot
import copy
import sys
from information_flow_analysis import implicit, information, progress
from networkx.drawing.nx_pydot import graphviz_layout

def determine_timing_procedure_call_leaks(states):
    leaks = []
    for state in states:
        for progress_instance in state.plugins[progress.ProgressRecordPlugin.NAME].records:
            timing_interval = state.plugins[ProcedureRecordPlugin.NAME].map[progress_instance.index]
            if len(timing_interval.high_arg_calls) > 0:
                for high_arg_call in timing_interval.high_arg_calls:
                    leaks.append(TimingProcedureCallLeak(state, timing_interval))
    return leaks

def determine_timing_procedure_leak(states):
    for state_a in states:
        for state_b in states:
            if state_a == state_b:
                continue
            for branch_instance in state_a.plugins[implicit.BranchRecordPlugin.NAME].records:
                if not branch_instance in state_b.plugins[implicit.BranchRecordPlugin.NAME].records:
                    continue
                progress_a = immediate_progress(state_a, branch_instance)
                if not progress_a:
                    continue
                progress_b = immediate_progress(state_b, branch_instance)
                if not progress_b:
                    continue
                timing_interval_a = state_a.plugins[ProcedureRecordPlugin.NAME].map[progress_a.index] if progress_a else None
                timing_interval_b = state_b.plugins[ProcedureRecordPlugin.NAME].map[progress_b.index] if progress_b else None
                if calc_procedure_diff(timing_interval_a, timing_interval_b) > 0:
                    return TimingProcedureLeakProof(branch_instance, state_a, state_b, timing_interval_a, timing_interval_b)

def calc_procedure_diff(interval_a, interval_b):
    val_a = interval_a.acc if interval_a else 0
    val_b = interval_b.acc if interval_b else 0
    return abs(val_a - val_b)

def determine_timing_instruction_leak(states, ins_count_threshold):
    for state_a in states:
        for state_b in states:
            if state_a == state_b:
                continue
            for branch_instance in state_a.plugins[implicit.BranchRecordPlugin.NAME].records:
                if not branch_instance in state_b.plugins[implicit.BranchRecordPlugin.NAME].records:
                    continue
                progress_a = immediate_progress(state_a, branch_instance)
                if not progress_a:
                    continue
                progress_b = immediate_progress(state_b, branch_instance)
                if not progress_b:
                    continue
                timing_interval_a = state_a.plugins[ProcedureRecordPlugin.NAME].map[progress_a.index] if progress_a else None
                timing_interval_b = state_b.plugins[ProcedureRecordPlugin.NAME].map[progress_b.index] if progress_b else None
                if calc_ins_diff(timing_interval_a, timing_interval_b) > ins_count_threshold:
                    return TimingEpsilonLeakProof(branch_instance, state_a, state_b, timing_interval_a, timing_interval_b)

def calc_ins_diff(interval_a, interval_b):
    val_a = interval_a.ins_count if interval_a else 0
    val_b = interval_b.ins_count if interval_b else 0
    return abs(val_a - val_b)

def immediate_progress(state, branching):
    for prog in state.plugins[progress.ProgressRecordPlugin.NAME].records:
        if prog.depth < branching.depth:
            continue
        return prog
    return None

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
        proc_addr = information.get_sim_proc_addr(proj, proc_name)
        if proc_addr:
            proc = proj._sim_procedures[proc_addr]
            proc_wrapper_funcs = information.get_sim_proc_function_wrapper_addrs(proj, proc_name)
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

def get_history_high_instruction_count(state, termination_depth, high_block_map):
    high_ins_count = 0
    his = state.history
    while his.block_count > termination_depth:
        if his.addr in high_block_map:
            high_ins_count += len(high_block_map[his.addr].instruction_addrs)
        if not his.parent:
            break
        his = his.parent
    return high_ins_count

def SleepTimingFunction():
    return TimingFunction('sleep', [16, 72], SleepAccumulateDelegate)

def SleepAccumulateDelegate(state):
    val = state.solver.eval(state.regs.rdi)
    return val

class TimingFunction:
    def __init__(self, name, registers, accumulate_delegate):
        self.name = name
        self.registers = registers
        self.accumulate_delegate = accumulate_delegate

class HighArgument:
    def __init__(self, reg, ins_addr):
        self.reg = reg
        self.ins_addr = ins_addr

    def __repr__(self):
        return "<" + str(self.reg) + ", " + str(hex(self.ins_addr)) + ">"

class HighArgumentCall:
    def __init__(self, high_args, block_addr):
        self.high_args = high_args
        self.block_addr = block_addr

    def __repr__(self):
        return "<HighArgumentCall @ " + str(hex(self.block_addr)) + ", high arguments: " + str(self.high_args) + ">"

class TimingInterval:
    def __init__(self, acc, ins_count):
        self.acc = acc
        self.ins_count = ins_count
        self.high_arg_calls = []

class ProcedureRecord:
    def __init__(self, call, depth):
        self.call = call
        self.depth = depth

class ProcedureRecordPlugin(angr.SimStatePlugin):
    NAME = 'procedure_record_plugin'

    def __init__(self, map, temp_interval):
        super(ProcedureRecordPlugin, self).__init__()
        self.temp_interval = copy.deepcopy(temp_interval)
        self.map = copy.deepcopy(map)

    @angr.SimStatePlugin.memo
    def copy(self, memo):
        return ProcedureRecordPlugin(self.map, self.temp_interval)

class TimingProcedureCallLeak:
    def __init__(self, state, interval):
        self.state = state
        self.interval = interval

    def __repr__(self):
        return "<TimingProcedureCallLeak @ calls: " + str(self.interval.high_arg_calls) + ">"

class TimingProcedureLeakProof:
    def __init__(self, branching, state1, state2, interval1, interval2):
        self.branching = branching
        self.state1 = state1
        self.state2 = state2
        self.interval1 = interval1
        self.interval2 = interval2

    def __repr__(self):
        return "<TimingProcedureLeakProof @ branching block: " + str(hex(self.branching.block_addr)) + ", acc1: " + str(self.interval1.acc) + ", acc2: " + str(self.interval2.acc) + ">"

class TimingEpsilonLeakProof:
    def __init__(self, branching, state1, state2, interval1, interval2):
        self.branching = branching
        self.state1 = state1
        self.state2 = state2
        self.interval1 = interval1
        self.interval2 = interval2

    def __repr__(self):
        return "<TimingEpsilonLeakProof @ branching block: " + str(hex(self.branching.block_addr)) + ", ins_count1: " + str(self.interval1.ins_count) + ", ins_count2: " + str(self.interval2.ins_count) + " diff: " + calc_procedure_diff(self.interval1, self.interval2) + ">"