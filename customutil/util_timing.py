import angr
import angr.analyses.reaching_definitions.dep_graph as dep_graph
from angrutils import *
import matplotlib.pyplot as plt
import networkx as nx
import pydot
import copy
import sys
from customutil import util_implicit, util_information, util_progress
from networkx.drawing.nx_pydot import graphviz_layout

def determine_timing_procedure_leak(states):
    for state_a in states:
        for state_b in states:
            if state_a == state_b:
                continue
            for branch_instance in state_a.plugins[util_implicit.BranchRecordPlugin.NAME].records:
                if not branch_instance in state_b.plugins[util_implicit.BranchRecordPlugin.NAME].records:
                    continue
                imm_progress_instance_a = immediate_progress(state_a, branch_instance)
                if not imm_progress_instance_a:
                    continue
                imm_progress_instance_b = immediate_progress(state_a, branch_instance)
                if not imm_progress_instance_b:
                    continue
                timing_interval_a = state_a.plugins[ProcedureRecordPlugin.NAME].map[imm_progress_instance_a.index]
                timing_interval_b = state_b.plugins[ProcedureRecordPlugin.NAME].map[imm_progress_instance_b.index]
                if abs(timing_interval_a.acc - timing_interval_b.acc) > 0:
                    return TimingProcedureLeakProof(branch_instance, state_a, state_b, timing_interval_a, timing_interval_b)

def determine_timing_instruction_leak(states, ins_count_threshold):
    for state_a in states:
        for state_b in states:
            if state_a == state_b:
                continue
            for branch_instance in state_a.plugins[util_implicit.BranchRecordPlugin.NAME].records:
                if not branch_instance in state_b.plugins[util_implicit.BranchRecordPlugin.NAME].records:
                    continue
                imm_progress_instance_a = immediate_progress(state_a, branch_instance)
                if not imm_progress_instance_a:
                    continue
                imm_progress_instance_b = immediate_progress(state_a, branch_instance)
                if not imm_progress_instance_b:
                    continue
                timing_interval_a = state_a.plugins[ProcedureRecordPlugin.NAME].map[imm_progress_instance_a.index]
                timing_interval_b = state_b.plugins[ProcedureRecordPlugin.NAME].map[imm_progress_instance_b.index]
                if abs(timing_interval_a.ins_count - timing_interval_b.ins_count) > ins_count_threshold:
                    return TimingEpsilonLeakProof(branch_instance, state_a, state_b, timing_interval_a, timing_interval_b)

def immediate_progress(state, branching):
    for prog in state.plugins[util_progress.ProgressRecordPlugin.NAME].records:
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

# def procedure_hook(proj, state):
    # plugin = state.plugins[ProcedureRecordPlugin.NAME]
    # call = {}
    # for arg_reg in arg_regs:
    #     offset, size = proj.arch.registers[arg_reg.reg_name]
    #     reg = state.registers.load(offset, size)
    #     val = state.solver.eval(reg)
    #     call[arg_reg.reg_name] = val
    # key = procedure.display_name
    # record = ProcedureRecord(call, state.history.block_count)
    # plugin.map.setdefault(key, []).append(record)

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
    #print(list(map(lambda h: h.addr, state.history.lineage)))
    while his.block_count > termination_depth:
        if his.addr in high_block_map:
            high_ins_count += len(high_block_map[his.addr].instruction_addrs)
        if not his.parent:
            break
        his = his.parent
    return high_ins_count

def SleepTimingFunction():
    return TimingFunction('sleep', SleepAccumulateDelegate)

def SleepAccumulateDelegate(state):
    val = state.solver.eval(state.regs.rdi)
    return val

class TimingFunction:
    def __init__(self, name, accumulate_delegate):
        self.name = name
        self.accumulate_delegate = accumulate_delegate

class TimingInterval:
    def __init__(self, acc, ins_count):
        self.acc = acc
        self.ins_count = ins_count

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
        return "<TimingEpsilonLeakProof @ branching block: " + str(hex(self.branching.block_addr)) + ", ins_count1: " + str(self.interval1.ins_count) + ", ins_count2: " + str(self.interval2.ins_count) + " eps: " + str(abs(self.interval1.ins_count - self.interval2.ins_count)) + ">"