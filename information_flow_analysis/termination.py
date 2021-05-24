import angr
import angr.analyses.reaching_definitions.dep_graph as dep_graph
from angrutils import *
import matplotlib.pyplot as plt
import networkx as nx
import pydot
from information_flow_analysis import information, out, explicit, implicit, progress

def determine_termination_leak(nonterm_state, term_states):
    for term_state in term_states:
        for branch_instance in nonterm_state.plugins[implicit.BranchRecordPlugin.NAME].records:
            if not branch_instance in term_state.plugins[implicit.BranchRecordPlugin.NAME].records:
                continue
            for progress_instance in term_state.plugins[progress.ProgressRecordPlugin.NAME].records:
                if progress_instance.depth < branch_instance.depth:
                    continue
                if progress_instance in nonterm_state.plugins[progress.ProgressRecordPlugin.NAME].records:
                    continue
                non_term_loop = get_nonterm_loop(nonterm_state)
                return TerminationLeak(non_term_loop, nonterm_state, term_state, progress_instance)
    return None

def get_termination_leak(rda_graph, cfg, high_addrs, spinning_state, progress_states): 
    #Progress_states are simply states that are not spinning and may be used as evidence for a termination leak
    infinite_loop_history_begin, infinite_loop = get_infinite_loop_begin_of_spinning(spinning_state)
    high_context_loop = implicit.test_high_loop_context(rda_graph, cfg, infinite_loop, high_addrs)
    if not high_context_loop:
        None
    loop_block_addrs = list(map(lambda n: n.addr, infinite_loop.body_nodes))
    for progress_state in progress_states:
        his = get_closest_common_ancestor(spinning_state.history, progress_state.history)
        if his == None:
            continue
        if not implicit.check_addr_high(rda_graph, his.addr):
            continue
        if progress_state.posix.dumps(1).startswith(spinning_state.posix.dumps(1)):
            post_progress = progress_state.posix.dumps(1)[len(spinning_state.posix.dumps(1)):]
            if post_progress:
                return TerminationLeak(infinite_loop, spinning_state, progress_state, post_progress)
        else:
           return TerminationLeak(infinite_loop, spinning_state, progress_state, spinning_state.posix.dumps(1))
    return []

def accumulate_loop_path_block_addrs(loop, addrs=[], blocknode=None):
    if not blocknode:
        blocknode = loop.entry
    addrs.append(blocknode.addr)
    for succ in blocknode.successors:
        if succ in loop.body_nodes and not succ.addr in addrs:
            accumulate_loop_path_block_addrs(succ, addrs, succ)

def get_nonterm_loop(spinning_state):
    for loop, addrs in reversed(spinning_state.loop_data.current_loop):
        if loop.entry.addr == spinning_state.addr:
            return loop
    return None

def get_infinite_loop_begin_of_spinning(spinning, min_iters=1):
    infinite_loop_history_begin = None
    infinite_loop = None
    iters = 0
    for loop, addrs in reversed(spinning.loop_data.current_loop):
        if loop.entry.addr == spinning.addr:
            infinite_loop = loop
    if infinite_loop == None: #Should not happen if loop_data is sound
        return None
    loop_block_addrs = list(map(lambda n: n.addr, infinite_loop.body_nodes))
    for h in reversed(spinning.history.lineage):
        if not h.addr in loop_block_addrs:
            break
        if h.addr == spinning.addr:
            iters += 1
        infinite_loop_history_begin = h
    if iters > min_iters and infinite_loop_history_begin:
        return (infinite_loop_history_begin, infinite_loop)
    return None

def get_closest_common_ancestor(his1, his2):
    his1 = list(his1.parents)
    his2 = list(his2.parents)
    i = 0
    while(his1[i] == his2[i]):
        i = i+1
        if i >= len(his1) or i >= len(his2):
            return None
    return his1[i]

class TerminationLeak:
    def __init__(self, loop, spinning_state, progress_state, progress_diff):
        self.loop = loop,
        self.spinning_state = spinning_state
        self.progress_state = progress_state
        self.progress_diff = progress_diff
    
    def __repr__(self):
        return "<TerminationLeak @ loop: " + str(self.loop) + ", loop state : " + str(self.spinning_state) + ", progress state: " + str(self.progress_state) + ", progress diff: " + str(self.progress_diff) + ">"
