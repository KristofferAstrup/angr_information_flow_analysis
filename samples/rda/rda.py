import angr
import monkeyhex
import inspect
import re
from angr import KnowledgeBase
from angr.knowledge_plugins.key_definitions.constants import OP_AFTER, OP_BEFORE
from angr.sim_variable import SimRegisterVariable, SimConstantVariable
from angr.code_location import CodeLocation
from angr.analyses.ddg import ProgramVariable
from angr.knowledge_plugins.functions.function_manager import FunctionManager
from angrutils import *
import networkx as nx
import angr.analyses.reaching_definitions.dep_graph as dep_graph
from networkx_query import search_nodes, search_edges
import sys
sys.path.append('../../')
from customutil import util

def main():
    proj = angr.Project('nothing.out', load_options={'auto_load_libs':True})
    sym_arg_size = 15
    arg0 = claripy.BVS('arg0', 8*sym_arg_size)
    state = proj.factory.entry_state(args=['./nothing.out', arg0])
    simgr = proj.factory.simgr(state)

    cfg = proj.analyses.CFGFast()

    call_to_puts = 0x40118b
    observation_points = [
        ('insn', call_to_puts, OP_BEFORE),
        ('insn', call_to_puts, OP_AFTER)
    ]
    main_func = proj.kb.functions.function(name='main')
    print(main_func)
    #print(dir(proj.analyses))
    rda = proj.analyses.ReachingDefinitions(
        subject = main_func,
        #func_graph = main_func.graph,
        cc = main_func.calling_convention,
        dep_graph = dep_graph.DepGraph(),
        #observation_points=observation_points,
        observe_all=True
        #function_handler=Handler(proj)
    )

    # vulnerable_function_first_block = rda.project.factory.block(main_func.addr).vex
    # state_before_puts_call = rda.observed_results[observation_points[0]]
    # state_after_puts_call = rda.observed_results[observation_points[1]]

    # stack_variables_before_call = state_before_puts_call.stack_definitions.get_all_variables()
    # stack_variables_after_call = state_after_puts_call.stack_definitions.get_all_variables()
    
    # print("-------BEFORE-------")
    # print(state_before_puts_call)
    # print("-------AFTER--------")
    # print(state_after_puts_call)
    # print("\n")

    # print("-------BEFORE-------")
    # print(stack_variables_before_call)
    # print("-------AFTER--------")
    # print(stack_variables_after_call)
    # print("\n")

    # before_puts = rda.get_reaching_definitions(call_to_puts, OP_BEFORE).stack_definitions.get_all_variables()
    # after_puts = rda.get_reaching_definitions(call_to_puts, OP_AFTER).stack_definitions.get_all_variables()

    #print_diffs(before_puts,after_puts)
    print(dir(rda.dep_graph))
    util.draw_graph(rda.dep_graph.graph)

def print_diffs(vars1, vars2):
    print("Additional in vars1")
    for var in vars1:
        if var not in vars2:
            print(var)
    print("Additional in vars2")
    for var in vars2:
        if var not in vars1:
            print(var)
    


if __name__ == "__main__":
    main()
