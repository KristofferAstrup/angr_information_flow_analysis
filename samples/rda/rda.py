import angr
import monkeyhex
import inspect
import re
from angr import KnowledgeBase
from angr.knowledge_plugins.key_definitions.constants import OP_AFTER, OP_BEFORE
from angr.sim_variable import SimRegisterVariable, SimConstantVariable
from angr.code_location import CodeLocation
from angr.analyses.ddg import ProgramVariable
from angr.knowledge_plugins.key_definitions.atoms import Atom
from angr.knowledge_plugins.functions.function_manager import FunctionManager
from argument_resolver.handlers import handler_factory, StdioHandlers
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
    print(proj.kb.functions.keys())
    for k in proj.kb.functions.values():
        print(k)

    main_func = proj.kb.functions.function(name='main')
    puts_func = proj.kb.functions.function(addr=0x500008)
    print(puts_func)
    #print(dir(proj.analyses))
    #print(main_func)
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

    parameter_atom = Atom.from_argument(
        puts_func.calling_convention.arg_locs()[0],
        proj.arch.registers
    )

    rdi_definition = list(
        handler.sink_atom_defs[parameter_atom]
    )[0]


    # reaches = rda.get_reaching_definitions_by_insn(call_to_puts, OP_BEFORE)
    # #print(dir(reaches))
    # reach_defs = reaches.get_definitions(parameter_atom)
    # reach_def = list(reach_defs)[0]

    # print(reach_def)
    # print(dir(reach_def))
    # print(reach_def.data)
    # for el in reach_def.data:
    #     print(hex(el))

    #closure = rda.dep_graph.transitive_closure(reach_def)
    #print(closure)

    # reg_def = None
    # for reg in reaches.register_definitions:
    #     if reg.start == 72:
    #         reg_def = reg
    # print(reg_def)
    #print(dir(rda.dep_graph))

    # for n in rda.dep_graph.nodes():
    #     print(n)
    #     print(dir(n))
    #     print(n.data)
    #     print(n.atom)
    #     break

    

    #util.draw_graph(rda.dep_graph.graph, fname="dep_graph.pdf")

    # 
    # for regdef in res.register_definitions:
    #     #print(dir(regdef))
    #     print(regdef.start)
    # print(res)
    return 0

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
