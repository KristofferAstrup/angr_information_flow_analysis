import angr
import time
import monkeyhex
import inspect
import re
import claripy
from angr import KnowledgeBase
from angr.sim_variable import SimRegisterVariable, SimConstantVariable
from angr.code_location import CodeLocation
from angr.analyses.ddg import ProgramVariable
from angr.knowledge_plugins.functions.function_manager import FunctionManager
import networkx as nx
import angr.analyses.reaching_definitions.dep_graph as dep_graph
from networkx.drawing.nx_pydot import graphviz_layout
import sys
sys.path.append('../../../')
from customutil import util_information, util_out, util_explicit, util_implicit, util_progress

def main():
    proj = angr.Project('simple_sleep.out', load_options={'auto_load_libs':False})

    sym_arg_size = 15
    arg0 = claripy.BVS('arg0', 8*sym_arg_size)
    state = proj.factory.entry_state(args=['./simple_sleep.out', arg0], add_options={angr.options.UNICORN})
    hier = angr.state_hierarchy.StateHierarchy()
    simgr = proj.factory.simgr(state, hierarchy=hier)
    for byte in arg0.chop(8):
        state.add_constraints(byte >= '\x21') # '!'
        state.add_constraints(byte <= '\x7e') # '~'

    #simgr.run()

    util_out.draw_everything(proj, simgr, state)

    #util_out.write_stashes(simgr, args=[arg0])

if __name__ == "__main__":
    main()
