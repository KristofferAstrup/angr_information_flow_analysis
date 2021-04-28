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
from customutil import util_analysis, util_information, util_out, util_explicit, util_implicit, util_progress, util_termination

def main():
    proj = angr.Project('samples/termination/non_termination/non_termination.out', load_options={'auto_load_libs':False})

    sym_arg_size = 15
    arg0 = claripy.BVS('arg0', 8*sym_arg_size)
    state = proj.factory.entry_state(args=['./non_termination.out', arg0], add_options={angr.options.UNICORN})
    for byte in arg0.chop(8):
        state.add_constraints(byte >= '\x21') # '!'
        state.add_constraints(byte <= '\x7e') # '~'

    high_addrs = [0x401155, 0x401158]

    ifa = util_analysis.InformationFlowAnalysis(proj, high_addrs, start="main")
    for leak in ifa.find_covert_leaks():
        print(leak)
    return

if __name__ == "__main__":
    main()
