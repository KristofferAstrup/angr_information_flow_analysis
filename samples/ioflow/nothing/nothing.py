import angr
import monkeyhex
import inspect
from angr import KnowledgeBase
from angr.sim_variable import SimRegisterVariable, SimConstantVariable
from angr.code_location import CodeLocation
from angr.analyses.ddg import ProgramVariable
from angr.knowledge_plugins.functions.function_manager import FunctionManager
from angrutils import *
import networkx as nx
from networkx_query import search_nodes, search_edges
import sys
sys.path.append('../../../')
from customutil import util_analysis

def main():
    proj = angr.Project('nothing.out', load_options={'auto_load_libs':False})
    state = proj.factory.entry_state()

    high_addrs = [0x401155, 0x401158]

    ifa = util_analysis.InformationFlowAnalysis(proj=proj,state=state,start="main",high_addrs=high_addrs)
    ifa.find_and_add_subject_addrs("puts")
    for flow in ifa.find_explicit_flows():
        print(flow)
    for flow in ifa.find_implicit_flows():
        print(flow)
    return 0

if __name__ == "__main__":
    main()
