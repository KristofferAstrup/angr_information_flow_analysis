import angr
import claripy
import sys
sys.path.append('../../../')
from customutil import util_analysis, util_rda, util_out, util_information

def main():
    proj = angr.Project('./arg_sleep_transitive.out', load_options={'auto_load_libs':False})

    sym_arg_size = 15
    arg0 = claripy.BVS('arg0', 8*sym_arg_size)
    state = proj.factory.entry_state(args=['./arg_sleep_transitive.out', arg0], add_options={angr.options.UNICORN})
    for byte in arg0.chop(8):
        state.add_constraints(byte >= '\x21') # '!'
        state.add_constraints(byte <= '\x7e') # '~'

    high_addrs = [0x401175, 0x401178]
    low_addrs = [0x401200, 0x40120d]

    # for reg in util_information.get_regs(proj):
    #     print(reg)

    ifa = util_analysis.InformationFlowAnalysis(proj=proj,state=state,start="main",high_addrs=high_addrs)
    # high_nodes = util_rda.find_rda_graph_nodes(ifa.rda_graph, 0x401178)
    # low_nodes = util_rda.find_rda_graph_nodes(ifa.rda_graph, [0x401200, 0x40120d])
    # edge_flow = None
    # for high_node in high_nodes:
    #     for low_node in low_nodes:
    #         edge_flow = util_rda.check_explicit_flow(ifa.rda_graph, high_node, low_node)
    #         if edge_flow:
    #             util_rda.print_edge_flow(edge_flow)
    # if not edge_flow:
    #     return
    # rda_graph = util_rda.get_edge_flow_rda(ifa.rda_graph, edge_flow)
    # util_out.draw_rda_graph(ifa.project, rda_graph, fname="out/edge_flow_rda.pdf")
    # return
    for leak in ifa.find_timing_leaks():
        print(leak)

if __name__ == "__main__":
    main()