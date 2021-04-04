#Explicit (static)
#Implicit (static)
#Termination (concolic)
#Progress (concolic)
#Timing (concolic)

from customutil import util_information, util_out, util_explicit, util_implicit, util_progress, util_termination, util_timing

class InformationFlowAnalysis:
    def __init__(self, proj, high_addrs, state=None, start_addr=None, subject_addrs=None):
        self.project = proj
        self.state = state if state else proj.factory.entry_state()
        self.simgr = proj.factory.simgr(self.state)
        self.cfg = proj.analyses.CFGEmulated(
            keep_state=True, 
            normalize=True, 
            starts=[start_addr if start_addr else self.state.addr],
            initial_state=self.state,
            context_sensitivity_level=5,
            resolve_indirect_jumps=True
        )
        self.ddg = proj.analyses.DDG(cfg = self.cfg)
        self.cdg = proj.analyses.CDG(cfg = self.cfg)
        self.high_addrs = high_addrs
        self.subject_addrs = subject_addrs
        self.start_node = self.cfg.model.get_any_node(addr=start_addr if start_addr else self.state.addr)
        self.rda = util_explicit.get_super_dep_graph_with_linking(self.project, self.cfg, self.cdg, self.start_node)
        self.post_dom_tree = self.cdg.get_post_dominators()

    def find_explicit_flows(self):
        if not self.subject_addrs:
            raise Exception("Please add subject addresses to the InformationFlowAnalysis")
        for explicit_path in util_explicit.find_explicit(self.rda, self.subject_addrs, self.high_addrs):
            print("Explicit flow:")
            print(explicit_path)
            yield explicit_path

    def find_implicit_flows(self):
        if not self.subject_addrs:
            raise Exception("Please add subject addresses to the InformationFlowAnalysis")
        return

    def find_termination_leaks(self, spinning_state, progress_states):
        proofs = util_termination.get_termination_leak(self.rda, self.cfg, self.high_addrs, spinning_state, progress_states)
        print(proofs)
        return proofs

    def find_timing_leaks(self):
        branches = util_implicit.find_high_branches(self.rda, self.post_dom_tree, self.start_node, self.high_addrs)
        for branch in branches:
            leak = util_timing.test_timing_leak(proj, cfg, state, branch)
            if leak:
                print(leak)
                yield leak

    def find_progress_leaks(self):
        branches = util_implicit.find_high_branches(self.rda, self.post_dom_tree, self.start_node, self.high_addrs)
        for branch in branches:
            leak = util_progress.test_observer_diff(proj, cfg, state, branch)
            if leak:
                print(leak)
                yield leak
        
    def find_all_leaks(self):
        explicit_flows = self.find_explicit_flows()
        if explicit_flows:
            return explicit_flows

        implicit_flows = self.find_implicit_flows()
        if implicit_flows:
            return implicit_flows
        
        termination_leaks = self.find_termination_leaks()
        if termination_leaks:
            return termination_leaks

        progress_leaks = self.find_progress_leaks()
        if progress_leaks:
            return progress_leaks

        timing_leaks = self.find_timing_leaks()
        if timing_leaks:
            return timing_leaks

        print("No leaks found")
        return []