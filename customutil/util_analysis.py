#Explicit (static)
#Implicit (static)
#Termination (concolic)
#Progress (concolic)
#Timing (concolic)
import angr
from customutil import util_information, util_out, util_explicit, util_implicit, util_progress, util_termination, util_timing

class InformationFlowAnalysis:
    def __init__(self, proj, high_addrs, state=None, start_addr=None, subject_addrs=None):
        self.project = proj
        self.state = state if state else proj.factory.entry_state()
        self.simgr = proj.factory.simgr(self.state, hierarchy=angr.state_hierarchy.StateHierarchy())
        self.cfg = util_information.cfg_emul(self.project, self.simgr, self.state)
        self.ddg = proj.analyses.DDG(cfg = self.cfg)
        self.cdg = proj.analyses.CDG(cfg = self.cfg)
        self.high_addrs = high_addrs
        self.subject_addrs = subject_addrs
        self.start_node = self.cfg.model.get_any_node(addr=start_addr if start_addr else self.state.addr)
        self.rda = util_explicit.get_super_dep_graph_with_linking(self.project, self.cfg, self.cdg, self.start_node)
        self.post_dom_tree = self.cdg.get_post_dominators()

        self.simgr.explore(find=self.start_node.addr)
        if len(self.simgr.found) < 1:
            raise("No main entry block state found!")
        self.state = self.simgr.found[0]

    def find_explicit_flows(self):
        if not self.subject_addrs:
            raise Exception("Please add subject addresses to the InformationFlowAnalysis")
        paths = []
        for explicit_path in util_explicit.find_explicit(self.rda, self.subject_addrs, self.high_addrs):
            paths.append(explicit_path)
        return paths

    def find_implicit_flows(self):
        if not self.subject_addrs:
            raise Exception("Please add subject addresses to the InformationFlowAnalysis")
        return

    def find_termination_leaks(self, spinning_state=None, progress_states=None):
        if not spinning_state or not progress_states:
            loop_seer = angr.exploration_techniques.LoopSeer(cfg=self.cfg, bound=100)
            simgr = self.simgr.copy()
            simgr.use_technique(loop_seer)
            simgr.explore(find=self.start_node.addr)
            if len(simgr.found) < 1:
                raise("No main entry block state found!")
            state = simgr.found[0]
            simgr.stash(from_stash='active', to_stash='stash')
            simgr.stash(from_stash='found', to_stash='active')
            simgr.explore()
            if not spinning_state or not progress_states:
                return []
            spinning_state = simgr.spinning[0]
            progress_states = simgr.deadended

        proofs = util_termination.get_termination_leak(self.rda, self.cfg, self.high_addrs, spinning_state, progress_states)
        return proofs

    def find_timing_leaks(self):
        branches = util_implicit.find_high_branches(self.rda, self.post_dom_tree, self.start_node, self.high_addrs)
        leaks = []
        for branch in branches:
            leak = util_timing.test_timing_leak(self.project, self.cfg, self.state, branch)
            if leak:
                leaks.append(leak)
        return leaks

    def find_progress_leaks(self):
        branches = util_implicit.find_high_branches(self.rda, self.post_dom_tree, self.start_node, self.high_addrs)   
        leaks = []
        for branch in branches:
            leak = util_progress.test_observer_diff(self.project, self.cfg, self.state, branch)
            if leak:
                leaks.append(leak)
        return leaks

    def find_all_leaks(self):
        if self.subject_addrs:
            explicit_flows = self.find_explicit_flows()
            if len(list(explicit_flows)) > 0:
                print("Found explicit flow(s):")
                print(explicit_flows)
                return explicit_flows
            print("Found no explicit flow(s):")

            implicit_flows = self.find_implicit_flows()
            if implicit_flows:
                print("Found implicit flow(s):")
                print(implicit_flows)
                return implicit_flows
            print("Found no implicit flow(s):")
        else:
            print("No subject addresses found, skipping implicit/explicit")
        termination_leaks = self.find_termination_leaks()
        if len(list(termination_leaks)) > 0:
            print("Found termination leak(s):")
            print(termination_leaks)
            return termination_leaks
        print("Found no termination leak(s):")

        progress_leaks = self.find_progress_leaks()
        if len(list(progress_leaks)) > 0:
            print("Found progress leak(s):")
            print(progress_leaks)
            return progress_leaks
        print("Found progress leak(s):")

        timing_leaks = self.find_timing_leaks()
        if timing_leaks:
            print("Found timing leak(s):")
            print(timing_leaks)
            return timing_leaks
        print("Found no timing leak(s):")

        print("No leaks found")
        return []