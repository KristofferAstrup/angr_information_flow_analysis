import angr
from angrutils import *
import matplotlib.pyplot as plt
import networkx as nx

class DefinitionDecorator(angr.knowledge_plugins.key_definitions.definition.Definition):
    given_sec_class = 0
    sec_class = 0
    def __repr__(self):
        return str(self.atom) + ", " + str(self.codeloc) + ", <sc " + str(self.sec_class) +\
            (" (" + str(self.given_sec_class) + ")" if self.given_sec_class != 0 else "") + ">"

def wrap_rda(rda):
    g = networkx.DiGraph()
    map = {}
    for n in rda.graph.nodes:
        decorator = DefinitionDecorator(n.atom, n.codeloc, n.data, n.dummy, n.tags)
        map[n] = decorator
        g.add_node(decorator)
    for e in rda.graph.edges:
        g.add_edge(map[e[0]],map[e[1]])
    return g