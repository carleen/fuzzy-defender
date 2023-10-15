import sys
sys.path.append('./sim')
sys.path.append('./utils')
import pandas as pd
import plotly.express as px

from network_sim import Simulation, NetworkNode
from generate_report import Report

if __name__=='__main__':
    # Run the simulation without a hacked node
    sim = Simulation('sim1')
    node_dict = sim.establish_nodes(9)
    sim.set_v1_structure()
    uncompromised_results = sim.run_simulation(t=100)
    
    # Run the simulation with node 0 hacked
    sim = Simulation('sim2')
    node_dict = sim.establish_nodes(9)
    sim.set_v1_structure()

    node0, ind = sim.get_node('node_0')
    node0.is_compromised = 1
    sim.modify_node(node0, ind)

    compromised_results = sim.run_simulation(t=100)
    
    report_c = Report('compromised', compromised_results)
    report_u = Report('uncompromised', uncompromised_results)