import sys
sys.path.append('./sim')
sys.path.append('./utils')
import pandas as pd
import plotly.express as px

from network_sim import Simulation 
from network_node import NetworkNode
from attacker import Attacker
from generate_report import Report

if __name__=='__main__':
    
    # Run the simulation with onboard attacker
    sim2 = Simulation('sim2')
    sim2.establish_nodes(9)
    sim2.set_v1_structure()
    attacker = Attacker('attacker1', 0)
    sim2.add_attacker(attacker)
    compromised_results = sim2.run_simulation(t=100)
    
    results_dir = '/Users/carleen/Documents/grad_school/fuzzy-defender/results'
    report_c = Report('compromised', compromised_results)
    report_c.generate_report(results_dir)
    