import numpy as np
import skfuzzy as fuzz
from skfuzzy import control as ctrl
import plotly.express as px
from network_node import NetworkNode

import pandas as pd


class Simulation:
    '''
    
    ****TODO**** 
    
    --------------
    Attributes
    --------------
        name: str 
            Simulation name
        node_list: list, NetworkNode objects
            Stores individual nodes contained in network
            
    --------------
    Methods
    --------------
        run_simulation(t)
            Runs simulation for a given number of time steps
        
    
    '''
    
    def __init__(self, name):
        self.name = name
        self.node_list = []
        self.attacker_list = []
        
    def establish_nodes(self, num_nodes):
        ''' Creates a specified number of nodes to be included in network
        
        --------------
        Parameters
        --------------
            num_nodes: int
                Number of nodes to be created for network
        
        --------------
        Returns
        --------------
            node_dict: dict
                Dictionary containing (key, value) pairs, where 
                pairs are (node_[i], NetworkNode)
        
        '''
        node_dict = {}
        for i in range(0,num_nodes):
            node_name = f'node_{i}'
            node = NetworkNode(node_name)
            self.node_list.append(node)
            node_dict[node_name] = i
        self.node_dict = node_dict
    
    def add_attacker(self, attacker):
        self.attacker_list.append(attacker)
        
        
    def run_simulation(self, t):
        ''' Steps through the simulation for a specified number of time steps.
        Each step is meant to represent one second of time, and network checks
        are completed at every iteration. 
        
        --------------
        Parameters
        --------------
            t: int
                Number of timesteps to run the simulation 
        
        --------------
        Returns
        --------------
            sim_results: dict
                Dictionary object containing the results of the simulation, 
                including the results of compromised node checks at each step,
                along with metrics recorded at each time step.
        
        '''
        for timestep in range(0, t):
            for a in self.attacker_list:    
                target_node_ind = a.get_target_node()
                threshold = self.node_list[target_node_ind].get_security_threshold()
                success = a.attempt_attack(threshold)
                
                if success:
                    self.node_list[target_node_ind].is_compromised = 1
                
            for n in self.node_list:
                n.get_node_metrics(timestep)
                n.truth_compromise_check()
                n.basic_compromise_check()
                n.fuzzy_compromise_check()
        
        sim_results = {}
        for n in self.node_list:
            sim_results[n.name] = {'time': n.time_step_array,
                                'packet_rate': n.packet_rate_array,
                                   'bandwidth': n.bandwidth_array,
                                   'response_time': n.response_time_array,
                                   'flagged_malicious': n.flagged_malicious_array,
                                   'fuzzy_compromised_value': n.fuzzy_compromised_value_array,
                                   'fuzzy_compromised_category': n.fuzzy_compromised_cat_array,
                                  'compromised_truth': n.compromised_array}
        return sim_results

        
            
    def get_node(self, node_name):
        ''' Gets a node based off of the provided node name
        
        --------------
        Parameters
        --------------
            node_name: str
                Name of the node of interest
        
        --------------
        Returns
        --------------
            node,ind: NetworkNode, int
                Returns network node and the corresponding index of the node, based on
                where it falls in the list of nodes contained in the network
        
        '''
        node = None
        ind=0
        for n in self.node_list:
            if n.name==node_name:
                node = n
                break
            ind+=1
        return node,ind
            
    def modify_node(self, node, ind):
        ''' Modifies the node within the network's list. This can change the properties
        of the node, such as whether or not the node has been attacked. 
        
        --------------
        Parameters
        --------------
            node: NetworkNode 
                Node to be modified
            ind: int
                Index of node to be modified, based on network's list of nodes
        
        
        '''
        self.node_list[ind] = node
            
    def set_attacker(self, attacker):
        self.attacker = attacker
                
    def set_v1_structure(self):
        '''Sets up the structure of the network. Currently not used, but may later
        be implimented as a means of increasing the likelihood that a node gets attacked,
        based on whether or not the node's parent is compromised
        
        '''
        self.node_list[0].set_node_level(0)
        self.node_list[0].link_nodes([], [self.node_list[1], self.node_list[2]])

        self.node_list[1].set_node_level(1)
        self.node_list[1].link_nodes([self.node_list[0]], [self.node_list[3]])
        self.node_list[2].set_node_level(1)
        self.node_list[2].link_nodes([self.node_list[0]], [self.node_list[4],self.node_list[5]])

        self.node_list[3].set_node_level(2)
        self.node_list[3].link_nodes([self.node_list[1]], [self.node_list[6], self.node_list[7]])
        self.node_list[4].set_node_level(2)
        self.node_list[4].link_nodes([self.node_list[2]], [])
        self.node_list[5].set_node_level(2)
        self.node_list[5].link_nodes([self.node_list[2]], [self.node_list[8]])

        self.node_list[6].set_node_level(3)
        self.node_list[6].link_nodes([self.node_list[3]], [])
        self.node_list[7].set_node_level(3)
        self.node_list[7].link_nodes([self.node_list[3]], [])
        self.node_list[8].set_node_level(3)
        self.node_list[8].link_nodes([self.node_list[5]], [])