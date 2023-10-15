import numpy as np
import skfuzzy as fuzz
from skfuzzy import control as ctrl
import plotly.express as px

import pandas as pd

class NetworkNode:
    '''
    A class used to represent an individual node within the network.
    
    ****TODO**** 
        Implement some way to store mu/stdev values for each of the
        metric calculations
    
    --------------
    Attributes
    --------------
        name: str 
            network node name
        flagged_malicious: int (0,1) 
            indicates basic algorithm's interpretation of node status
        level: int 
            represents where node falls in network hierarchy

        [*]_array: list
            stores values at each time step of the simulation
            - comproised_array: used for truthing
            - bandwidth, packet_rate, response_time: the metrics that
              underly the "wellness" calculations of the nodes

        parent_nodes: list 
            node's ancestor nodes
        child_nodes 
            node's children nodes

        cur_[*]: list 
            tracks the current values for node metrics
            
    --------------
    Methods
    --------------
        get_packet_rate(mu, stdev, min_munivorm, max_uniform)
        get_bandwidth(mu, stdev, min_munivorm, max_uniform)
        get_response_time(mu, stdev, min_munivorm, max_uniform)
            Determines the values of the network metric parameters
            at the current simulation time step
        
        link_nodes(parent_node_list, child_node_list)
            Establishes parents and children of node
            
        get_node_metrics(timesteps)
            Calls methods to set the metrics for the node based on
            the health of the node
        
        set_node_level(level)
            Setter function
        get_node_level()
            Getter function
            
        add_timestep(t)
            Appends timestep value to array for node
        
        basic_compromise_check()
            Uses simple logic with cutoffs for node metrics to determine
            if node is compromised
        fuzzy_compromise_check()
            Uses fuzzy logic to calculate the likelihood that the
            node is compromsied
    --------------
    
    '''
    
    def __init__(self, name):
        self.name = name
        self.is_compromised = 0
        self.flagged_malicious = 0
        self.level = 0
        self.fuzzy_flagged_malicious = -1
        
        self.packet_rate_array = []
        self.bandwidth_array = []
        self.response_time_array = []
        self.flagged_malicious_array = [0]
        self.compromised_array = [0]
        self.fuzzy_compromised_value_array = [0]
        self.fuzzy_compromised_cat_array = [-1]
        self.time_step_array = [-1]
        
        self.parent_nodes = []
        self.child_nodes = []
        
        self.cur_packet_rate = self.get_packet_rate()
        self.cur_bandwidth = self.get_bandwidth()
        self.cur_response_time = self.get_response_time()

        
    def get_packet_rate(self, mu=0.91, stdev=0.01, min_uniform=0.05, max_uniform=0.1):
        ''' Gets the current packet rate of the node. Packet rate is determined
        based on whether or not the node is compromised
        
        *****TODO*****
            Store mu, stdev values for metric
        
        --------------
        Parameters
        --------------
            - mu: float
                Sets the mean value for the normal distribution for the packet
                rate of the node
            - stdev: float
                Sets the standard deviation for the normal distribution for
                packet rate of the node
            - min_uniform: float
                Lower limit on random amount packet rate is degraded if 
                the node is compromised
            - max_uniform: float
                Upper limit on random amount packet rate is degraded if 
                the node is compromised
        --------------
        Returns
        --------------
            - packet_rate: float
                Packet rate of node at time in simulation 
        
        '''
        # Under normal operation, 
        if self.is_compromised ==0:
            packet_rate = np.random.normal(mu, stdev)
        else:
            packet_rate = np.random.normal(mu,stdev) - np.random.uniform(min_uniform, max_uniform)
        self.packet_rate_array.append(packet_rate)
        return packet_rate
    
    def get_bandwidth(self, mu=30, stdev=3, min_uniform=2, max_uniform=7):
        ''' Gets the current bandwidth of the node. Bandwidthis determined
        based on whether or not the node is compromised
        
        *****TODO*****
            Store mu, stdev values for metric
        
        --------------
        Parameters
        --------------
            - mu: float
                Sets the mean value for the normal distribution for the 
                bandwidth of the node
            - stdev: float
                Sets the standard deviation for the normal distribution for
                banwidth of the node
            - min_uniform: float
                Lower limit on random amount bandwidth is degraded if 
                the node is compromised
            - max_uniform: float
                Upper limit on random amount bandwidth is degraded if 
                the node is compromised
        --------------
        Returns
        --------------
            - bandwidth: float
                Bandwidth of node at time in simulation 
        
        '''
        if self.is_compromised == 0:
            bandwidth = np.random.normal(mu, stdev)
        else:
            bandwidth = np.random.normal(mu, stdev) - np.random.uniform(min_uniform, max_uniform)
        self.bandwidth_array.append(bandwidth)
        return bandwidth
    
    def get_response_time(self, mu=130, stdev=20, min_uniform=100, max_uniform=300):
        ''' Gets the current response timeof the node. Response time isdetermined
        based on whether or not the node is compromised
        
        *****TODO*****
            Store mu, stdev values for metric
        
        --------------
        Parameters
        --------------
            - mu: float
                Sets the mean value for the normal distribution for the 
                response time of the node
            - stdev: float
                Sets the standard deviation for the normal distribution for
                response time of the node
            - min_uniform: float
                Lower limit on random amount response time is degraded if 
                the node is compromised
            - max_uniform: float
                Upper limit on random amount response time is degraded if 
                the node is compromised
        --------------
        Returns
        --------------
            - bandwidth: float
                Bandwidth of node at time in simulation 
        
        '''
        if self.is_compromised == 0:
            response_time = np.random.normal(mu, stdev)
        else:
            response_time = np.random.normal(mu, stdev) + np.random.uniform(min_uniform, max_uniform)
        self.response_time_array.append(response_time)
        return response_time
        
    def link_nodes(self, parent_node_list, child_node_list):
        ''' Establishes nodes relationships to other nodes in network
        
        --------------
        Parameters
        --------------
            - parent_node_list: list, NetworkNode objects
                Parents of the node
            - child_node_list: list, NetworkNode objects
                Children of the node
        
        '''
        for node in parent_node_list:
            self.parent_nodes.append(node)
        for node in child_node_list:
            self.child_nodes.append(node)
            
    def get_node_metrics(self, timestep):
        ''' Calls each of the functions that determine the node's current
        performance metrics:
            - cur_packet_rate
            - cur_bandwidth
            - cur_response_time
        
        --------------
        Parameters
        --------------
            - timestep: int
                Current timestep of the simulation
                
        '''
        self.time_step_array.append(timestep)
        self.cur_packet_rate = self.get_packet_rate()
        self.cur_bandwidth = self.get_bandwidth()
        self.cur_response_time = self.get_response_time()

    def set_node_level(self, level):
        ''' Sets the "level" of the node, which represents where the node
        falls in the overall network geneaology
        
        --------------
        Parameters
        --------------
        - level: int
            Tree level of node in network architecture
        
        '''
        self.level=level
        
    def get_node_level(self):
        ''' Getter function for the node level
        
        --------------
        Returns
        --------------
        level: int
            Level of node
        
        '''
        return self.level
    
    def add_timestep(self, t):
        ''' Adds timestep to array for node
        
        --------------
        Parameters
        --------------
        t: int 
            Timestep of simulation
        
        '''
        self.time_step_array.append(t)
        
    def truth_compromise_check(self):
        ''' Used to store values as to whether or not the
        node is truly compromised. 
        
        '''
        self.compromised_array.append(self.is_compromised)
        
    def basic_compromise_check(self):
        ''' Basic compromise check of whether or not the node is
        compromised. 
        
        This check is based on a rough threshold for what is considered
        to be normal, non-attacked behavior of the network node. At each
        step of the simulation, the node is assumed to be non-malicious
        before performing the check. If this logic check detects unusual 
        behavior, it flags the node as malicious.
        
        
        --------------
        Parameters
        --------------
        t: int 
            Timestep of simulation
        
        '''
        self.flagged_malicious = 0
        if (self.cur_response_time > 130) & (self.cur_bandwidth < 32):
            if self.cur_packet_rate < 0.905:
                self.flagged_malicious = 1

            
        if (self.cur_response_time > 130) & (self.cur_packet_rate < 0.91):
            if self.cur_bandwidth < 27:
                self.flagged_malicious = 1
                
        self.flagged_malicious_array.append(self.flagged_malicious)
        
    def fuzzy_compromise_check(self):
        '''
        Sets up fuzzy logic system. Implements antecedents and consequent,
        establishes universe, calculates fuzzy logic output for 
        whether or note node is compromised. 
        
       *****TODO*****
            - remove hard-coded values for Antecedents, and base values
            off of the mu, stdev for each of the metrics
            - clean this up, potentially move this to another location
        '''

        response_time = ctrl.Antecedent(np.arange(0,600,10), 'response_time')
        packet_rate = ctrl.Antecedent(np.arange(0.83,0.93,0.005), 'packet_rate')
        bandwidth = ctrl.Antecedent(np.arange(5,35,1), 'bandwidth')

        compromised = ctrl.Consequent(np.arange(0,11), 'compromised')

        response_time.automf(3)
        packet_rate.automf(3)
        bandwidth.automf(3)

        compromised['green'] = fuzz.trimf(compromised.universe, [0,0,4])
        compromised['yellow'] = fuzz.trimf(compromised.universe, [2,8,11])
        compromised['red'] = fuzz.trimf(compromised.universe, [7,11,11])

        rule2 = ctrl.Rule(response_time['poor'] | packet_rate['poor'] | bandwidth['poor'], compromised['red'])
        rule3 = ctrl.Rule(packet_rate['average'] & response_time['average'], compromised['yellow'])
        rule4 = ctrl.Rule(packet_rate['average'] & bandwidth['average'], compromised['yellow'])
        rule5 = ctrl.Rule(response_time['good'] & bandwidth['good'], compromised['green'])
        rule6 = ctrl.Rule(response_time['good'] & packet_rate['good'], compromised['green'])

        compromised_ctrl = ctrl.ControlSystem([rule2, rule3, rule4, rule5, rule6])

        compromised_sim = ctrl.ControlSystemSimulation(compromised_ctrl)
        
        p = self.cur_packet_rate
        b = self.cur_bandwidth
        r = 600 - self.cur_response_time

        compromised_sim.input['packet_rate'] = p
        compromised_sim.input['bandwidth'] = b
        compromised_sim.input['response_time'] = r
        
        compromised_sim.compute()

        result = compromised_sim.output['compromised']
        self.fuzzy_compromised_value_array.append(result)
        
        
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
        return node_dict
        
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