import numpy as np

class Attacker:
    
    def __init__(self, name, target_node_ind):
        self.name = name
        self.target_node_ind = target_node_ind
        
    def get_target_node(self):
        return self.target_node_ind
        
    def attempt_attack(self, threshold):
        success = False
        
        val = np.random.rand()
        if val > threshold: 
            success = True
            
        return success
        